import { Callback, maybePromise, MongoDBNamespace } from '../utils';
import { Long, Document, BSONSerializeOptions, pluckBSONSerializeOptions } from '../bson';
import { ClientSession } from '../sessions';
import { AnyError, MongoError } from '../error';
import { ReadPreference, ReadPreferenceLike } from '../read_preference';
import type { Server } from '../sdam/server';
import type { CursorCloseOptions, CursorStreamOptions } from './cursor';
import type { Topology } from '../sdam/topology';
import { Readable } from 'stream';
import { EventEmitter } from 'events';
import { read } from 'fs';

const kId = Symbol('id');
const kDocuments = Symbol('documents');
const kServer = Symbol('server');
const kNamespace = Symbol('namespace');
const kTopology = Symbol('topology');
const kSession = Symbol('session');
const kOptions = Symbol('options');
const kTransform = Symbol('transform');

/** @internal */
export const CURSOR_FLAGS = [
  'tailable',
  'oplogReplay',
  'noCursorTimeout',
  'awaitData',
  'exhaust',
  'partial'
] as const;

/** @public */
export type CursorFlag = typeof CURSOR_FLAGS[number];

export interface AbstractCursorOptions extends BSONSerializeOptions {
  session?: ClientSession;
  readPreference?: ReadPreferenceLike;
  batchSize?: number;
  maxTimeMS?: number;
  comment?: Document | string;
  tailable?: boolean;
  awaitData?: boolean;
}

export abstract class AbstractCursor extends EventEmitter {
  [kId]?: Long;
  [kSession]?: ClientSession;
  [kServer]?: Server;
  [kNamespace]?: MongoDBNamespace;
  [kDocuments]: Document[];
  [kTopology]: Topology;
  [kTransform]?: (doc: Document) => Document;
  [kOptions]: {
    readPreference: ReadPreference;
    batchSize?: number;
    maxTimeMS?: number;
    comment?: Document | string;

    // cursor flags, some are deprecated
    tailable?: boolean;
    awaitData?: boolean;
    oplogReplay?: boolean;
    noCursorTimeout?: boolean;
    exhaust?: boolean;
    partial?: boolean;
  } & BSONSerializeOptions;

  closed: boolean;

  /** @event */
  static readonly CLOSE = 'close' as const;

  constructor(topology: Topology, options: AbstractCursorOptions = {}) {
    super();

    this[kTopology] = topology;
    this[kDocuments] = []; // TODO: https://github.com/microsoft/TypeScript/issues/36230
    this[kOptions] = {
      batchSize: typeof options.batchSize === 'number' ? options.batchSize : undefined, // TODO: there should be no default here
      comment: options.comment,
      maxTimeMS: typeof options.maxTimeMS === 'number' ? options.maxTimeMS : undefined,
      readPreference:
        options.readPreference && options.readPreference instanceof ReadPreference
          ? options.readPreference
          : ReadPreference.primary,
      ...pluckBSONSerializeOptions(options)
    };

    if (options.session instanceof ClientSession) {
      this[kSession] = options.session;
    }

    this.closed = false;
  }

  get id(): Long | undefined {
    return this[kId];
  }

  get topology(): Topology {
    return this[kTopology];
  }

  get namespace(): MongoDBNamespace | undefined {
    return this[kNamespace];
  }

  get readPreference(): ReadPreference {
    return this[kOptions].readPreference;
  }

  // NOTE: should we remove these? They are currently needed by a number of tests
  isClosed(): boolean {
    const cursorId = this[kId];
    if (cursorId == null) {
      return false;
    }

    return cursorId.isZero() || cursorId === Long.ZERO;
  }

  /** Returns current buffered documents length */
  bufferedCount(): number {
    return this[kDocuments].length;
  }

  /** Returns current buffered documents */
  readBufferedDocuments(number: number): Document[] {
    return this[kDocuments].slice(0, number);
    // const unreadDocumentsLength = this.documents.length - this.cursorIndex;
    // const length = number < unreadDocumentsLength ? number : unreadDocumentsLength;
    // let elements = this.documents.slice(this.cursorIndex, this.cursorIndex + length);

    // // Transform the doc with passed in transformation method if provided
    // if (this.transforms && typeof this.transforms.doc === 'function') {
    //   // Transform all the elements
    //   for (let i = 0; i < elements.length; i++) {
    //     elements[i] = this.transforms.doc(elements[i]);
    //   }
    // }

    // // Ensure we do not return any more documents than the limit imposed
    // // Just return the number of elements up to the limit
    // if (this._limit > 0 && this.currentLimit + elements.length > this._limit) {
    //   elements = elements.slice(0, this._limit - this.currentLimit);
    //   this.kill();
    // }

    // // Adjust current limit
    // this.currentLimit = this.currentLimit + elements.length;
    // this.cursorIndex = this.cursorIndex + elements.length;

    // // Return elements
    // return elements;
  }

  [Symbol.asyncIterator](): AsyncIterator<Document | null> {
    return {
      next: async () => {
        const value = await this.next();
        return { value, done: value === null };
      }
    };
  }

  stream(options?: CursorStreamOptions): AbstractCursorStream {
    return new AbstractCursorStream(this, options);
  }

  hasNext(): Promise<boolean>;
  hasNext(callback: Callback<boolean>): void;
  hasNext(callback?: Callback<boolean>): Promise<boolean> | void {
    return maybePromise(callback, done => {
      if (this[kId] === Long.ZERO) {
        return done(undefined, false);
      }

      if (this[kDocuments].length) {
        return done(undefined, true);
      }

      next(this, (err, doc) => {
        if (err) return done(err);

        if (doc) {
          this[kDocuments].unshift(doc);
          done(undefined, true);
          return;
        }

        done(undefined, false);
      });
    });
  }

  /** Get the next available document from the cursor, returns null if no more documents are available. */
  next(): Promise<Document | null>;
  next(callback: Callback<Document | null>): void;
  next(callback?: Callback<Document | null>): Promise<Document | null> | void {
    return maybePromise(callback, done => {
      if (this[kId] === Long.ZERO) {
        return done(new MongoError('Cursor is exhausted'));
      }

      next(this, done);
    });
  }

  /**
   * Iterates over all the documents for this cursor using the iterator, callback pattern.
   *
   * @param iterator - The iteration callback.
   * @param callback - The end callback.
   */
  forEach(iterator: (doc: Document) => boolean | void): Promise<void>;
  forEach(iterator: (doc: Document) => boolean | void, callback: Callback<void>): void;
  forEach(
    iterator: (doc: Document) => boolean | void,
    callback?: Callback<void>
  ): Promise<void> | void {
    if (typeof iterator !== 'function') {
      throw new TypeError('Missing required parameter `iterator`');
    }

    return maybePromise(callback, done => {
      const transform = this[kTransform];
      const fetchDocs = () => {
        next(this, (err, doc) => {
          if (err || doc == null) return done(err);
          if (doc == null) return done();

          // NOTE: no need to transform because `next` will do this automatically
          let result = iterator(doc);
          if (result === false) return done();

          // these do need to be transformed since they are copying the rest of the batch
          const internalDocs = this[kDocuments].splice(0, this[kDocuments].length);
          if (internalDocs) {
            for (let i = 0; i < internalDocs.length; ++i) {
              result = iterator(transform ? transform(internalDocs[i]) : internalDocs[i]);
              if (result === false) return done();
            }
          }

          fetchDocs();
        });
      };

      fetchDocs();
    });
  }

  close(): void;
  close(callback: Callback): void;
  close(options: CursorCloseOptions): Promise<void>;
  close(options: CursorCloseOptions, callback: Callback): void;
  close(options?: CursorCloseOptions | Callback, callback?: Callback): Promise<void> | void {
    if (typeof options === 'function') (callback = options), (options = {});
    options = options || {};

    this.closed = true;

    return maybePromise(callback, done => {
      const cursorId = this[kId];
      const cursorNs = this[kNamespace];
      const server = this[kServer];
      const session = this[kSession];

      if (cursorId == null || server == null || cursorId.isZero() || cursorNs == null) {
        this[kId] = Long.ZERO;
        this.emit(AbstractCursor.CLOSE);
        return done();
      }

      // TODO: bson options
      server.killCursors(cursorNs.toString(), [cursorId], { session }, () => {
        if (session && session.owner === this) {
          return session.endSession(() => {
            this.emit(AbstractCursor.CLOSE);
            done();
          });
        }

        this.emit(AbstractCursor.CLOSE);
        done();
      });
    });
  }

  /**
   * Returns an array of documents. The caller is responsible for making sure that there
   * is enough memory to store the results. Note that the array only contains partial
   * results when this cursor had been previously accessed. In that case,
   * cursor.rewind() can be used to reset the cursor.
   *
   * @param callback - The result callback.
   */
  toArray(): Promise<Document[]>;
  toArray(callback: Callback<Document[]>): void;
  toArray(callback?: Callback<Document[]>): Promise<Document[]> | void {
    return maybePromise(callback, done => {
      const docs: Document[] = [];
      const transform = this[kTransform];
      const fetchDocs = () => {
        // NOTE: if we add a `nextBatch` then we should use it here
        next(this, (err, doc) => {
          if (err) return done(err);
          if (doc == null) return done(undefined, docs);

          // NOTE: no need to transform because `next` will do this automatically
          docs.push(doc);

          // these do need to be transformed since they are copying the rest of the batch
          const internalDocs = transform
            ? this[kDocuments].splice(0, this[kDocuments].length).map(transform)
            : this[kDocuments].splice(0, this[kDocuments].length);

          if (internalDocs) {
            docs.push(...internalDocs);
          }

          fetchDocs();
        });
      };

      fetchDocs();
    });
  }

  // DO THESE PROPERTIES BELONG HERE?

  /**
   * Add a cursor flag to the cursor
   *
   * @param flag - The flag to set, must be one of following ['tailable', 'oplogReplay', 'noCursorTimeout', 'awaitData', 'partial' -.
   * @param value - The flag boolean value.
   */
  addCursorFlag(flag: CursorFlag, value: boolean): this {
    if (!CURSOR_FLAGS.includes(flag)) {
      throw new MongoError(`flag ${flag} is not one of ${CURSOR_FLAGS}`);
    }

    if (typeof value !== 'boolean') {
      throw new MongoError(`flag ${flag} must be a boolean value`);
    }

    this[kOptions][flag] = value;
    return this;
  }

  /**
   * Map all documents using the provided function
   *
   * @param transform - The mapping transformation method.
   */
  map(transform: (doc: Document) => Document): this {
    const oldTransform = this[kTransform];
    if (oldTransform) {
      this[kTransform] = doc => {
        return transform(oldTransform(doc));
      };
    } else {
      this[kTransform] = transform;
    }

    return this;
  }

  /**
   * Set the ReadPreference for the cursor.
   *
   * @param readPreference - The new read preference for the cursor.
   */
  setReadPreference(readPreference: ReadPreferenceLike): this {
    // if (this.s.state === CursorState.CLOSED || this.isDead()) {
    //   throw new MongoError('Cursor is closed');
    // }

    // if (this.s.state !== CursorState.INIT) {
    //   throw new MongoError('cannot change cursor readPreference after cursor has been accessed');
    // }

    if (readPreference instanceof ReadPreference) {
      this[kOptions].readPreference = readPreference;
    } else if (typeof readPreference === 'string') {
      this[kOptions].readPreference = ReadPreference.fromString(readPreference);
    } else {
      throw new TypeError('Invalid read preference: ' + readPreference);
    }

    return this;
  }

  /**
   * Set a maxTimeMS on the cursor query, allowing for hard timeout limits on queries (Only supported on MongoDB 2.6 or higher)
   *
   * @param value - Number of milliseconds to wait before aborting the query.
   */
  maxTimeMS(value: number): this {
    if (typeof value !== 'number') {
      throw new TypeError('maxTimeMS must be a number');
    }

    this[kOptions].maxTimeMS = value;
    return this;
  }

  /**
   * Set the batch size for the cursor.
   *
   * @param value - The number of documents to return per batch. See {@link https://docs.mongodb.com/manual/reference/command/find/|find command documentation}.
   */
  batchSize(value: number): this {
    // if (this.options.tailable) {
    //   throw new MongoError('Tailable cursor does not support batchSize');
    // }

    // if (this.s.state === CursorState.CLOSED || this.isDead()) {
    //   throw new MongoError('Cursor is closed');
    // }

    if (typeof value !== 'number') {
      throw new TypeError('batchSize requires an integer');
    }

    this[kOptions].batchSize = value;
    return this;
  }

  /* @internal */
  abstract _initialize(
    session: ClientSession | undefined,
    options: AbstractCursorOptions,
    callback: Callback<ExecutionResult>
  ): void;
}

/* @internal */
export interface ExecutionResult {
  /** The server selected for the operation */
  server: Server;
  /** The session used for this operation, may be implicitly created */
  session?: ClientSession;
  /** The namespace for the operation, this is only needed for pre-3.2 servers which don't use commands */
  namespace: MongoDBNamespace;
  /** The raw server response for the operation */
  response: Document;
}

const kCursor = Symbol('cursor');

/** @public */
export class AbstractCursorStream extends Readable {
  [kCursor]: AbstractCursor;
  options: CursorStreamOptions;
  reading: boolean;

  /** @event */
  static readonly CLOSE = 'close' as const;
  /** @event */
  static readonly DATA = 'data' as const;
  /** @event */
  static readonly END = 'end' as const;
  /** @event */
  static readonly FINISH = 'finish' as const;
  /** @event */
  static readonly ERROR = 'error' as const;
  /** @event */
  static readonly PAUSE = 'pause' as const;
  /** @event */
  static readonly READABLE = 'readable' as const;
  /** @event */
  static readonly RESUME = 'resume' as const;

  constructor(cursor: AbstractCursor, options?: CursorStreamOptions) {
    super({ objectMode: true });
    this[kCursor] = cursor;
    this.options = options || {};
  }

  destroy(err?: AnyError): void {
    this.pause();
    this[kCursor].close();
    super.destroy(err);
  }

  /** @internal */
  _read(): void {
    const cursor = this[kCursor];
    // if ((cursor.s && cursor.s.state === CursorState.CLOSED) || cursor.isDead()) {
    //   this.push(null);
    //   return;
    // }

    // Get the next item
    next(cursor, (err, result) => {
      if (err) {
        // if (cursor.s && cursor.s.state === CursorState.CLOSED) return;
        // if (!cursor.isDead()) this.emit(CursorStream.ERROR, err);
        // cursor.close(() => this.emit(CursorStream.END));

        this.emit(AbstractCursorStream.ERROR, err);
        this.emit(AbstractCursorStream.END);
        return;
      }

      // If we provided a transformation method
      if (typeof this.options.transform === 'function' && result != null) {
        this.push(this.options.transform(result));
        return;
      }

      // Return the result
      this.push(result);

      if (result === null /* && cursor.isDead() */) {
        this.once(AbstractCursorStream.END, () => {
          cursor.close();
          this.emit(AbstractCursorStream.FINISH);
        });
      }
    });
  }
}

function nextDocument(cursor: AbstractCursor): Document | null | undefined {
  if (cursor[kDocuments] == null || !cursor[kDocuments].length) {
    return undefined;
  }

  const doc = cursor[kDocuments].shift();
  if (doc) {
    const transform = cursor[kTransform];
    if (transform) {
      return transform(doc);
    }

    return doc;
  }

  return null;
}

function next(cursor: AbstractCursor, callback: Callback<Document | null>): void {
  const cursorId = cursor[kId];
  const cursorNs = cursor[kNamespace];
  const server = cursor[kServer];

  if (cursorId == null) {
    const session = cursor[kSession]
      ? cursor[kSession]
      : cursor[kTopology].hasSessionSupport()
      ? cursor[kTopology].startSession({ owner: cursor, explicit: true })
      : undefined;

    cursor._initialize(session, cursor[kOptions], (err, state) => {
      if (state) {
        const response = state.response;
        cursor[kServer] = state.server;
        cursor[kSession] = state.session;

        if (response.cursor) {
          cursor[kId] =
            typeof response.cursor.id === 'number'
              ? Long.fromNumber(response.cursor.id)
              : response.cursor.id;
          cursor[kNamespace] = MongoDBNamespace.fromString(response.cursor.ns);
          cursor[kDocuments] = response.cursor.firstBatch;
        } else {
          // NOTE: This is for support of older servers (<3.2) which do not use commands
          cursor[kId] =
            typeof response.cursorId === 'number'
              ? Long.fromNumber(response.cursorId)
              : response.cursorId;
          cursor[kNamespace] = state.namespace;
          cursor[kDocuments] = response.documents;
        }
      }

      if (err || (cursor.id && cursor.id.isZero())) {
        if (session && session.owner === cursor) {
          session.endSession(() => callback(err, nextDocument(cursor)));
        } else {
          callback(err, nextDocument(cursor));
        }

        return;
      }

      callback(err, nextDocument(cursor));
    });

    return;
  }

  if (cursor[kDocuments].length) {
    callback(undefined, nextDocument(cursor));
    return;
  }

  if (cursorId.isZero() || cursorNs == null) {
    const session = cursor[kSession];
    if (session && session.owner === cursor) {
      session.endSession(() => callback(undefined, null));
    } else {
      callback(undefined, null);
    }

    return;
  }

  // otherwise need to call getMore
  if (server == null) {
    callback(new MongoError('unable to iterate cursor without pinned server'));
    return;
  }

  server.getMore(
    cursorNs.toString(),
    cursorId,
    {
      session: cursor[kSession],
      ...cursor[kOptions],
      batchSize: cursor[kOptions].batchSize || 1000 // TODO: there should be no default here
    },
    (err, response) => {
      if (response) {
        const cursorId =
          typeof response.cursor.id === 'number'
            ? Long.fromNumber(response.cursor.id)
            : response.cursor.id;

        cursor[kDocuments] = response.cursor.nextBatch;
        cursor[kId] = cursorId;
      }

      if (err || (cursor.id && cursor.id.isZero())) {
        const session = cursor[kSession];
        if (session && session.owner === cursor) {
          session.endSession(() => callback(err, nextDocument(cursor)));
        } else {
          callback(err, nextDocument(cursor));
        }

        return;
      }

      callback(err, nextDocument(cursor));
    }
  );
}

// function makeCursorStream(cursor: AbstractCursor) {
//   const readable = new Readable({
//     objectMode: true,
//     highWaterMark: 1
//   });

//   let reading = false;
//   let needToClose = false;

//   readable._read = function () {
//     if (!reading) {
//       reading = true;
//       readNext();
//     }
//   };

//   readable._destroy = function (error, cb) {
//     if (needToClose) {
//       cursor.close(err => process.nextTick(cb, err));
//     } else {
//       cb(error);
//     }
//   };

//   function readNext() {
//     needToClose = false;
//     next(cursor, (err, result) => {
//       if (err) {
//         if (cursor.closed) {
//           return readable.push(null);
//         }

//         return readable.destroy(err);
//       }

//       if (result === null) {
//         // console.log('DONE READING');
//         return readable.push(null);
//       }

//       if (readable.destroyed) {
//         return cursor.close();
//       }

//       if (readable.push(result)) {
//         return readNext();
//       }

//       reading = false;
//     });
//   }

//   return readable;
// }
