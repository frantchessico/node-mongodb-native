import type { Document } from '../bson';
import type { CollationOptions } from '../cmap/wire_protocol/write_command';
import { MongoError } from '../error';
import { CountOperation, CountOptions } from '../operations/count';
import { executeOperation } from '../operations/execute_operation';
import { FindOperation, FindOptions } from '../operations/find';
import type { Hint } from '../operations/operation';
import type { Topology } from '../sdam/topology';
import type { ClientSession } from '../sessions';
import { formatSort, Sort, SortDirection } from '../sort';
import type { Callback, MongoDBNamespace } from '../utils';
import { AbstractCursor, AbstractCursorOptions, ExecutionResult } from './abstract_cursor';

/** @internal */
const kFilter = Symbol('filter');

/** @public Flags allowed for cursor */
export const FLAGS = [
  'tailable',
  'oplogReplay',
  'noCursorTimeout',
  'awaitData',
  'exhaust',
  'partial'
] as const;

export class FindCursor extends AbstractCursor {
  ns: MongoDBNamespace;
  [kFilter]: Document;
  options: FindOptions;

  constructor(
    topology: Topology,
    ns: MongoDBNamespace,
    filter: Document | undefined,
    options: FindOptions = {}
  ) {
    super(topology, options);

    this.ns = ns; // TEMPORARY
    this[kFilter] = filter || {};
    this.options = options;

    if (typeof options.sort !== 'undefined') {
      this.options.sort = formatSort(options.sort);
    }
  }

  /** @internal */
  _initialize(
    session: ClientSession | undefined,
    options: AbstractCursorOptions,
    callback: Callback<ExecutionResult>
  ): void {
    this.options = Object.freeze(this.options);

    const findOperation = new FindOperation(undefined, this.ns, this[kFilter], {
      session,
      ...options,
      ...this.options
    });

    executeOperation(this.topology, findOperation, (err, response) => {
      if (err || response == null) return callback(err);

      // NOTE: `executeOperation` should be improved to allow returning an intermediate
      //       representation including the selected server, session, and server response.
      callback(undefined, {
        namespace: findOperation.ns,
        server: findOperation.server,
        session,
        response
      });
    });
  }

  /**
   * Get the count of documents for this cursor
   *
   * @param applySkipLimit - Should the count command apply limit and skip settings on the cursor or in the passed in options.
   */

  count(): Promise<number>;
  count(callback: Callback<number>): void;
  count(options: CountOptions): Promise<number>;
  count(options: CountOptions, callback: Callback<number>): void;
  count(
    options?: CountOptions | Callback<number>,
    callback?: Callback<number>
  ): Promise<number> | void {
    if (typeof options === 'boolean') {
      throw new TypeError('Invalid first parameter to count');
    }

    if (typeof options === 'function') (callback = options), (options = {});
    options = options || {};

    // if (this.session) {
    //   options = Object.assign({}, options, { session: this.session });
    // }

    return executeOperation(
      this.topology,
      new CountOperation(this, this[kFilter], Object.assign({}, options, this.options)),
      callback
    );
  }

  /**
   * Execute the explain for the cursor
   *
   * @param callback - The result callback.
   */
  explain(): Promise<unknown>;
  explain(callback: Callback): void;
  explain(callback?: Callback): Promise<unknown> | void {
    // TODO: session?
    return executeOperation(
      this.topology,
      new FindOperation(undefined, this.ns, this[kFilter], {
        explain: true,
        // session,
        ...this.options
      }),
      callback
    );
  }

  /** Set the cursor query */
  filter(filter: Document): this {
    this[kFilter] = filter;
    return this;
  }

  /**
   * Set the cursor hint
   *
   * @param hint - If specified, then the query system will only consider plans using the hinted index.
   */
  hint(hint: Hint): this {
    this.options.hint = hint;
    return this;
  }

  /**
   * Set the cursor min
   *
   * @param min - Specify a $min value to specify the inclusive lower bound for a specific index in order to constrain the results of find(). The $min specifies the lower bound for all keys of a specific index in order.
   */
  min(min: number): this {
    this.options.min = min;
    return this;
  }

  /**
   * Set the cursor max
   *
   * @param max - Specify a $max value to specify the exclusive upper bound for a specific index in order to constrain the results of find(). The $max specifies the upper bound for all keys of a specific index in order.
   */
  max(max: number): this {
    this.options.max = max;
    return this;
  }

  /**
   * Set the cursor returnKey.
   * If set to true, modifies the cursor to only return the index field or fields for the results of the query, rather than documents.
   * If set to true and the query does not use an index to perform the read operation, the returned documents will not contain any fields.
   *
   * @param value - the returnKey value.
   */
  returnKey(value: boolean): this {
    this.options.returnKey = value;
    return this;
  }

  /**
   * Modifies the output of a query by adding a field $recordId to matching documents. $recordId is the internal key which uniquely identifies a document in a collection.
   *
   * @param value - The $showDiskLoc option has now been deprecated and replaced with the showRecordId field. $showDiskLoc will still be accepted for OP_QUERY stye find.
   */
  showRecordId(value: boolean): this {
    this.options.showRecordId = value;
    return this;
  }

  /**
   * Add a query modifier to the cursor query
   *
   * @param name - The query modifier (must start with $, such as $orderby etc)
   * @param value - The modifier value.
   */
  addQueryModifier(name: string, value: string | boolean | number | Document): this {
    if (name[0] !== '$') {
      throw new MongoError(`${name} is not a valid query modifier`);
    }

    // Strip of the $
    const field = name.substr(1);

    // NOTE: consider some TS magic for this
    switch (field) {
      case 'comment':
        this.options.comment = value as string | Document;
        break;

      case 'explain':
        this.options.explain = value as boolean;
        break;

      case 'hint':
        this.options.hint = value as string | Document;
        break;

      case 'max':
        this.options.max = value as number;
        break;

      case 'maxTimeMS':
        this.options.maxTimeMS = value as number;
        break;

      case 'min':
        this.options.min = value as number;
        break;

      case 'orderby':
        this.options.sort = formatSort(value as string | Document);
        break;

      case 'query':
        this[kFilter] = value as Document;
        break;

      case 'returnKey':
        this.options.returnKey = value as boolean;
        break;

      case 'showDiskLoc':
        this.options.showRecordId = value as boolean;
        break;

      default:
        throw new TypeError(`invalid query modifier: ${name}`);
    }

    return this;
  }

  /**
   * Add a comment to the cursor query allowing for tracking the comment in the log.
   *
   * @param value - The comment attached to this query.
   */
  comment(value: string): this {
    this.options.comment = value;
    return this;
  }

  /**
   * Set a maxAwaitTimeMS on a tailing cursor query to allow to customize the timeout value for the option awaitData (Only supported on MongoDB 3.2 or higher, ignored otherwise)
   *
   * @param value - Number of milliseconds to wait before aborting the tailed query.
   */
  maxAwaitTimeMS(value: number): this {
    if (typeof value !== 'number') {
      throw new MongoError('maxAwaitTimeMS must be a number');
    }

    this.options.maxAwaitTimeMS = value;
    return this;
  }

  /**
   * Set a maxTimeMS on the cursor query, allowing for hard timeout limits on queries (Only supported on MongoDB 2.6 or higher)
   *
   * @param value - Number of milliseconds to wait before aborting the query.
   */
  maxTimeMS(value: number): this {
    if (typeof value !== 'number') {
      throw new MongoError('maxTimeMS must be a number');
    }

    this.options.maxTimeMS = value;
    return this;
  }

  /**
   * Sets a field projection for the query.
   *
   * @param value - The field projection object.
   */
  project(value: Document): this {
    this.options.projection = value;
    return this;
  }

  /**
   * Sets the sort order of the cursor query.
   *
   * @param sort - The key or keys set for the sort.
   * @param direction - The direction of the sorting (1 or -1).
   */
  sort(sort: Sort | string, direction?: SortDirection): this {
    if (this.options.tailable) {
      throw new MongoError('Tailable cursor does not support sorting');
    }

    this.options.sort = formatSort(sort, direction);
    return this;
  }

  /**
   * Set the collation options for the cursor.
   *
   * @param value - The cursor collation options (MongoDB 3.4 or higher) settings for update operation (see 3.4 documentation for available fields).
   */
  collation(value: CollationOptions): this {
    this.options.collation = value;
    return this;
  }

  /**
   * Set the limit for the cursor.
   *
   * @param value - The limit for the cursor query.
   */
  limit(value: number): this {
    if (this.options.tailable) {
      throw new MongoError('Tailable cursor does not support limit');
    }

    if (typeof value !== 'number') {
      throw new MongoError('limit requires an integer');
    }

    this.options.limit = value;
    return this;
  }

  /**
   * Set the skip for the cursor.
   *
   * @param value - The skip for the cursor query.
   */
  skip(value: number): this {
    if (this.options.tailable) {
      throw new MongoError('Tailable cursor does not support skip');
    }

    if (typeof value !== 'number') {
      throw new MongoError('skip requires an integer');
    }

    this.options.skip = value;
    return this;
  }
}
