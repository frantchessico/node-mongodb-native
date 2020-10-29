import type { Document } from '../bson';
import type { CollationOptions } from '../cmap/wire_protocol/write_command';
import { MongoError } from '../error';
import { executeOperation } from '../operations/execute_operation';
import { FindOperation, FindOptions } from '../operations/find';
import type { Hint } from '../operations/operation';
import type { Topology } from '../sdam/topology';
import type { ClientSession } from '../sessions';
import { formatSort, Sort, SortDirection } from '../sort';
import type { Callback, MongoDBNamespace } from '../utils';
import { AbstractCursor, ExecutionResult } from './abstract_cursor';

const kFilter = Symbol('filter');

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
  }

  _initialize(session: ClientSession | undefined, callback: Callback<ExecutionResult>): void {
    const findOperation = new FindOperation(undefined, this.ns, this[kFilter], {
      session,
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
   * Set a node.js specific cursor option
   *
   * @param field - The cursor option to set 'numberOfRetries' | 'tailableRetryInterval'.
   * @param value - The field value.
   */
  // setCursorOption(field: typeof FIELDS[number], value: number): this {
  //   if (!FIELDS.includes(field)) {
  //     throw new MongoError(`option ${field} is not a supported option ${FIELDS}`);
  //   }

  //   Object.assign(this.s, { [field]: value });
  //   if (field === 'numberOfRetries') this.s.currentNumberOfRetries = value as number;
  //   return this;
  // }

  /**
   * Add a cursor flag to the cursor
   *
   * @param flag - The flag to set, must be one of following ['tailable', 'oplogReplay', 'noCursorTimeout', 'awaitData', 'partial' -.
   * @param value - The flag boolean value.
   */
  // addCursorFlag(flag: CursorFlag, value: boolean): this {
  //   if (!FLAGS.includes(flag)) {
  //     throw new MongoError(`flag ${flag} is not a supported flag ${FLAGS}`);
  //   }

  //   if (typeof value !== 'boolean') {
  //     throw new MongoError(`flag ${flag} must be a boolean value`);
  //   }

  //   if (flag === 'tailable') {
  //     this.tailable = value;
  //   }

  //   if (flag === 'awaitData') {
  //     this.awaitData = value;
  //   }

  //   this.cmd[flag] = value;
  //   return this;
  // }

  /**
   * Add a query modifier to the cursor query
   *
   * @param name - The query modifier (must start with $, such as $orderby etc)
   * @param value - The modifier value.
   */
  // addQueryModifier(name: string, value: string | boolean | number): this {
  //   if (name[0] !== '$') {
  //     throw new MongoError(`${name} is not a valid query modifier`);
  //   }

  //   // Strip of the $
  //   const field = name.substr(1);
  //   // Set on the command
  //   this.cmd[field] = value;
  //   // Deal with the special case for sort
  //   if (field === 'orderby') this.cmd.sort = this.cmd[field];
  //   return this;
  // }

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
