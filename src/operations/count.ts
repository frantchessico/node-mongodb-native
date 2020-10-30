import { Aspect, defineAspects } from './operation';
import { CommandOperation, CommandOperationOptions } from './command';
import type { Callback } from '../utils';
import type { Document } from '../bson';
import type { Server } from '../sdam/server';
import type { Collection } from '../collection';
import type { FindCursor } from '../cursor/find_cursor';

/** @public */
export interface CountOptions extends CommandOperationOptions {
  /** The number of documents to skip. */
  skip?: number;
  /** The maximum amounts to count before aborting. */
  limit?: number;
  /** Number of milliseconds to wait before aborting the query. */
  maxTimeMS?: number;
  /** An index name hint for the query. */
  hint?: string | Document;
}

type BuildCountCommandOptions = CountOptions & { collectionName: string };

/** @internal */
export class CountOperation extends CommandOperation<CountOptions, number> {
  cursor: FindCursor;
  query: Document;

  // count: <collection or view>,
  // query: <document>,
  // limit: <integer>,
  // skip: <integer>,
  // hint: <hint>,
  // comment: <any>
  constructor(cursor: FindCursor, filter: Document, options: CountOptions) {
    super(({ s: { namespace: cursor.ns } } as unknown) as Collection, options);

    this.cursor = cursor;
    this.query = filter;
  }

  execute(server: Server, callback: Callback<number>): void {
    const cursor = this.cursor;
    const options = this.options;
    const cmd: Document = {
      count: cursor.ns.collection ?? '',
      query: this.query
    };

    if (typeof options.limit === 'number') {
      cmd.limit = options.limit;
    }

    if (typeof options.skip === 'number') {
      cmd.skip = options.skip;
    }

    if (typeof options.hint !== 'undefined') {
      cmd.hint = options.hint;
    }

    if (typeof options.maxTimeMS === 'number') {
      cmd.maxTimeMS = options.maxTimeMS;
    }

    // let command;
    // try {
    //   command = buildCountCommand(cursor, cursor.cmd.query, finalOptions);
    // } catch (err) {
    //   return callback(err);
    // }

    super.executeCommand(server, cmd, (err, result) => {
      callback(err, result ? result.n : 0);
    });
  }
}

/**
 * Build the count command.
 *
 * @param collectionOrCursor - an instance of a collection or cursor
 * @param query - The query for the count.
 * @param options - Optional settings. See Collection.prototype.count and Cursor.prototype.count for a list of options.
 */
// function buildCountCommand(cursor: Cursor, query: Document, options: BuildCountCommandOptions) {
//   const skip = options.skip;
//   const limit = options.limit;
//   let hint = options.hint;
//   const maxTimeMS = options.maxTimeMS;
//   query = query || {};

//   // Final query
//   const cmd: Document = {
//     count: options.collectionName,
//     query: query
//   };

//   // collectionOrCursor is a cursor
//   if (cursor.options.hint) {
//     hint = cursor.options.hint;
//   } else if (cursor.cmd.hint) {
//     hint = cursor.cmd.hint;
//   }

//   decorateWithCollation(cmd, cursor, cursor.cmd);

//   // Add limit, skip and maxTimeMS if defined
//   if (typeof skip === 'number') cmd.skip = skip;
//   if (typeof limit === 'number') cmd.limit = limit;
//   if (typeof maxTimeMS === 'number') cmd.maxTimeMS = maxTimeMS;
//   if (hint) cmd.hint = hint;

//   // Do we have a readConcern specified
//   decorateWithReadConcern(cmd, cursor);

//   return cmd;
// }

defineAspects(CountOperation, [Aspect.READ_OPERATION, Aspect.RETRYABLE]);
