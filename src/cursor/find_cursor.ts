import type { Document } from '../bson';
import { executeOperation } from '../operations/execute_operation';
import { FindOperation, FindOptions } from '../operations/find';
import type { Topology } from '../sdam/topology';
import type { ClientSession } from '../sessions';
import type { Callback, MongoDBNamespace } from '../utils';
import { AbstractCursor, ExecutionResult } from './abstract_cursor';

export class FindCursor extends AbstractCursor {
  ns: MongoDBNamespace;
  filter: Document;
  options: FindOptions;

  constructor(
    topology: Topology,
    ns: MongoDBNamespace,
    filter: Document | undefined,
    options: FindOptions = {}
  ) {
    super(topology, options);

    this.ns = ns; // TEMPORARY
    this.filter = filter || {};
    this.options = options;
  }

  _initialize(session: ClientSession | undefined, callback: Callback<ExecutionResult>): void {
    const findOperation = new FindOperation(undefined, this.ns, this.filter, {
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
}
