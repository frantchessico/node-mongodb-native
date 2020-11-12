import { MongoCredentials } from './cmap/auth/mongo_credentials';
import type { MongoClientOptions, PkFactory } from './mongo_client';
import { ReadConcern, ReadConcernLevel } from './read_concern';
import { ReadPreference, ReadPreferenceMode } from './read_preference';
import { W, WriteConcern } from './write_concern';

import type { ConnectionOptions as TLSConnectionOptions } from 'tls';
import type { TcpSocketConnectOpts as ConnectionOptions } from 'net';
import type { BSONSerializeOptions, Document } from './bson';
import { MongoParseError } from './error';
import { URL } from 'url';
import { AuthMechanismEnum } from './cmap/auth/defaultAuthProviders';
import type { TagSet } from './sdam/server_description';
import { Logger, LoggerLevel } from './logger';

/**
 * Mongo Client Options
 * @internal
 */
export interface MongoOptions
  extends Required<BSONSerializeOptions>,
    Omit<ConnectionOptions, 'port'>,
    Omit<TLSConnectionOptions, 'port'>,
    Required<
      Pick<
        MongoClientOptions,
        | 'autoEncryption'
        | 'compression'
        | 'compressors'
        | 'connectTimeoutMS'
        | 'dbName'
        | 'directConnection'
        | 'domainsEnabled'
        | 'driverInfo'
        | 'forceServerObjectId'
        | 'gssapiServiceName'
        | 'ha'
        | 'haInterval'
        | 'heartbeatFrequencyMS'
        | 'keepAlive'
        | 'keepAliveInitialDelay'
        | 'localThresholdMS'
        | 'logger'
        | 'maxIdleTimeMS'
        | 'maxPoolSize'
        | 'minPoolSize'
        | 'monitorCommands'
        | 'noDelay'
        | 'numberOfRetries'
        | 'pkFactory'
        | 'promiseLibrary'
        | 'raw'
        | 'reconnectInterval'
        | 'reconnectTries'
        | 'replicaSet'
        | 'retryReads'
        | 'retryWrites'
        | 'serverSelectionTimeoutMS'
        | 'serverSelectionTryOnce'
        | 'socketTimeoutMS'
        | 'tlsAllowInvalidCertificates'
        | 'tlsAllowInvalidHostnames'
        | 'tlsInsecure'
        | 'waitQueueMultiple'
        | 'waitQueueTimeoutMS'
        | 'zlibCompressionLevel'
      >
    > {
  hosts: { host: string; port: number }[];
  srv: boolean;
  credentials: MongoCredentials;
  readPreference: ReadPreference;
  readConcern: ReadConcern;
  writeConcern: WriteConcern;

  /**
   * # NOTE ABOUT TLS Options
   *
   * If set TLS enabled, equivalent to setting the ssl option.
   *
   * ### Additional options:
   *
   * |    nodejs option     | MongoDB equivalent                                       | type                                   |
   * |:---------------------|--------------------------------------------------------- |:---------------------------------------|
   * | `ca`                 | `sslCA`, `tlsCAFile`                                     | `string \| Buffer \| Buffer[]`         |
   * | `crl`                | `sslCRL`                                                 | `string \| Buffer \| Buffer[]`         |
   * | `cert`               | `sslCert`, `tlsCertificateFile`, `tlsCertificateKeyFile` | `string \| Buffer \| Buffer[]`         |
   * | `key`                | `sslKey`, `tlsCertificateKeyFile`                        | `string \| Buffer \| KeyObject[]`      |
   * | `passphrase`         | `sslPass`, `tlsCertificateKeyFilePassword`               | `string`                               |
   * | `rejectUnauthorized` | `sslValidate`                                            | `boolean`                              |
   *
   */
  tls: boolean;

  /**
   * Turn these options into a reusable options dictionary
   */
  toJSON(): Record<string, any>;
  /**
   * Turn these options into a reusable connection URI
   */
  toURI(): string;
}

const HOSTS_RX = new RegExp(
  '(?<protocol>mongodb(?:\\+srv|)):\\/\\/(?:(?<username>[^:]*)(?::(?<password>[^@]*))?@)?(?<hosts>[^\\/?]*)(?<rest>.*)'
);

function parseURI(uri: string): { srv: boolean; url: URL; hosts: string[] } {
  const match = uri.match(HOSTS_RX);
  if (!match) {
    throw new MongoParseError(`Invalid connection string ${uri}`);
  }

  const protocol = match.groups?.protocol;
  const username = match.groups?.username;
  const password = match.groups?.password;
  const hosts = match.groups?.hosts;
  const rest = match.groups?.rest;

  if (!protocol || !hosts) {
    throw new MongoParseError('Invalid connection string, protocol and host(s) required');
  }

  const authString = username ? (password ? `${username}:${password}` : `${username}`) : '';
  return {
    srv: protocol.includes('srv'),
    url: new URL(`${protocol.toLowerCase()}://${authString}@dummyHostname${rest}`),
    hosts: hosts.split(',')
  };
}

function getBoolean(name: string, value: unknown): boolean {
  if (typeof value === 'boolean') return value;
  const valueString = String(value).toLowerCase();
  const truths = ['true', 't', '1', 'y', 'yes'];
  const lies = ['false', 'f', '0', 'n', 'no', '-1'];
  if (truths.includes(valueString)) return true;
  if (lies.includes(valueString)) return false;
  throw new TypeError(`For ${name} Expected stringified boolean value, got: ${value}`);
}

function getInt(name: string, value: unknown): number {
  if (typeof value === 'number') return Math.trunc(value);
  const parsedValue = Number.parseInt(String(value), 10);
  if (!Number.isNaN(parsedValue)) return parsedValue;
  throw new TypeError(`Expected ${name} to be stringified int value, got: ${value}`);
}

function getUint(name: string, value: unknown): number {
  const parsedValue = getInt(name, value);
  if (parsedValue < 0) {
    throw new TypeError(`${name} can only be a positive int value, got: ${value}`);
  }
  return parsedValue;
}

function isRecord(value: unknown): value is Record<string, any> {
  return !!value && typeof value === 'object';
}

function toRecord(value: string): Record<string, any> {
  const record = Object.create(null);
  const keyValuePairs = value.split(',');
  for (const keyValue of keyValuePairs) {
    const [key, value] = keyValue.split(':');
    record[key] = value;
  }
  return record;
}

const defaultOptions = new Map<string, unknown>([
  ['dbName', 'test'],
  ['socketTimeoutMS', 0],
  ['readPreference', ReadPreference.primary]
  // TODO: add more
]);

export function parseOptions(
  uri: string,
  options: MongoClientOptions = {}
): Readonly<MongoOptions> {
  const { url, hosts, srv } = parseURI(uri);

  const mongoOptions = Object.create(null);
  mongoOptions.hosts = hosts;
  mongoOptions.srv = srv;

  const urlOptions = new Map();
  for (const key of url.searchParams.keys()) {
    const loweredKey = key.toLowerCase();
    if (urlOptions.has(loweredKey)) {
      urlOptions.set(loweredKey, [...urlOptions.get(loweredKey), ...url.searchParams.getAll(key)]);
    } else {
      urlOptions.set(loweredKey, url.searchParams.getAll(key));
    }
  }

  const objectOptions = new Map(
    Object.entries(options).map(([k, v]) => [k.toLowerCase(), v] as [string, any])
  );

  const allOptions = new Map();

  const allKeys = new Set([
    ...urlOptions.keys(),
    ...objectOptions.keys(),
    ...defaultOptions.keys()
  ]);

  for (const key of allKeys) {
    const values = [];
    if (urlOptions.has(key)) {
      values.push(...urlOptions.get(key));
    }
    if (objectOptions.has(key)) {
      values.push(objectOptions.get(key));
    }
    if (defaultOptions.has(key)) {
      values.push(defaultOptions.get(key));
    }
    allOptions.set(key, values);
  }

  for (const [loweredKey, values] of allOptions.entries()) {
    const descriptor = descriptorFor(loweredKey);
    const {
      descriptor: { rename, type, transform, deprecated },
      key
    } = descriptor;
    const name = rename ?? key;

    if (deprecated) {
      console.warn(`${key} is a deprecated option`);
    }

    switch (type) {
      case 'boolean':
        mongoOptions[name] = getBoolean(name, values[0]);
        break;
      case 'int':
        mongoOptions[name] = getInt(name, values[0]);
        break;
      case 'uint':
        mongoOptions[name] = getUint(name, values[0]);
        break;
      case 'string':
        mongoOptions[name] = String(values[0]);
        break;
      case 'record':
        if (!isRecord(values[0])) {
          throw new TypeError(`${name} must be an object`);
        }
        mongoOptions[name] = values[0];
        break;
      case 'asIs':
        mongoOptions[name] = values[0];
        break;
      default: {
        if (!transform) {
          throw new MongoParseError('Descriptors missing a type must define a transform');
        }
        const transformValue = transform({ name, options: mongoOptions, values });
        mongoOptions[name] = transformValue;
        break;
      }
    }
  }

  return Object.freeze(mongoOptions) as Readonly<MongoOptions>;
}

interface OptionDescriptor {
  rename?: string;
  type?: 'boolean' | 'int' | 'uint' | 'record' | 'string' | 'asIs';

  deprecated?: boolean;
  /**
   * @param name - the original option name
   * @param options - the options so far for resolution
   * @param values - the possible values in precedence order
   */
  transform?: (args: { name: string; options: MongoOptions; values: unknown[] }) => unknown;
}

export const OPTIONS: Record<keyof MongoClientOptions, OptionDescriptor> = {
  appName: {
    rename: 'driverInfo',
    transform({ options, values: [value] }) {
      return { ...options.driverInfo, name: String(value) };
    }
  },
  auth: {
    rename: 'credentials',
    transform({ name, options, values: [value] }): MongoCredentials {
      if (!isRecord(value)) {
        throw new TypeError(`${name} must be an object with 'user' and 'pass' properties`);
      }
      return new MongoCredentials({
        ...options.credentials,
        username: value.user,
        password: value.pass
      });
    }
  },
  authMechanism: {
    rename: 'credentials',
    transform({ options, values: [value] }): MongoCredentials {
      const mechanisms = Object.values(AuthMechanismEnum);
      const [mechanism] = mechanisms.filter(m => m.match(RegExp(String.raw`\b${value}\b`, 'i')));
      if (!mechanism) {
        throw new TypeError(`authMechanism one of ${mechanisms}, got ${value}`);
      }
      return new MongoCredentials({ ...options.credentials, mechanism });
    }
  },
  authMechanismProperties: {
    rename: 'credentials',
    transform({ options, values: [value] }): MongoCredentials {
      if (typeof value === 'string') {
        value = toRecord(value);
      }
      if (!isRecord(value)) {
        throw new TypeError('AuthMechanismProperties must be an object');
      }
      return new MongoCredentials({ ...options.credentials, mechanismProperties: value });
    }
  },
  authSource: {
    rename: 'credentials',
    transform({ options, values: [value] }): MongoCredentials {
      return new MongoCredentials({ ...options.credentials, source: String(value) });
    }
  },
  autoEncryption: {
    type: 'record'
  },
  checkKeys: {
    type: 'boolean'
  },
  checkServerIdentity: {
    rename: 'checkServerIdentity',
    transform({
      values: [value]
    }): boolean | ((hostname: string, cert: Document) => Error | undefined) {
      if (typeof value !== 'boolean' && typeof value !== 'function')
        throw new TypeError('check server identity must be a boolean or custom function');
      return value as boolean | ((hostname: string, cert: Document) => Error | undefined);
    }
  },
  compression: {
    rename: 'compressors',
    transform({ values }) {
      const compressionList = new Set();
      for (const c of values) {
        if (['none', 'snappy', 'zlib'].includes(String(c))) {
          compressionList.add(String(c));
        } else {
          throw new TypeError(`${c} is not a valid compression mechanism`);
        }
      }
      return [...compressionList];
    }
  },
  compressors: {
    rename: 'compressors',
    transform({ values }) {
      const compressionList = new Set();
      for (const compVal of values as string[]) {
        for (const c of compVal.split(',')) {
          if (['none', 'snappy', 'zlib'].includes(String(c))) {
            compressionList.add(String(c));
          } else {
            throw new TypeError(`${c} is not a valid compression mechanism`);
          }
        }
      }
      return [...compressionList];
    }
  },
  connectTimeoutMS: {
    type: 'uint'
  },
  createPk: {
    rename: 'pkFactory',
    transform({ values: [value] }): PkFactory {
      if (typeof value === 'function') {
        return { createPk: value } as PkFactory;
      }
      throw new TypeError(
        `Option pkFactory must be an object with a createPk function, got ${value}`
      );
    }
  } as OptionDescriptor,
  dbName: {
    type: 'string'
  },
  directConnection: {
    type: 'boolean'
  },
  domainsEnabled: {
    type: 'boolean'
  },
  driverInfo: {
    type: 'record'
  },
  family: {
    rename: 'family',
    transform({ name, values: [value] }): 4 | 6 {
      const transformValue = getInt(name, value);
      if (transformValue === 4 || transformValue === 6) {
        return transformValue;
      }
      throw new TypeError(`Option 'family' must be 4 or 6 got ${transformValue}.`);
    }
  },
  fieldsAsRaw: {
    type: 'record'
  },
  forceServerObjectId: {
    type: 'boolean'
  },
  fsync: {
    rename: 'writeConcern',
    transform({ name, options, values: [value] }): WriteConcern {
      const wc = WriteConcern.fromOptions({
        ...options.writeConcern,
        fsync: getBoolean(name, value)
      });
      if (!wc) throw new TypeError(`Unable to make a writeConcern from fsync=${value}`);
      return wc;
    }
  },
  gssapiServiceName: {
    type: 'string'
  },
  ha: {
    type: 'boolean'
  },
  haInterval: {
    type: 'uint'
  },
  heartbeatFrequencyMS: {
    type: 'uint'
  },
  ignoreUndefined: {
    type: 'boolean'
  },
  j: {
    rename: 'writeConcern',
    transform({ name, options, values: [value] }): WriteConcern {
      console.warn('j is deprecated');
      const wc = WriteConcern.fromOptions({
        ...options.writeConcern,
        journal: getBoolean(name, value)
      });
      if (!wc) throw new TypeError(`Unable to make a writeConcern from journal=${value}`);
      return wc;
    }
  },
  journal: {
    rename: 'writeConcern',
    transform({ name, options, values: [value] }): WriteConcern {
      const wc = WriteConcern.fromOptions({
        ...options.writeConcern,
        journal: getBoolean(name, value)
      });
      if (!wc) throw new TypeError(`Unable to make a writeConcern from journal=${value}`);
      return wc;
    }
  },
  keepAlive: {
    type: 'boolean'
  },
  keepAliveInitialDelay: {
    type: 'uint'
  },
  localThresholdMS: {
    type: 'uint'
  },
  logger: {
    transform({ values: [value] }) {
      if (value instanceof Logger) {
        return value;
      }
      console.warn('Alternative loggers might not be supported');
      // TODO: make Logger an interface that others can implement, make usage consistent in driver
      // DRIVERS-1204
    }
  },
  loggerLevel: {
    rename: 'logger',
    transform({ values: [value] }) {
      return new Logger('MongoClient', { loggerLevel: value as LoggerLevel });
    }
  },
  maxIdleTimeMS: {
    type: 'uint'
  },
  maxPoolSize: {
    type: 'uint'
  },
  maxStalenessSeconds: {
    type: 'uint'
  },
  minInternalBufferSize: {
    type: 'uint'
  },
  minPoolSize: {
    type: 'uint'
  },
  minSize: {
    type: 'uint',
    rename: 'minPoolSize'
  },
  monitorCommands: {
    type: 'boolean'
  },
  name: {
    // DriverInfo
    transform({ values: [value], options }) {
      return { ...options.driverInfo, name: String(value) };
    }
  } as OptionDescriptor,
  noDelay: {
    type: 'boolean'
  },
  numberOfRetries: {
    type: 'int'
  },
  pass: {
    rename: 'credentials',
    transform({ values: [password], options }) {
      if (typeof password !== 'string') {
        throw new TypeError('pass must be a string');
      }
      return new MongoCredentials({ ...options.credentials, password });
    }
  } as OptionDescriptor,
  pkFactory: {
    rename: 'createPk',
    transform({ values: [value] }): PkFactory {
      if (isRecord(value) && 'createPk' in value && typeof value.createPk === 'function') {
        return value as PkFactory;
      }
      throw new TypeError(
        `Option pkFactory must be an object with a createPk function, got ${value}`
      );
    }
  },
  platform: {
    rename: 'driverInfo',
    transform({ values: [value], options }) {
      return { ...options.driverInfo, platform: String(value) };
    }
  } as OptionDescriptor,
  poolSize: {
    rename: 'maxPoolSize',
    type: 'uint'
  },
  promiseLibrary: {
    type: 'asIs'
  },
  promoteBuffers: {
    type: 'boolean'
  },
  promoteLongs: {
    type: 'boolean'
  },
  promoteValues: {
    type: 'boolean'
  },
  raw: {
    type: 'boolean'
  },
  readConcern: {
    transform({ values: [value], options }) {
      if (value instanceof ReadConcern || isRecord(value)) {
        return ReadConcern.fromOptions({ ...options.readConcern, ...value } as any);
      }
      throw new MongoParseError(`ReadConcern must be an object, got ${JSON.stringify(value)}`);
    }
  },
  readConcernLevel: {
    rename: 'readConcern',
    transform({ values: [level], options }) {
      return ReadConcern.fromOptions({
        ...options.readConcern,
        level: level as ReadConcernLevel
      });
    }
  },
  readPreference: {
    transform({ values: [value], options }) {
      if (value instanceof ReadPreference) {
        return ReadPreference.fromOptions({ ...options.readPreference, ...value });
      }
      if (isRecord(value)) {
        const rp = ReadPreference.fromOptions({ ...options.readPreference, ...value });
        if (rp) return rp;
        else throw new MongoParseError(`Cannot make read preference from ${JSON.stringify(value)}`);
      }
      if (typeof value === 'string') {
        const rpOpts = {
          hedge: options.readPreference?.hedge,
          maxStalenessSeconds: options.readPreference?.maxStalenessSeconds
        };
        return new ReadPreference(
          value as ReadPreferenceMode,
          options.readPreference?.tags,
          rpOpts
        );
      }
    }
  },
  readPreferenceTags: {
    transform({ values }) {
      // TODO!!!!!!!
      const finalTags: TagSet = Object.create(null);
      for (const tag of values) {
        if (typeof tag === 'string') {
          for (const [k, v] of Object.entries(toRecord(tag))) {
            finalTags[k] = v;
          }
        }
        if (isRecord(tag)) {
          for (const [k, v] of Object.entries(tag)) {
            finalTags[k] = v;
          }
        }
      }
    }
  },
  reconnectInterval: {
    type: 'uint'
  },
  reconnectTries: {
    type: 'uint'
  },
  replicaSet: {
    type: 'string'
  },
  retryReads: {
    type: 'boolean'
  },
  retryWrites: {
    type: 'boolean'
  },
  serializeFunctions: {
    type: 'boolean'
  },
  serverSelectionTimeoutMS: {
    type: 'uint'
  },
  serverSelectionTryOnce: {
    type: 'boolean'
  },
  servername: {
    type: 'string'
  },
  socketTimeoutMS: {
    type: 'uint'
  },
  ssl: {
    rename: 'tls',
    deprecated: true,
    type: 'boolean'
  },
  sslCA: {
    deprecated: true,
    rename: 'ca',
    type: 'asIs'
  },
  sslCRL: {
    rename: 'crl',
    type: 'asIs'
  },
  sslCert: {
    deprecated: true,
    rename: 'cert',
    type: 'asIs'
  },
  sslKey: {
    deprecated: true,
    rename: 'key',
    type: 'asIs'
  },
  sslPass: {
    deprecated: true,
    rename: 'passphrase',
    type: 'string'
  },
  sslValidate: {
    rename: 'rejectUnauthorized',
    type: 'boolean'
  },
  tls: {
    type: 'boolean'
  },
  tlsAllowInvalidCertificates: {
    type: 'boolean'
  },
  tlsAllowInvalidHostnames: {
    type: 'boolean'
  },
  tlsCAFile: {
    rename: 'ca',
    type: 'asIs'
  },
  tlsCertificateFile: {
    rename: 'cert',
    type: 'asIs'
  },
  tlsCertificateKeyFile: {
    rename: 'key',
    type: 'asIs'
  },
  tlsCertificateKeyFilePassword: {
    rename: 'passphrase',
    type: 'asIs'
  },
  tlsInsecure: {
    type: 'boolean'
  },
  user: {
    transform({ values: [value], options }) {
      return new MongoCredentials({ ...options.credentials, username: String(value) });
    }
  } as OptionDescriptor,
  validateOptions: {
    type: 'boolean'
  },
  version: {
    transform({ values: [value], options }) {
      return { ...options.driverInfo, version: String(value) };
    }
  } as OptionDescriptor,
  w: {
    rename: 'writeConcern',
    transform({ values: [value], options }) {
      return WriteConcern.fromOptions({ ...options.writeConcern, w: value as W });
    }
  },
  waitQueueMultiple: {
    type: 'uint'
  },
  waitQueueTimeoutMS: {
    type: 'uint'
  },
  writeConcern: {
    rename: 'writeConcern',
    transform({ values: [value], options }) {
      if (isRecord(value)) {
        return WriteConcern.fromOptions({
          ...options.writeConcern,
          ...value
        });
      }
      throw new MongoParseError(`WriteConcern must be an object, got ${JSON.stringify(value)}`);
    }
  },
  wtimeout: {
    rename: 'writeConcern',
    transform({ values: [value], options }) {
      const wc = WriteConcern.fromOptions({
        ...options.writeConcern,
        wtimeout: getUint('wtimeout', value)
      });
      if (wc) return wc;
      throw new MongoParseError(`Cannot make WriteConcern from wtimeout`);
    }
  },
  wtimeoutMS: {
    rename: 'writeConcern',
    transform({ values: [value], options }) {
      const wc = WriteConcern.fromOptions({
        ...options.writeConcern,
        wtimeoutMS: getUint('wtimeoutMS', value)
      });
      if (wc) return wc;
      throw new MongoParseError(`Cannot make WriteConcern from wtimeout`);
    }
  },
  zlibCompressionLevel: {
    type: 'int'
  }
} as Record<keyof MongoClientOptions, OptionDescriptor>;

const keys = Object.keys(OPTIONS);
function descriptorFor(name: string) {
  const key = keys.filter(
    k => !!k.match(new RegExp(String.raw`\b${name}\b`, 'i'))
  )[0] as keyof MongoClientOptions;
  if (!(key in OPTIONS)) throw new MongoParseError(`Unsupported option ${name}`);
  return { descriptor: OPTIONS[key], key };
}
