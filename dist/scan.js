// apps/github-scan-action/src/scanJob.ts
var import_node_fs5 = require("node:fs");
var import_node_os = require("node:os");
var import_node_path3 = require("node:path");

// packages/github/src/scan/seal.ts
var import_node_crypto = require("node:crypto");
var SEAL_VERSION = 1;
var INFO = "jutsu-code-scan-report-v1";
var KID_BYTES = 8;
var PUBLIC_BYTES = 32;
var NONCE_BYTES = 12;
var TAG_BYTES = 16;
var SEAL_OVERHEAD_BYTES = 1 + KID_BYTES + PUBLIC_BYTES + NONCE_BYTES + TAG_BYTES;
var SPKI_PREFIX = Buffer.from("302a300506032b656e032100", "hex");
var PUBLIC_KEY_B64 = /^[A-Za-z0-9+/]{43}=$/;
function isAllZero(bytes) {
  return bytes.every((b) => b === 0);
}
function kidOf(rawPublic) {
  return import_node_crypto.createHash("sha256").update(rawPublic).digest().subarray(0, KID_BYTES).toString("hex");
}
function rawPublicOf(key) {
  return Buffer.from(key.export({ format: "der", type: "spki" })).subarray(-PUBLIC_BYTES);
}
function parseReportPublicKey(b64) {
  if (typeof b64 !== "string" || !PUBLIC_KEY_B64.test(b64))
    return null;
  const raw = Buffer.from(b64, "base64");
  if (raw.length !== PUBLIC_BYTES || raw.toString("base64") !== b64)
    return null;
  try {
    const key = import_node_crypto.createPublicKey({ key: Buffer.concat([SPKI_PREFIX, raw]), format: "der", type: "spki" });
    const probe = import_node_crypto.diffieHellman({ privateKey: import_node_crypto.generateKeyPairSync("x25519").privateKey, publicKey: key });
    if (isAllZero(probe))
      return null;
    return { raw, kid: kidOf(raw), key };
  } catch {
    return null;
  }
}
function sealAad(run) {
  return `${run.repositoryId}:${run.runId}`;
}
function derive(shared, ephemeralPublic, recipientPublic) {
  if (shared.length !== 32 || isAllZero(shared))
    throw new Error("seal: a low-order public key");
  return Buffer.from(import_node_crypto.hkdfSync("sha256", shared, Buffer.concat([ephemeralPublic, recipientPublic]), INFO, 32));
}
function seal(plaintext, recipient, aad) {
  const ephemeral = import_node_crypto.generateKeyPairSync("x25519");
  const ephemeralPublic = rawPublicOf(ephemeral.publicKey);
  const key = derive(import_node_crypto.diffieHellman({ privateKey: ephemeral.privateKey, publicKey: recipient.key }), ephemeralPublic, recipient.raw);
  const nonce = import_node_crypto.randomBytes(NONCE_BYTES);
  const cipher = import_node_crypto.createCipheriv("aes-256-gcm", key, nonce);
  cipher.setAAD(Buffer.from(aad, "utf8"));
  const body = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return Buffer.concat([
    Buffer.from([SEAL_VERSION]),
    Buffer.from(recipient.kid, "hex"),
    ephemeralPublic,
    nonce,
    body,
    cipher.getAuthTag()
  ]);
}

// packages/github/src/scan/report.ts
var import_node_zlib = require("node:zlib");

// node_modules/zod/v3/helpers/util.js
var util;
(function(util) {
  util.assertEqual = (_) => {};
  function assertIs(_arg) {}
  util.assertIs = assertIs;
  function assertNever(_x) {
    throw new Error;
  }
  util.assertNever = assertNever;
  util.arrayToEnum = (items) => {
    const obj = {};
    for (const item of items) {
      obj[item] = item;
    }
    return obj;
  };
  util.getValidEnumValues = (obj) => {
    const validKeys = util.objectKeys(obj).filter((k) => typeof obj[obj[k]] !== "number");
    const filtered = {};
    for (const k of validKeys) {
      filtered[k] = obj[k];
    }
    return util.objectValues(filtered);
  };
  util.objectValues = (obj) => {
    return util.objectKeys(obj).map(function(e) {
      return obj[e];
    });
  };
  util.objectKeys = typeof Object.keys === "function" ? (obj) => Object.keys(obj) : (object) => {
    const keys = [];
    for (const key in object) {
      if (Object.prototype.hasOwnProperty.call(object, key)) {
        keys.push(key);
      }
    }
    return keys;
  };
  util.find = (arr, checker) => {
    for (const item of arr) {
      if (checker(item))
        return item;
    }
    return;
  };
  util.isInteger = typeof Number.isInteger === "function" ? (val) => Number.isInteger(val) : (val) => typeof val === "number" && Number.isFinite(val) && Math.floor(val) === val;
  function joinValues(array, separator = " | ") {
    return array.map((val) => typeof val === "string" ? `'${val}'` : val).join(separator);
  }
  util.joinValues = joinValues;
  util.jsonStringifyReplacer = (_, value) => {
    if (typeof value === "bigint") {
      return value.toString();
    }
    return value;
  };
})(util || (util = {}));
var objectUtil;
(function(objectUtil) {
  objectUtil.mergeShapes = (first, second) => {
    return {
      ...first,
      ...second
    };
  };
})(objectUtil || (objectUtil = {}));
var ZodParsedType = util.arrayToEnum([
  "string",
  "nan",
  "number",
  "integer",
  "float",
  "boolean",
  "date",
  "bigint",
  "symbol",
  "function",
  "undefined",
  "null",
  "array",
  "object",
  "unknown",
  "promise",
  "void",
  "never",
  "map",
  "set"
]);
var getParsedType = (data) => {
  const t = typeof data;
  switch (t) {
    case "undefined":
      return ZodParsedType.undefined;
    case "string":
      return ZodParsedType.string;
    case "number":
      return Number.isNaN(data) ? ZodParsedType.nan : ZodParsedType.number;
    case "boolean":
      return ZodParsedType.boolean;
    case "function":
      return ZodParsedType.function;
    case "bigint":
      return ZodParsedType.bigint;
    case "symbol":
      return ZodParsedType.symbol;
    case "object":
      if (Array.isArray(data)) {
        return ZodParsedType.array;
      }
      if (data === null) {
        return ZodParsedType.null;
      }
      if (data.then && typeof data.then === "function" && data.catch && typeof data.catch === "function") {
        return ZodParsedType.promise;
      }
      if (typeof Map !== "undefined" && data instanceof Map) {
        return ZodParsedType.map;
      }
      if (typeof Set !== "undefined" && data instanceof Set) {
        return ZodParsedType.set;
      }
      if (typeof Date !== "undefined" && data instanceof Date) {
        return ZodParsedType.date;
      }
      return ZodParsedType.object;
    default:
      return ZodParsedType.unknown;
  }
};

// node_modules/zod/v3/ZodError.js
var ZodIssueCode = util.arrayToEnum([
  "invalid_type",
  "invalid_literal",
  "custom",
  "invalid_union",
  "invalid_union_discriminator",
  "invalid_enum_value",
  "unrecognized_keys",
  "invalid_arguments",
  "invalid_return_type",
  "invalid_date",
  "invalid_string",
  "too_small",
  "too_big",
  "invalid_intersection_types",
  "not_multiple_of",
  "not_finite"
]);
class ZodError extends Error {
  get errors() {
    return this.issues;
  }
  constructor(issues) {
    super();
    this.issues = [];
    this.addIssue = (sub) => {
      this.issues = [...this.issues, sub];
    };
    this.addIssues = (subs = []) => {
      this.issues = [...this.issues, ...subs];
    };
    const actualProto = new.target.prototype;
    if (Object.setPrototypeOf) {
      Object.setPrototypeOf(this, actualProto);
    } else {
      this.__proto__ = actualProto;
    }
    this.name = "ZodError";
    this.issues = issues;
  }
  format(_mapper) {
    const mapper = _mapper || function(issue) {
      return issue.message;
    };
    const fieldErrors = { _errors: [] };
    const processError = (error) => {
      for (const issue of error.issues) {
        if (issue.code === "invalid_union") {
          issue.unionErrors.map(processError);
        } else if (issue.code === "invalid_return_type") {
          processError(issue.returnTypeError);
        } else if (issue.code === "invalid_arguments") {
          processError(issue.argumentsError);
        } else if (issue.path.length === 0) {
          fieldErrors._errors.push(mapper(issue));
        } else {
          let curr = fieldErrors;
          let i = 0;
          while (i < issue.path.length) {
            const el = issue.path[i];
            const terminal = i === issue.path.length - 1;
            if (!terminal) {
              curr[el] = curr[el] || { _errors: [] };
            } else {
              curr[el] = curr[el] || { _errors: [] };
              curr[el]._errors.push(mapper(issue));
            }
            curr = curr[el];
            i++;
          }
        }
      }
    };
    processError(this);
    return fieldErrors;
  }
  static assert(value) {
    if (!(value instanceof ZodError)) {
      throw new Error(`Not a ZodError: ${value}`);
    }
  }
  toString() {
    return this.message;
  }
  get message() {
    return JSON.stringify(this.issues, util.jsonStringifyReplacer, 2);
  }
  get isEmpty() {
    return this.issues.length === 0;
  }
  flatten(mapper = (issue) => issue.message) {
    const fieldErrors = {};
    const formErrors = [];
    for (const sub of this.issues) {
      if (sub.path.length > 0) {
        const firstEl = sub.path[0];
        fieldErrors[firstEl] = fieldErrors[firstEl] || [];
        fieldErrors[firstEl].push(mapper(sub));
      } else {
        formErrors.push(mapper(sub));
      }
    }
    return { formErrors, fieldErrors };
  }
  get formErrors() {
    return this.flatten();
  }
}
ZodError.create = (issues) => {
  const error = new ZodError(issues);
  return error;
};

// node_modules/zod/v3/locales/en.js
var errorMap = (issue, _ctx) => {
  let message;
  switch (issue.code) {
    case ZodIssueCode.invalid_type:
      if (issue.received === ZodParsedType.undefined) {
        message = "Required";
      } else {
        message = `Expected ${issue.expected}, received ${issue.received}`;
      }
      break;
    case ZodIssueCode.invalid_literal:
      message = `Invalid literal value, expected ${JSON.stringify(issue.expected, util.jsonStringifyReplacer)}`;
      break;
    case ZodIssueCode.unrecognized_keys:
      message = `Unrecognized key(s) in object: ${util.joinValues(issue.keys, ", ")}`;
      break;
    case ZodIssueCode.invalid_union:
      message = `Invalid input`;
      break;
    case ZodIssueCode.invalid_union_discriminator:
      message = `Invalid discriminator value. Expected ${util.joinValues(issue.options)}`;
      break;
    case ZodIssueCode.invalid_enum_value:
      message = `Invalid enum value. Expected ${util.joinValues(issue.options)}, received '${issue.received}'`;
      break;
    case ZodIssueCode.invalid_arguments:
      message = `Invalid function arguments`;
      break;
    case ZodIssueCode.invalid_return_type:
      message = `Invalid function return type`;
      break;
    case ZodIssueCode.invalid_date:
      message = `Invalid date`;
      break;
    case ZodIssueCode.invalid_string:
      if (typeof issue.validation === "object") {
        if ("includes" in issue.validation) {
          message = `Invalid input: must include "${issue.validation.includes}"`;
          if (typeof issue.validation.position === "number") {
            message = `${message} at one or more positions greater than or equal to ${issue.validation.position}`;
          }
        } else if ("startsWith" in issue.validation) {
          message = `Invalid input: must start with "${issue.validation.startsWith}"`;
        } else if ("endsWith" in issue.validation) {
          message = `Invalid input: must end with "${issue.validation.endsWith}"`;
        } else {
          util.assertNever(issue.validation);
        }
      } else if (issue.validation !== "regex") {
        message = `Invalid ${issue.validation}`;
      } else {
        message = "Invalid";
      }
      break;
    case ZodIssueCode.too_small:
      if (issue.type === "array")
        message = `Array must contain ${issue.exact ? "exactly" : issue.inclusive ? `at least` : `more than`} ${issue.minimum} element(s)`;
      else if (issue.type === "string")
        message = `String must contain ${issue.exact ? "exactly" : issue.inclusive ? `at least` : `over`} ${issue.minimum} character(s)`;
      else if (issue.type === "number")
        message = `Number must be ${issue.exact ? `exactly equal to ` : issue.inclusive ? `greater than or equal to ` : `greater than `}${issue.minimum}`;
      else if (issue.type === "bigint")
        message = `Number must be ${issue.exact ? `exactly equal to ` : issue.inclusive ? `greater than or equal to ` : `greater than `}${issue.minimum}`;
      else if (issue.type === "date")
        message = `Date must be ${issue.exact ? `exactly equal to ` : issue.inclusive ? `greater than or equal to ` : `greater than `}${new Date(Number(issue.minimum))}`;
      else
        message = "Invalid input";
      break;
    case ZodIssueCode.too_big:
      if (issue.type === "array")
        message = `Array must contain ${issue.exact ? `exactly` : issue.inclusive ? `at most` : `less than`} ${issue.maximum} element(s)`;
      else if (issue.type === "string")
        message = `String must contain ${issue.exact ? `exactly` : issue.inclusive ? `at most` : `under`} ${issue.maximum} character(s)`;
      else if (issue.type === "number")
        message = `Number must be ${issue.exact ? `exactly` : issue.inclusive ? `less than or equal to` : `less than`} ${issue.maximum}`;
      else if (issue.type === "bigint")
        message = `BigInt must be ${issue.exact ? `exactly` : issue.inclusive ? `less than or equal to` : `less than`} ${issue.maximum}`;
      else if (issue.type === "date")
        message = `Date must be ${issue.exact ? `exactly` : issue.inclusive ? `smaller than or equal to` : `smaller than`} ${new Date(Number(issue.maximum))}`;
      else
        message = "Invalid input";
      break;
    case ZodIssueCode.custom:
      message = `Invalid input`;
      break;
    case ZodIssueCode.invalid_intersection_types:
      message = `Intersection results could not be merged`;
      break;
    case ZodIssueCode.not_multiple_of:
      message = `Number must be a multiple of ${issue.multipleOf}`;
      break;
    case ZodIssueCode.not_finite:
      message = "Number must be finite";
      break;
    default:
      message = _ctx.defaultError;
      util.assertNever(issue);
  }
  return { message };
};
var en_default = errorMap;

// node_modules/zod/v3/errors.js
var overrideErrorMap = en_default;
function getErrorMap() {
  return overrideErrorMap;
}

// node_modules/zod/v3/helpers/parseUtil.js
var makeIssue = (params) => {
  const { data, path, errorMaps, issueData } = params;
  const fullPath = [...path, ...issueData.path || []];
  const fullIssue = {
    ...issueData,
    path: fullPath
  };
  if (issueData.message !== undefined) {
    return {
      ...issueData,
      path: fullPath,
      message: issueData.message
    };
  }
  let errorMessage = "";
  const maps = errorMaps.filter((m) => !!m).slice().reverse();
  for (const map of maps) {
    errorMessage = map(fullIssue, { data, defaultError: errorMessage }).message;
  }
  return {
    ...issueData,
    path: fullPath,
    message: errorMessage
  };
};
function addIssueToContext(ctx, issueData) {
  const overrideMap = getErrorMap();
  const issue = makeIssue({
    issueData,
    data: ctx.data,
    path: ctx.path,
    errorMaps: [
      ctx.common.contextualErrorMap,
      ctx.schemaErrorMap,
      overrideMap,
      overrideMap === en_default ? undefined : en_default
    ].filter((x) => !!x)
  });
  ctx.common.issues.push(issue);
}

class ParseStatus {
  constructor() {
    this.value = "valid";
  }
  dirty() {
    if (this.value === "valid")
      this.value = "dirty";
  }
  abort() {
    if (this.value !== "aborted")
      this.value = "aborted";
  }
  static mergeArray(status, results) {
    const arrayValue = [];
    for (const s of results) {
      if (s.status === "aborted")
        return INVALID;
      if (s.status === "dirty")
        status.dirty();
      arrayValue.push(s.value);
    }
    return { status: status.value, value: arrayValue };
  }
  static async mergeObjectAsync(status, pairs) {
    const syncPairs = [];
    for (const pair of pairs) {
      const key = await pair.key;
      const value = await pair.value;
      syncPairs.push({
        key,
        value
      });
    }
    return ParseStatus.mergeObjectSync(status, syncPairs);
  }
  static mergeObjectSync(status, pairs) {
    const finalObject = {};
    for (const pair of pairs) {
      const { key, value } = pair;
      if (key.status === "aborted")
        return INVALID;
      if (value.status === "aborted")
        return INVALID;
      if (key.status === "dirty")
        status.dirty();
      if (value.status === "dirty")
        status.dirty();
      if (key.value !== "__proto__" && (typeof value.value !== "undefined" || pair.alwaysSet)) {
        finalObject[key.value] = value.value;
      }
    }
    return { status: status.value, value: finalObject };
  }
}
var INVALID = Object.freeze({
  status: "aborted"
});
var DIRTY = (value) => ({ status: "dirty", value });
var OK = (value) => ({ status: "valid", value });
var isAborted = (x) => x.status === "aborted";
var isDirty = (x) => x.status === "dirty";
var isValid = (x) => x.status === "valid";
var isAsync = (x) => typeof Promise !== "undefined" && x instanceof Promise;

// node_modules/zod/v3/helpers/errorUtil.js
var errorUtil;
(function(errorUtil) {
  errorUtil.errToObj = (message) => typeof message === "string" ? { message } : message || {};
  errorUtil.toString = (message) => typeof message === "string" ? message : message?.message;
})(errorUtil || (errorUtil = {}));

// node_modules/zod/v3/types.js
class ParseInputLazyPath {
  constructor(parent, value, path, key) {
    this._cachedPath = [];
    this.parent = parent;
    this.data = value;
    this._path = path;
    this._key = key;
  }
  get path() {
    if (!this._cachedPath.length) {
      if (Array.isArray(this._key)) {
        this._cachedPath.push(...this._path, ...this._key);
      } else {
        this._cachedPath.push(...this._path, this._key);
      }
    }
    return this._cachedPath;
  }
}
var handleResult = (ctx, result) => {
  if (isValid(result)) {
    return { success: true, data: result.value };
  } else {
    if (!ctx.common.issues.length) {
      throw new Error("Validation failed but no issues detected.");
    }
    return {
      success: false,
      get error() {
        if (this._error)
          return this._error;
        const error = new ZodError(ctx.common.issues);
        this._error = error;
        return this._error;
      }
    };
  }
};
function processCreateParams(params) {
  if (!params)
    return {};
  const { errorMap, invalid_type_error, required_error, description } = params;
  if (errorMap && (invalid_type_error || required_error)) {
    throw new Error(`Can't use "invalid_type_error" or "required_error" in conjunction with custom error map.`);
  }
  if (errorMap)
    return { errorMap, description };
  const customMap = (iss, ctx) => {
    const { message } = params;
    if (iss.code === "invalid_enum_value") {
      return { message: message ?? ctx.defaultError };
    }
    if (typeof ctx.data === "undefined") {
      return { message: message ?? required_error ?? ctx.defaultError };
    }
    if (iss.code !== "invalid_type")
      return { message: ctx.defaultError };
    return { message: message ?? invalid_type_error ?? ctx.defaultError };
  };
  return { errorMap: customMap, description };
}

class ZodType {
  get description() {
    return this._def.description;
  }
  _getType(input) {
    return getParsedType(input.data);
  }
  _getOrReturnCtx(input, ctx) {
    return ctx || {
      common: input.parent.common,
      data: input.data,
      parsedType: getParsedType(input.data),
      schemaErrorMap: this._def.errorMap,
      path: input.path,
      parent: input.parent
    };
  }
  _processInputParams(input) {
    return {
      status: new ParseStatus,
      ctx: {
        common: input.parent.common,
        data: input.data,
        parsedType: getParsedType(input.data),
        schemaErrorMap: this._def.errorMap,
        path: input.path,
        parent: input.parent
      }
    };
  }
  _parseSync(input) {
    const result = this._parse(input);
    if (isAsync(result)) {
      throw new Error("Synchronous parse encountered promise.");
    }
    return result;
  }
  _parseAsync(input) {
    const result = this._parse(input);
    return Promise.resolve(result);
  }
  parse(data, params) {
    const result = this.safeParse(data, params);
    if (result.success)
      return result.data;
    throw result.error;
  }
  safeParse(data, params) {
    const ctx = {
      common: {
        issues: [],
        async: params?.async ?? false,
        contextualErrorMap: params?.errorMap
      },
      path: params?.path || [],
      schemaErrorMap: this._def.errorMap,
      parent: null,
      data,
      parsedType: getParsedType(data)
    };
    const result = this._parseSync({ data, path: ctx.path, parent: ctx });
    return handleResult(ctx, result);
  }
  "~validate"(data) {
    const ctx = {
      common: {
        issues: [],
        async: !!this["~standard"].async
      },
      path: [],
      schemaErrorMap: this._def.errorMap,
      parent: null,
      data,
      parsedType: getParsedType(data)
    };
    if (!this["~standard"].async) {
      try {
        const result = this._parseSync({ data, path: [], parent: ctx });
        return isValid(result) ? {
          value: result.value
        } : {
          issues: ctx.common.issues
        };
      } catch (err) {
        if (err?.message?.toLowerCase()?.includes("encountered")) {
          this["~standard"].async = true;
        }
        ctx.common = {
          issues: [],
          async: true
        };
      }
    }
    return this._parseAsync({ data, path: [], parent: ctx }).then((result) => isValid(result) ? {
      value: result.value
    } : {
      issues: ctx.common.issues
    });
  }
  async parseAsync(data, params) {
    const result = await this.safeParseAsync(data, params);
    if (result.success)
      return result.data;
    throw result.error;
  }
  async safeParseAsync(data, params) {
    const ctx = {
      common: {
        issues: [],
        contextualErrorMap: params?.errorMap,
        async: true
      },
      path: params?.path || [],
      schemaErrorMap: this._def.errorMap,
      parent: null,
      data,
      parsedType: getParsedType(data)
    };
    const maybeAsyncResult = this._parse({ data, path: ctx.path, parent: ctx });
    const result = await (isAsync(maybeAsyncResult) ? maybeAsyncResult : Promise.resolve(maybeAsyncResult));
    return handleResult(ctx, result);
  }
  refine(check, message) {
    const getIssueProperties = (val) => {
      if (typeof message === "string" || typeof message === "undefined") {
        return { message };
      } else if (typeof message === "function") {
        return message(val);
      } else {
        return message;
      }
    };
    return this._refinement((val, ctx) => {
      const result = check(val);
      const setError = () => ctx.addIssue({
        code: ZodIssueCode.custom,
        ...getIssueProperties(val)
      });
      if (typeof Promise !== "undefined" && result instanceof Promise) {
        return result.then((data) => {
          if (!data) {
            setError();
            return false;
          } else {
            return true;
          }
        });
      }
      if (!result) {
        setError();
        return false;
      } else {
        return true;
      }
    });
  }
  refinement(check, refinementData) {
    return this._refinement((val, ctx) => {
      if (!check(val)) {
        ctx.addIssue(typeof refinementData === "function" ? refinementData(val, ctx) : refinementData);
        return false;
      } else {
        return true;
      }
    });
  }
  _refinement(refinement) {
    return new ZodEffects({
      schema: this,
      typeName: ZodFirstPartyTypeKind.ZodEffects,
      effect: { type: "refinement", refinement }
    });
  }
  superRefine(refinement) {
    return this._refinement(refinement);
  }
  constructor(def) {
    this.spa = this.safeParseAsync;
    this._def = def;
    this.parse = this.parse.bind(this);
    this.safeParse = this.safeParse.bind(this);
    this.parseAsync = this.parseAsync.bind(this);
    this.safeParseAsync = this.safeParseAsync.bind(this);
    this.spa = this.spa.bind(this);
    this.refine = this.refine.bind(this);
    this.refinement = this.refinement.bind(this);
    this.superRefine = this.superRefine.bind(this);
    this.optional = this.optional.bind(this);
    this.nullable = this.nullable.bind(this);
    this.nullish = this.nullish.bind(this);
    this.array = this.array.bind(this);
    this.promise = this.promise.bind(this);
    this.or = this.or.bind(this);
    this.and = this.and.bind(this);
    this.transform = this.transform.bind(this);
    this.brand = this.brand.bind(this);
    this.default = this.default.bind(this);
    this.catch = this.catch.bind(this);
    this.describe = this.describe.bind(this);
    this.pipe = this.pipe.bind(this);
    this.readonly = this.readonly.bind(this);
    this.isNullable = this.isNullable.bind(this);
    this.isOptional = this.isOptional.bind(this);
    this["~standard"] = {
      version: 1,
      vendor: "zod",
      validate: (data) => this["~validate"](data)
    };
  }
  optional() {
    return ZodOptional.create(this, this._def);
  }
  nullable() {
    return ZodNullable.create(this, this._def);
  }
  nullish() {
    return this.nullable().optional();
  }
  array() {
    return ZodArray.create(this);
  }
  promise() {
    return ZodPromise.create(this, this._def);
  }
  or(option) {
    return ZodUnion.create([this, option], this._def);
  }
  and(incoming) {
    return ZodIntersection.create(this, incoming, this._def);
  }
  transform(transform) {
    return new ZodEffects({
      ...processCreateParams(this._def),
      schema: this,
      typeName: ZodFirstPartyTypeKind.ZodEffects,
      effect: { type: "transform", transform }
    });
  }
  default(def) {
    const defaultValueFunc = typeof def === "function" ? def : () => def;
    return new ZodDefault({
      ...processCreateParams(this._def),
      innerType: this,
      defaultValue: defaultValueFunc,
      typeName: ZodFirstPartyTypeKind.ZodDefault
    });
  }
  brand() {
    return new ZodBranded({
      typeName: ZodFirstPartyTypeKind.ZodBranded,
      type: this,
      ...processCreateParams(this._def)
    });
  }
  catch(def) {
    const catchValueFunc = typeof def === "function" ? def : () => def;
    return new ZodCatch({
      ...processCreateParams(this._def),
      innerType: this,
      catchValue: catchValueFunc,
      typeName: ZodFirstPartyTypeKind.ZodCatch
    });
  }
  describe(description) {
    const This = this.constructor;
    return new This({
      ...this._def,
      description
    });
  }
  pipe(target) {
    return ZodPipeline.create(this, target);
  }
  readonly() {
    return ZodReadonly.create(this);
  }
  isOptional() {
    return this.safeParse(undefined).success;
  }
  isNullable() {
    return this.safeParse(null).success;
  }
}
var cuidRegex = /^c[^\s-]{8,}$/i;
var cuid2Regex = /^[0-9a-z]+$/;
var ulidRegex = /^[0-9A-HJKMNP-TV-Z]{26}$/i;
var uuidRegex = /^[0-9a-fA-F]{8}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{12}$/i;
var nanoidRegex = /^[a-z0-9_-]{21}$/i;
var jwtRegex = /^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]*$/;
var durationRegex = /^[-+]?P(?!$)(?:(?:[-+]?\d+Y)|(?:[-+]?\d+[.,]\d+Y$))?(?:(?:[-+]?\d+M)|(?:[-+]?\d+[.,]\d+M$))?(?:(?:[-+]?\d+W)|(?:[-+]?\d+[.,]\d+W$))?(?:(?:[-+]?\d+D)|(?:[-+]?\d+[.,]\d+D$))?(?:T(?=[\d+-])(?:(?:[-+]?\d+H)|(?:[-+]?\d+[.,]\d+H$))?(?:(?:[-+]?\d+M)|(?:[-+]?\d+[.,]\d+M$))?(?:[-+]?\d+(?:[.,]\d+)?S)?)??$/;
var emailRegex = /^(?!\.)(?!.*\.\.)([A-Z0-9_'+\-\.]*)[A-Z0-9_+-]@([A-Z0-9][A-Z0-9\-]*\.)+[A-Z]{2,}$/i;
var _emojiRegex = `^(\\p{Extended_Pictographic}|\\p{Emoji_Component})+$`;
var emojiRegex;
var ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])$/;
var ipv4CidrRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\/(3[0-2]|[12]?[0-9])$/;
var ipv6Regex = /^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$/;
var ipv6CidrRegex = /^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))\/(12[0-8]|1[01][0-9]|[1-9]?[0-9])$/;
var base64Regex = /^([0-9a-zA-Z+/]{4})*(([0-9a-zA-Z+/]{2}==)|([0-9a-zA-Z+/]{3}=))?$/;
var base64urlRegex = /^([0-9a-zA-Z-_]{4})*(([0-9a-zA-Z-_]{2}(==)?)|([0-9a-zA-Z-_]{3}(=)?))?$/;
var dateRegexSource = `((\\d\\d[2468][048]|\\d\\d[13579][26]|\\d\\d0[48]|[02468][048]00|[13579][26]00)-02-29|\\d{4}-((0[13578]|1[02])-(0[1-9]|[12]\\d|3[01])|(0[469]|11)-(0[1-9]|[12]\\d|30)|(02)-(0[1-9]|1\\d|2[0-8])))`;
var dateRegex = new RegExp(`^${dateRegexSource}$`);
function timeRegexSource(args) {
  let secondsRegexSource = `[0-5]\\d`;
  if (args.precision) {
    secondsRegexSource = `${secondsRegexSource}\\.\\d{${args.precision}}`;
  } else if (args.precision == null) {
    secondsRegexSource = `${secondsRegexSource}(\\.\\d+)?`;
  }
  const secondsQuantifier = args.precision ? "+" : "?";
  return `([01]\\d|2[0-3]):[0-5]\\d(:${secondsRegexSource})${secondsQuantifier}`;
}
function timeRegex(args) {
  return new RegExp(`^${timeRegexSource(args)}$`);
}
function datetimeRegex(args) {
  let regex = `${dateRegexSource}T${timeRegexSource(args)}`;
  const opts = [];
  opts.push(args.local ? `Z?` : `Z`);
  if (args.offset)
    opts.push(`([+-]\\d{2}:?\\d{2})`);
  regex = `${regex}(${opts.join("|")})`;
  return new RegExp(`^${regex}$`);
}
function isValidIP(ip, version) {
  if ((version === "v4" || !version) && ipv4Regex.test(ip)) {
    return true;
  }
  if ((version === "v6" || !version) && ipv6Regex.test(ip)) {
    return true;
  }
  return false;
}
function isValidJWT(jwt, alg) {
  if (!jwtRegex.test(jwt))
    return false;
  try {
    const [header] = jwt.split(".");
    if (!header)
      return false;
    const base64 = header.replace(/-/g, "+").replace(/_/g, "/").padEnd(header.length + (4 - header.length % 4) % 4, "=");
    const decoded = JSON.parse(atob(base64));
    if (typeof decoded !== "object" || decoded === null)
      return false;
    if ("typ" in decoded && decoded?.typ !== "JWT")
      return false;
    if (!decoded.alg)
      return false;
    if (alg && decoded.alg !== alg)
      return false;
    return true;
  } catch {
    return false;
  }
}
function isValidCidr(ip, version) {
  if ((version === "v4" || !version) && ipv4CidrRegex.test(ip)) {
    return true;
  }
  if ((version === "v6" || !version) && ipv6CidrRegex.test(ip)) {
    return true;
  }
  return false;
}

class ZodString extends ZodType {
  _parse(input) {
    if (this._def.coerce) {
      input.data = String(input.data);
    }
    const parsedType = this._getType(input);
    if (parsedType !== ZodParsedType.string) {
      const ctx = this._getOrReturnCtx(input);
      addIssueToContext(ctx, {
        code: ZodIssueCode.invalid_type,
        expected: ZodParsedType.string,
        received: ctx.parsedType
      });
      return INVALID;
    }
    const status = new ParseStatus;
    let ctx = undefined;
    for (const check of this._def.checks) {
      if (check.kind === "min") {
        if (input.data.length < check.value) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            code: ZodIssueCode.too_small,
            minimum: check.value,
            type: "string",
            inclusive: true,
            exact: false,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "max") {
        if (input.data.length > check.value) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            code: ZodIssueCode.too_big,
            maximum: check.value,
            type: "string",
            inclusive: true,
            exact: false,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "length") {
        const tooBig = input.data.length > check.value;
        const tooSmall = input.data.length < check.value;
        if (tooBig || tooSmall) {
          ctx = this._getOrReturnCtx(input, ctx);
          if (tooBig) {
            addIssueToContext(ctx, {
              code: ZodIssueCode.too_big,
              maximum: check.value,
              type: "string",
              inclusive: true,
              exact: true,
              message: check.message
            });
          } else if (tooSmall) {
            addIssueToContext(ctx, {
              code: ZodIssueCode.too_small,
              minimum: check.value,
              type: "string",
              inclusive: true,
              exact: true,
              message: check.message
            });
          }
          status.dirty();
        }
      } else if (check.kind === "email") {
        if (!emailRegex.test(input.data)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            validation: "email",
            code: ZodIssueCode.invalid_string,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "emoji") {
        if (!emojiRegex) {
          emojiRegex = new RegExp(_emojiRegex, "u");
        }
        if (!emojiRegex.test(input.data)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            validation: "emoji",
            code: ZodIssueCode.invalid_string,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "uuid") {
        if (!uuidRegex.test(input.data)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            validation: "uuid",
            code: ZodIssueCode.invalid_string,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "nanoid") {
        if (!nanoidRegex.test(input.data)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            validation: "nanoid",
            code: ZodIssueCode.invalid_string,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "cuid") {
        if (!cuidRegex.test(input.data)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            validation: "cuid",
            code: ZodIssueCode.invalid_string,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "cuid2") {
        if (!cuid2Regex.test(input.data)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            validation: "cuid2",
            code: ZodIssueCode.invalid_string,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "ulid") {
        if (!ulidRegex.test(input.data)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            validation: "ulid",
            code: ZodIssueCode.invalid_string,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "url") {
        try {
          new URL(input.data);
        } catch {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            validation: "url",
            code: ZodIssueCode.invalid_string,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "regex") {
        check.regex.lastIndex = 0;
        const testResult = check.regex.test(input.data);
        if (!testResult) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            validation: "regex",
            code: ZodIssueCode.invalid_string,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "trim") {
        input.data = input.data.trim();
      } else if (check.kind === "includes") {
        if (!input.data.includes(check.value, check.position)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            code: ZodIssueCode.invalid_string,
            validation: { includes: check.value, position: check.position },
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "toLowerCase") {
        input.data = input.data.toLowerCase();
      } else if (check.kind === "toUpperCase") {
        input.data = input.data.toUpperCase();
      } else if (check.kind === "startsWith") {
        if (!input.data.startsWith(check.value)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            code: ZodIssueCode.invalid_string,
            validation: { startsWith: check.value },
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "endsWith") {
        if (!input.data.endsWith(check.value)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            code: ZodIssueCode.invalid_string,
            validation: { endsWith: check.value },
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "datetime") {
        const regex = datetimeRegex(check);
        if (!regex.test(input.data)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            code: ZodIssueCode.invalid_string,
            validation: "datetime",
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "date") {
        const regex = dateRegex;
        if (!regex.test(input.data)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            code: ZodIssueCode.invalid_string,
            validation: "date",
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "time") {
        const regex = timeRegex(check);
        if (!regex.test(input.data)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            code: ZodIssueCode.invalid_string,
            validation: "time",
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "duration") {
        if (!durationRegex.test(input.data)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            validation: "duration",
            code: ZodIssueCode.invalid_string,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "ip") {
        if (!isValidIP(input.data, check.version)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            validation: "ip",
            code: ZodIssueCode.invalid_string,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "jwt") {
        if (!isValidJWT(input.data, check.alg)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            validation: "jwt",
            code: ZodIssueCode.invalid_string,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "cidr") {
        if (!isValidCidr(input.data, check.version)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            validation: "cidr",
            code: ZodIssueCode.invalid_string,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "base64") {
        if (!base64Regex.test(input.data)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            validation: "base64",
            code: ZodIssueCode.invalid_string,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "base64url") {
        if (!base64urlRegex.test(input.data)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            validation: "base64url",
            code: ZodIssueCode.invalid_string,
            message: check.message
          });
          status.dirty();
        }
      } else {
        util.assertNever(check);
      }
    }
    return { status: status.value, value: input.data };
  }
  _regex(regex, validation, message) {
    return this.refinement((data) => regex.test(data), {
      validation,
      code: ZodIssueCode.invalid_string,
      ...errorUtil.errToObj(message)
    });
  }
  _addCheck(check) {
    return new ZodString({
      ...this._def,
      checks: [...this._def.checks, check]
    });
  }
  email(message) {
    return this._addCheck({ kind: "email", ...errorUtil.errToObj(message) });
  }
  url(message) {
    return this._addCheck({ kind: "url", ...errorUtil.errToObj(message) });
  }
  emoji(message) {
    return this._addCheck({ kind: "emoji", ...errorUtil.errToObj(message) });
  }
  uuid(message) {
    return this._addCheck({ kind: "uuid", ...errorUtil.errToObj(message) });
  }
  nanoid(message) {
    return this._addCheck({ kind: "nanoid", ...errorUtil.errToObj(message) });
  }
  cuid(message) {
    return this._addCheck({ kind: "cuid", ...errorUtil.errToObj(message) });
  }
  cuid2(message) {
    return this._addCheck({ kind: "cuid2", ...errorUtil.errToObj(message) });
  }
  ulid(message) {
    return this._addCheck({ kind: "ulid", ...errorUtil.errToObj(message) });
  }
  base64(message) {
    return this._addCheck({ kind: "base64", ...errorUtil.errToObj(message) });
  }
  base64url(message) {
    return this._addCheck({
      kind: "base64url",
      ...errorUtil.errToObj(message)
    });
  }
  jwt(options) {
    return this._addCheck({ kind: "jwt", ...errorUtil.errToObj(options) });
  }
  ip(options) {
    return this._addCheck({ kind: "ip", ...errorUtil.errToObj(options) });
  }
  cidr(options) {
    return this._addCheck({ kind: "cidr", ...errorUtil.errToObj(options) });
  }
  datetime(options) {
    if (typeof options === "string") {
      return this._addCheck({
        kind: "datetime",
        precision: null,
        offset: false,
        local: false,
        message: options
      });
    }
    return this._addCheck({
      kind: "datetime",
      precision: typeof options?.precision === "undefined" ? null : options?.precision,
      offset: options?.offset ?? false,
      local: options?.local ?? false,
      ...errorUtil.errToObj(options?.message)
    });
  }
  date(message) {
    return this._addCheck({ kind: "date", message });
  }
  time(options) {
    if (typeof options === "string") {
      return this._addCheck({
        kind: "time",
        precision: null,
        message: options
      });
    }
    return this._addCheck({
      kind: "time",
      precision: typeof options?.precision === "undefined" ? null : options?.precision,
      ...errorUtil.errToObj(options?.message)
    });
  }
  duration(message) {
    return this._addCheck({ kind: "duration", ...errorUtil.errToObj(message) });
  }
  regex(regex, message) {
    return this._addCheck({
      kind: "regex",
      regex,
      ...errorUtil.errToObj(message)
    });
  }
  includes(value, options) {
    return this._addCheck({
      kind: "includes",
      value,
      position: options?.position,
      ...errorUtil.errToObj(options?.message)
    });
  }
  startsWith(value, message) {
    return this._addCheck({
      kind: "startsWith",
      value,
      ...errorUtil.errToObj(message)
    });
  }
  endsWith(value, message) {
    return this._addCheck({
      kind: "endsWith",
      value,
      ...errorUtil.errToObj(message)
    });
  }
  min(minLength, message) {
    return this._addCheck({
      kind: "min",
      value: minLength,
      ...errorUtil.errToObj(message)
    });
  }
  max(maxLength, message) {
    return this._addCheck({
      kind: "max",
      value: maxLength,
      ...errorUtil.errToObj(message)
    });
  }
  length(len, message) {
    return this._addCheck({
      kind: "length",
      value: len,
      ...errorUtil.errToObj(message)
    });
  }
  nonempty(message) {
    return this.min(1, errorUtil.errToObj(message));
  }
  trim() {
    return new ZodString({
      ...this._def,
      checks: [...this._def.checks, { kind: "trim" }]
    });
  }
  toLowerCase() {
    return new ZodString({
      ...this._def,
      checks: [...this._def.checks, { kind: "toLowerCase" }]
    });
  }
  toUpperCase() {
    return new ZodString({
      ...this._def,
      checks: [...this._def.checks, { kind: "toUpperCase" }]
    });
  }
  get isDatetime() {
    return !!this._def.checks.find((ch) => ch.kind === "datetime");
  }
  get isDate() {
    return !!this._def.checks.find((ch) => ch.kind === "date");
  }
  get isTime() {
    return !!this._def.checks.find((ch) => ch.kind === "time");
  }
  get isDuration() {
    return !!this._def.checks.find((ch) => ch.kind === "duration");
  }
  get isEmail() {
    return !!this._def.checks.find((ch) => ch.kind === "email");
  }
  get isURL() {
    return !!this._def.checks.find((ch) => ch.kind === "url");
  }
  get isEmoji() {
    return !!this._def.checks.find((ch) => ch.kind === "emoji");
  }
  get isUUID() {
    return !!this._def.checks.find((ch) => ch.kind === "uuid");
  }
  get isNANOID() {
    return !!this._def.checks.find((ch) => ch.kind === "nanoid");
  }
  get isCUID() {
    return !!this._def.checks.find((ch) => ch.kind === "cuid");
  }
  get isCUID2() {
    return !!this._def.checks.find((ch) => ch.kind === "cuid2");
  }
  get isULID() {
    return !!this._def.checks.find((ch) => ch.kind === "ulid");
  }
  get isIP() {
    return !!this._def.checks.find((ch) => ch.kind === "ip");
  }
  get isCIDR() {
    return !!this._def.checks.find((ch) => ch.kind === "cidr");
  }
  get isBase64() {
    return !!this._def.checks.find((ch) => ch.kind === "base64");
  }
  get isBase64url() {
    return !!this._def.checks.find((ch) => ch.kind === "base64url");
  }
  get minLength() {
    let min = null;
    for (const ch of this._def.checks) {
      if (ch.kind === "min") {
        if (min === null || ch.value > min)
          min = ch.value;
      }
    }
    return min;
  }
  get maxLength() {
    let max = null;
    for (const ch of this._def.checks) {
      if (ch.kind === "max") {
        if (max === null || ch.value < max)
          max = ch.value;
      }
    }
    return max;
  }
}
ZodString.create = (params) => {
  return new ZodString({
    checks: [],
    typeName: ZodFirstPartyTypeKind.ZodString,
    coerce: params?.coerce ?? false,
    ...processCreateParams(params)
  });
};
function floatSafeRemainder(val, step) {
  const valDecCount = (val.toString().split(".")[1] || "").length;
  const stepDecCount = (step.toString().split(".")[1] || "").length;
  const decCount = valDecCount > stepDecCount ? valDecCount : stepDecCount;
  const valInt = Number.parseInt(val.toFixed(decCount).replace(".", ""));
  const stepInt = Number.parseInt(step.toFixed(decCount).replace(".", ""));
  return valInt % stepInt / 10 ** decCount;
}

class ZodNumber extends ZodType {
  constructor() {
    super(...arguments);
    this.min = this.gte;
    this.max = this.lte;
    this.step = this.multipleOf;
  }
  _parse(input) {
    if (this._def.coerce) {
      input.data = Number(input.data);
    }
    const parsedType = this._getType(input);
    if (parsedType !== ZodParsedType.number) {
      const ctx = this._getOrReturnCtx(input);
      addIssueToContext(ctx, {
        code: ZodIssueCode.invalid_type,
        expected: ZodParsedType.number,
        received: ctx.parsedType
      });
      return INVALID;
    }
    let ctx = undefined;
    const status = new ParseStatus;
    for (const check of this._def.checks) {
      if (check.kind === "int") {
        if (!util.isInteger(input.data)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            code: ZodIssueCode.invalid_type,
            expected: "integer",
            received: "float",
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "min") {
        const tooSmall = check.inclusive ? input.data < check.value : input.data <= check.value;
        if (tooSmall) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            code: ZodIssueCode.too_small,
            minimum: check.value,
            type: "number",
            inclusive: check.inclusive,
            exact: false,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "max") {
        const tooBig = check.inclusive ? input.data > check.value : input.data >= check.value;
        if (tooBig) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            code: ZodIssueCode.too_big,
            maximum: check.value,
            type: "number",
            inclusive: check.inclusive,
            exact: false,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "multipleOf") {
        if (floatSafeRemainder(input.data, check.value) !== 0) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            code: ZodIssueCode.not_multiple_of,
            multipleOf: check.value,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "finite") {
        if (!Number.isFinite(input.data)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            code: ZodIssueCode.not_finite,
            message: check.message
          });
          status.dirty();
        }
      } else {
        util.assertNever(check);
      }
    }
    return { status: status.value, value: input.data };
  }
  gte(value, message) {
    return this.setLimit("min", value, true, errorUtil.toString(message));
  }
  gt(value, message) {
    return this.setLimit("min", value, false, errorUtil.toString(message));
  }
  lte(value, message) {
    return this.setLimit("max", value, true, errorUtil.toString(message));
  }
  lt(value, message) {
    return this.setLimit("max", value, false, errorUtil.toString(message));
  }
  setLimit(kind, value, inclusive, message) {
    return new ZodNumber({
      ...this._def,
      checks: [
        ...this._def.checks,
        {
          kind,
          value,
          inclusive,
          message: errorUtil.toString(message)
        }
      ]
    });
  }
  _addCheck(check) {
    return new ZodNumber({
      ...this._def,
      checks: [...this._def.checks, check]
    });
  }
  int(message) {
    return this._addCheck({
      kind: "int",
      message: errorUtil.toString(message)
    });
  }
  positive(message) {
    return this._addCheck({
      kind: "min",
      value: 0,
      inclusive: false,
      message: errorUtil.toString(message)
    });
  }
  negative(message) {
    return this._addCheck({
      kind: "max",
      value: 0,
      inclusive: false,
      message: errorUtil.toString(message)
    });
  }
  nonpositive(message) {
    return this._addCheck({
      kind: "max",
      value: 0,
      inclusive: true,
      message: errorUtil.toString(message)
    });
  }
  nonnegative(message) {
    return this._addCheck({
      kind: "min",
      value: 0,
      inclusive: true,
      message: errorUtil.toString(message)
    });
  }
  multipleOf(value, message) {
    return this._addCheck({
      kind: "multipleOf",
      value,
      message: errorUtil.toString(message)
    });
  }
  finite(message) {
    return this._addCheck({
      kind: "finite",
      message: errorUtil.toString(message)
    });
  }
  safe(message) {
    return this._addCheck({
      kind: "min",
      inclusive: true,
      value: Number.MIN_SAFE_INTEGER,
      message: errorUtil.toString(message)
    })._addCheck({
      kind: "max",
      inclusive: true,
      value: Number.MAX_SAFE_INTEGER,
      message: errorUtil.toString(message)
    });
  }
  get minValue() {
    let min = null;
    for (const ch of this._def.checks) {
      if (ch.kind === "min") {
        if (min === null || ch.value > min)
          min = ch.value;
      }
    }
    return min;
  }
  get maxValue() {
    let max = null;
    for (const ch of this._def.checks) {
      if (ch.kind === "max") {
        if (max === null || ch.value < max)
          max = ch.value;
      }
    }
    return max;
  }
  get isInt() {
    return !!this._def.checks.find((ch) => ch.kind === "int" || ch.kind === "multipleOf" && util.isInteger(ch.value));
  }
  get isFinite() {
    let max = null;
    let min = null;
    for (const ch of this._def.checks) {
      if (ch.kind === "finite" || ch.kind === "int" || ch.kind === "multipleOf") {
        return true;
      } else if (ch.kind === "min") {
        if (min === null || ch.value > min)
          min = ch.value;
      } else if (ch.kind === "max") {
        if (max === null || ch.value < max)
          max = ch.value;
      }
    }
    return Number.isFinite(min) && Number.isFinite(max);
  }
}
ZodNumber.create = (params) => {
  return new ZodNumber({
    checks: [],
    typeName: ZodFirstPartyTypeKind.ZodNumber,
    coerce: params?.coerce || false,
    ...processCreateParams(params)
  });
};

class ZodBigInt extends ZodType {
  constructor() {
    super(...arguments);
    this.min = this.gte;
    this.max = this.lte;
  }
  _parse(input) {
    if (this._def.coerce) {
      try {
        input.data = BigInt(input.data);
      } catch {
        return this._getInvalidInput(input);
      }
    }
    const parsedType = this._getType(input);
    if (parsedType !== ZodParsedType.bigint) {
      return this._getInvalidInput(input);
    }
    let ctx = undefined;
    const status = new ParseStatus;
    for (const check of this._def.checks) {
      if (check.kind === "min") {
        const tooSmall = check.inclusive ? input.data < check.value : input.data <= check.value;
        if (tooSmall) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            code: ZodIssueCode.too_small,
            type: "bigint",
            minimum: check.value,
            inclusive: check.inclusive,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "max") {
        const tooBig = check.inclusive ? input.data > check.value : input.data >= check.value;
        if (tooBig) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            code: ZodIssueCode.too_big,
            type: "bigint",
            maximum: check.value,
            inclusive: check.inclusive,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "multipleOf") {
        if (input.data % check.value !== BigInt(0)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            code: ZodIssueCode.not_multiple_of,
            multipleOf: check.value,
            message: check.message
          });
          status.dirty();
        }
      } else {
        util.assertNever(check);
      }
    }
    return { status: status.value, value: input.data };
  }
  _getInvalidInput(input) {
    const ctx = this._getOrReturnCtx(input);
    addIssueToContext(ctx, {
      code: ZodIssueCode.invalid_type,
      expected: ZodParsedType.bigint,
      received: ctx.parsedType
    });
    return INVALID;
  }
  gte(value, message) {
    return this.setLimit("min", value, true, errorUtil.toString(message));
  }
  gt(value, message) {
    return this.setLimit("min", value, false, errorUtil.toString(message));
  }
  lte(value, message) {
    return this.setLimit("max", value, true, errorUtil.toString(message));
  }
  lt(value, message) {
    return this.setLimit("max", value, false, errorUtil.toString(message));
  }
  setLimit(kind, value, inclusive, message) {
    return new ZodBigInt({
      ...this._def,
      checks: [
        ...this._def.checks,
        {
          kind,
          value,
          inclusive,
          message: errorUtil.toString(message)
        }
      ]
    });
  }
  _addCheck(check) {
    return new ZodBigInt({
      ...this._def,
      checks: [...this._def.checks, check]
    });
  }
  positive(message) {
    return this._addCheck({
      kind: "min",
      value: BigInt(0),
      inclusive: false,
      message: errorUtil.toString(message)
    });
  }
  negative(message) {
    return this._addCheck({
      kind: "max",
      value: BigInt(0),
      inclusive: false,
      message: errorUtil.toString(message)
    });
  }
  nonpositive(message) {
    return this._addCheck({
      kind: "max",
      value: BigInt(0),
      inclusive: true,
      message: errorUtil.toString(message)
    });
  }
  nonnegative(message) {
    return this._addCheck({
      kind: "min",
      value: BigInt(0),
      inclusive: true,
      message: errorUtil.toString(message)
    });
  }
  multipleOf(value, message) {
    return this._addCheck({
      kind: "multipleOf",
      value,
      message: errorUtil.toString(message)
    });
  }
  get minValue() {
    let min = null;
    for (const ch of this._def.checks) {
      if (ch.kind === "min") {
        if (min === null || ch.value > min)
          min = ch.value;
      }
    }
    return min;
  }
  get maxValue() {
    let max = null;
    for (const ch of this._def.checks) {
      if (ch.kind === "max") {
        if (max === null || ch.value < max)
          max = ch.value;
      }
    }
    return max;
  }
}
ZodBigInt.create = (params) => {
  return new ZodBigInt({
    checks: [],
    typeName: ZodFirstPartyTypeKind.ZodBigInt,
    coerce: params?.coerce ?? false,
    ...processCreateParams(params)
  });
};

class ZodBoolean extends ZodType {
  _parse(input) {
    if (this._def.coerce) {
      input.data = Boolean(input.data);
    }
    const parsedType = this._getType(input);
    if (parsedType !== ZodParsedType.boolean) {
      const ctx = this._getOrReturnCtx(input);
      addIssueToContext(ctx, {
        code: ZodIssueCode.invalid_type,
        expected: ZodParsedType.boolean,
        received: ctx.parsedType
      });
      return INVALID;
    }
    return OK(input.data);
  }
}
ZodBoolean.create = (params) => {
  return new ZodBoolean({
    typeName: ZodFirstPartyTypeKind.ZodBoolean,
    coerce: params?.coerce || false,
    ...processCreateParams(params)
  });
};

class ZodDate extends ZodType {
  _parse(input) {
    if (this._def.coerce) {
      input.data = new Date(input.data);
    }
    const parsedType = this._getType(input);
    if (parsedType !== ZodParsedType.date) {
      const ctx = this._getOrReturnCtx(input);
      addIssueToContext(ctx, {
        code: ZodIssueCode.invalid_type,
        expected: ZodParsedType.date,
        received: ctx.parsedType
      });
      return INVALID;
    }
    if (Number.isNaN(input.data.getTime())) {
      const ctx = this._getOrReturnCtx(input);
      addIssueToContext(ctx, {
        code: ZodIssueCode.invalid_date
      });
      return INVALID;
    }
    const status = new ParseStatus;
    let ctx = undefined;
    for (const check of this._def.checks) {
      if (check.kind === "min") {
        if (input.data.getTime() < check.value) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            code: ZodIssueCode.too_small,
            message: check.message,
            inclusive: true,
            exact: false,
            minimum: check.value,
            type: "date"
          });
          status.dirty();
        }
      } else if (check.kind === "max") {
        if (input.data.getTime() > check.value) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            code: ZodIssueCode.too_big,
            message: check.message,
            inclusive: true,
            exact: false,
            maximum: check.value,
            type: "date"
          });
          status.dirty();
        }
      } else {
        util.assertNever(check);
      }
    }
    return {
      status: status.value,
      value: new Date(input.data.getTime())
    };
  }
  _addCheck(check) {
    return new ZodDate({
      ...this._def,
      checks: [...this._def.checks, check]
    });
  }
  min(minDate, message) {
    return this._addCheck({
      kind: "min",
      value: minDate.getTime(),
      message: errorUtil.toString(message)
    });
  }
  max(maxDate, message) {
    return this._addCheck({
      kind: "max",
      value: maxDate.getTime(),
      message: errorUtil.toString(message)
    });
  }
  get minDate() {
    let min = null;
    for (const ch of this._def.checks) {
      if (ch.kind === "min") {
        if (min === null || ch.value > min)
          min = ch.value;
      }
    }
    return min != null ? new Date(min) : null;
  }
  get maxDate() {
    let max = null;
    for (const ch of this._def.checks) {
      if (ch.kind === "max") {
        if (max === null || ch.value < max)
          max = ch.value;
      }
    }
    return max != null ? new Date(max) : null;
  }
}
ZodDate.create = (params) => {
  return new ZodDate({
    checks: [],
    coerce: params?.coerce || false,
    typeName: ZodFirstPartyTypeKind.ZodDate,
    ...processCreateParams(params)
  });
};

class ZodSymbol extends ZodType {
  _parse(input) {
    const parsedType = this._getType(input);
    if (parsedType !== ZodParsedType.symbol) {
      const ctx = this._getOrReturnCtx(input);
      addIssueToContext(ctx, {
        code: ZodIssueCode.invalid_type,
        expected: ZodParsedType.symbol,
        received: ctx.parsedType
      });
      return INVALID;
    }
    return OK(input.data);
  }
}
ZodSymbol.create = (params) => {
  return new ZodSymbol({
    typeName: ZodFirstPartyTypeKind.ZodSymbol,
    ...processCreateParams(params)
  });
};

class ZodUndefined extends ZodType {
  _parse(input) {
    const parsedType = this._getType(input);
    if (parsedType !== ZodParsedType.undefined) {
      const ctx = this._getOrReturnCtx(input);
      addIssueToContext(ctx, {
        code: ZodIssueCode.invalid_type,
        expected: ZodParsedType.undefined,
        received: ctx.parsedType
      });
      return INVALID;
    }
    return OK(input.data);
  }
}
ZodUndefined.create = (params) => {
  return new ZodUndefined({
    typeName: ZodFirstPartyTypeKind.ZodUndefined,
    ...processCreateParams(params)
  });
};

class ZodNull extends ZodType {
  _parse(input) {
    const parsedType = this._getType(input);
    if (parsedType !== ZodParsedType.null) {
      const ctx = this._getOrReturnCtx(input);
      addIssueToContext(ctx, {
        code: ZodIssueCode.invalid_type,
        expected: ZodParsedType.null,
        received: ctx.parsedType
      });
      return INVALID;
    }
    return OK(input.data);
  }
}
ZodNull.create = (params) => {
  return new ZodNull({
    typeName: ZodFirstPartyTypeKind.ZodNull,
    ...processCreateParams(params)
  });
};

class ZodAny extends ZodType {
  constructor() {
    super(...arguments);
    this._any = true;
  }
  _parse(input) {
    return OK(input.data);
  }
}
ZodAny.create = (params) => {
  return new ZodAny({
    typeName: ZodFirstPartyTypeKind.ZodAny,
    ...processCreateParams(params)
  });
};

class ZodUnknown extends ZodType {
  constructor() {
    super(...arguments);
    this._unknown = true;
  }
  _parse(input) {
    return OK(input.data);
  }
}
ZodUnknown.create = (params) => {
  return new ZodUnknown({
    typeName: ZodFirstPartyTypeKind.ZodUnknown,
    ...processCreateParams(params)
  });
};

class ZodNever extends ZodType {
  _parse(input) {
    const ctx = this._getOrReturnCtx(input);
    addIssueToContext(ctx, {
      code: ZodIssueCode.invalid_type,
      expected: ZodParsedType.never,
      received: ctx.parsedType
    });
    return INVALID;
  }
}
ZodNever.create = (params) => {
  return new ZodNever({
    typeName: ZodFirstPartyTypeKind.ZodNever,
    ...processCreateParams(params)
  });
};

class ZodVoid extends ZodType {
  _parse(input) {
    const parsedType = this._getType(input);
    if (parsedType !== ZodParsedType.undefined) {
      const ctx = this._getOrReturnCtx(input);
      addIssueToContext(ctx, {
        code: ZodIssueCode.invalid_type,
        expected: ZodParsedType.void,
        received: ctx.parsedType
      });
      return INVALID;
    }
    return OK(input.data);
  }
}
ZodVoid.create = (params) => {
  return new ZodVoid({
    typeName: ZodFirstPartyTypeKind.ZodVoid,
    ...processCreateParams(params)
  });
};

class ZodArray extends ZodType {
  _parse(input) {
    const { ctx, status } = this._processInputParams(input);
    const def = this._def;
    if (ctx.parsedType !== ZodParsedType.array) {
      addIssueToContext(ctx, {
        code: ZodIssueCode.invalid_type,
        expected: ZodParsedType.array,
        received: ctx.parsedType
      });
      return INVALID;
    }
    if (def.exactLength !== null) {
      const tooBig = ctx.data.length > def.exactLength.value;
      const tooSmall = ctx.data.length < def.exactLength.value;
      if (tooBig || tooSmall) {
        addIssueToContext(ctx, {
          code: tooBig ? ZodIssueCode.too_big : ZodIssueCode.too_small,
          minimum: tooSmall ? def.exactLength.value : undefined,
          maximum: tooBig ? def.exactLength.value : undefined,
          type: "array",
          inclusive: true,
          exact: true,
          message: def.exactLength.message
        });
        status.dirty();
      }
    }
    if (def.minLength !== null) {
      if (ctx.data.length < def.minLength.value) {
        addIssueToContext(ctx, {
          code: ZodIssueCode.too_small,
          minimum: def.minLength.value,
          type: "array",
          inclusive: true,
          exact: false,
          message: def.minLength.message
        });
        status.dirty();
      }
    }
    if (def.maxLength !== null) {
      if (ctx.data.length > def.maxLength.value) {
        addIssueToContext(ctx, {
          code: ZodIssueCode.too_big,
          maximum: def.maxLength.value,
          type: "array",
          inclusive: true,
          exact: false,
          message: def.maxLength.message
        });
        status.dirty();
      }
    }
    if (ctx.common.async) {
      return Promise.all([...ctx.data].map((item, i) => {
        return def.type._parseAsync(new ParseInputLazyPath(ctx, item, ctx.path, i));
      })).then((result) => {
        return ParseStatus.mergeArray(status, result);
      });
    }
    const result = [...ctx.data].map((item, i) => {
      return def.type._parseSync(new ParseInputLazyPath(ctx, item, ctx.path, i));
    });
    return ParseStatus.mergeArray(status, result);
  }
  get element() {
    return this._def.type;
  }
  min(minLength, message) {
    return new ZodArray({
      ...this._def,
      minLength: { value: minLength, message: errorUtil.toString(message) }
    });
  }
  max(maxLength, message) {
    return new ZodArray({
      ...this._def,
      maxLength: { value: maxLength, message: errorUtil.toString(message) }
    });
  }
  length(len, message) {
    return new ZodArray({
      ...this._def,
      exactLength: { value: len, message: errorUtil.toString(message) }
    });
  }
  nonempty(message) {
    return this.min(1, message);
  }
}
ZodArray.create = (schema, params) => {
  return new ZodArray({
    type: schema,
    minLength: null,
    maxLength: null,
    exactLength: null,
    typeName: ZodFirstPartyTypeKind.ZodArray,
    ...processCreateParams(params)
  });
};
function deepPartialify(schema) {
  if (schema instanceof ZodObject) {
    const newShape = {};
    for (const key in schema.shape) {
      const fieldSchema = schema.shape[key];
      newShape[key] = ZodOptional.create(deepPartialify(fieldSchema));
    }
    return new ZodObject({
      ...schema._def,
      shape: () => newShape
    });
  } else if (schema instanceof ZodArray) {
    return new ZodArray({
      ...schema._def,
      type: deepPartialify(schema.element)
    });
  } else if (schema instanceof ZodOptional) {
    return ZodOptional.create(deepPartialify(schema.unwrap()));
  } else if (schema instanceof ZodNullable) {
    return ZodNullable.create(deepPartialify(schema.unwrap()));
  } else if (schema instanceof ZodTuple) {
    return ZodTuple.create(schema.items.map((item) => deepPartialify(item)));
  } else {
    return schema;
  }
}

class ZodObject extends ZodType {
  constructor() {
    super(...arguments);
    this._cached = null;
    this.nonstrict = this.passthrough;
    this.augment = this.extend;
  }
  _getCached() {
    if (this._cached !== null)
      return this._cached;
    const shape = this._def.shape();
    const keys = util.objectKeys(shape);
    this._cached = { shape, keys };
    return this._cached;
  }
  _parse(input) {
    const parsedType = this._getType(input);
    if (parsedType !== ZodParsedType.object) {
      const ctx = this._getOrReturnCtx(input);
      addIssueToContext(ctx, {
        code: ZodIssueCode.invalid_type,
        expected: ZodParsedType.object,
        received: ctx.parsedType
      });
      return INVALID;
    }
    const { status, ctx } = this._processInputParams(input);
    const { shape, keys: shapeKeys } = this._getCached();
    const extraKeys = [];
    if (!(this._def.catchall instanceof ZodNever && this._def.unknownKeys === "strip")) {
      for (const key in ctx.data) {
        if (!shapeKeys.includes(key)) {
          extraKeys.push(key);
        }
      }
    }
    const pairs = [];
    for (const key of shapeKeys) {
      const keyValidator = shape[key];
      const value = ctx.data[key];
      pairs.push({
        key: { status: "valid", value: key },
        value: keyValidator._parse(new ParseInputLazyPath(ctx, value, ctx.path, key)),
        alwaysSet: key in ctx.data
      });
    }
    if (this._def.catchall instanceof ZodNever) {
      const unknownKeys = this._def.unknownKeys;
      if (unknownKeys === "passthrough") {
        for (const key of extraKeys) {
          pairs.push({
            key: { status: "valid", value: key },
            value: { status: "valid", value: ctx.data[key] }
          });
        }
      } else if (unknownKeys === "strict") {
        if (extraKeys.length > 0) {
          addIssueToContext(ctx, {
            code: ZodIssueCode.unrecognized_keys,
            keys: extraKeys
          });
          status.dirty();
        }
      } else if (unknownKeys === "strip") {} else {
        throw new Error(`Internal ZodObject error: invalid unknownKeys value.`);
      }
    } else {
      const catchall = this._def.catchall;
      for (const key of extraKeys) {
        const value = ctx.data[key];
        pairs.push({
          key: { status: "valid", value: key },
          value: catchall._parse(new ParseInputLazyPath(ctx, value, ctx.path, key)),
          alwaysSet: key in ctx.data
        });
      }
    }
    if (ctx.common.async) {
      return Promise.resolve().then(async () => {
        const syncPairs = [];
        for (const pair of pairs) {
          const key = await pair.key;
          const value = await pair.value;
          syncPairs.push({
            key,
            value,
            alwaysSet: pair.alwaysSet
          });
        }
        return syncPairs;
      }).then((syncPairs) => {
        return ParseStatus.mergeObjectSync(status, syncPairs);
      });
    } else {
      return ParseStatus.mergeObjectSync(status, pairs);
    }
  }
  get shape() {
    return this._def.shape();
  }
  strict(message) {
    errorUtil.errToObj;
    return new ZodObject({
      ...this._def,
      unknownKeys: "strict",
      ...message !== undefined ? {
        errorMap: (issue, ctx) => {
          const defaultError = this._def.errorMap?.(issue, ctx).message ?? ctx.defaultError;
          if (issue.code === "unrecognized_keys")
            return {
              message: errorUtil.errToObj(message).message ?? defaultError
            };
          return {
            message: defaultError
          };
        }
      } : {}
    });
  }
  strip() {
    return new ZodObject({
      ...this._def,
      unknownKeys: "strip"
    });
  }
  passthrough() {
    return new ZodObject({
      ...this._def,
      unknownKeys: "passthrough"
    });
  }
  extend(augmentation) {
    return new ZodObject({
      ...this._def,
      shape: () => ({
        ...this._def.shape(),
        ...augmentation
      })
    });
  }
  merge(merging) {
    const merged = new ZodObject({
      unknownKeys: merging._def.unknownKeys,
      catchall: merging._def.catchall,
      shape: () => ({
        ...this._def.shape(),
        ...merging._def.shape()
      }),
      typeName: ZodFirstPartyTypeKind.ZodObject
    });
    return merged;
  }
  setKey(key, schema) {
    return this.augment({ [key]: schema });
  }
  catchall(index) {
    return new ZodObject({
      ...this._def,
      catchall: index
    });
  }
  pick(mask) {
    const shape = {};
    for (const key of util.objectKeys(mask)) {
      if (mask[key] && this.shape[key]) {
        shape[key] = this.shape[key];
      }
    }
    return new ZodObject({
      ...this._def,
      shape: () => shape
    });
  }
  omit(mask) {
    const shape = {};
    for (const key of util.objectKeys(this.shape)) {
      if (!mask[key]) {
        shape[key] = this.shape[key];
      }
    }
    return new ZodObject({
      ...this._def,
      shape: () => shape
    });
  }
  deepPartial() {
    return deepPartialify(this);
  }
  partial(mask) {
    const newShape = {};
    for (const key of util.objectKeys(this.shape)) {
      const fieldSchema = this.shape[key];
      if (mask && !mask[key]) {
        newShape[key] = fieldSchema;
      } else {
        newShape[key] = fieldSchema.optional();
      }
    }
    return new ZodObject({
      ...this._def,
      shape: () => newShape
    });
  }
  required(mask) {
    const newShape = {};
    for (const key of util.objectKeys(this.shape)) {
      if (mask && !mask[key]) {
        newShape[key] = this.shape[key];
      } else {
        const fieldSchema = this.shape[key];
        let newField = fieldSchema;
        while (newField instanceof ZodOptional) {
          newField = newField._def.innerType;
        }
        newShape[key] = newField;
      }
    }
    return new ZodObject({
      ...this._def,
      shape: () => newShape
    });
  }
  keyof() {
    return createZodEnum(util.objectKeys(this.shape));
  }
}
ZodObject.create = (shape, params) => {
  return new ZodObject({
    shape: () => shape,
    unknownKeys: "strip",
    catchall: ZodNever.create(),
    typeName: ZodFirstPartyTypeKind.ZodObject,
    ...processCreateParams(params)
  });
};
ZodObject.strictCreate = (shape, params) => {
  return new ZodObject({
    shape: () => shape,
    unknownKeys: "strict",
    catchall: ZodNever.create(),
    typeName: ZodFirstPartyTypeKind.ZodObject,
    ...processCreateParams(params)
  });
};
ZodObject.lazycreate = (shape, params) => {
  return new ZodObject({
    shape,
    unknownKeys: "strip",
    catchall: ZodNever.create(),
    typeName: ZodFirstPartyTypeKind.ZodObject,
    ...processCreateParams(params)
  });
};

class ZodUnion extends ZodType {
  _parse(input) {
    const { ctx } = this._processInputParams(input);
    const options = this._def.options;
    function handleResults(results) {
      for (const result of results) {
        if (result.result.status === "valid") {
          return result.result;
        }
      }
      for (const result of results) {
        if (result.result.status === "dirty") {
          ctx.common.issues.push(...result.ctx.common.issues);
          return result.result;
        }
      }
      const unionErrors = results.map((result) => new ZodError(result.ctx.common.issues));
      addIssueToContext(ctx, {
        code: ZodIssueCode.invalid_union,
        unionErrors
      });
      return INVALID;
    }
    if (ctx.common.async) {
      return Promise.all(options.map(async (option) => {
        const childCtx = {
          ...ctx,
          common: {
            ...ctx.common,
            issues: []
          },
          parent: null
        };
        return {
          result: await option._parseAsync({
            data: ctx.data,
            path: ctx.path,
            parent: childCtx
          }),
          ctx: childCtx
        };
      })).then(handleResults);
    } else {
      let dirty = undefined;
      const issues = [];
      for (const option of options) {
        const childCtx = {
          ...ctx,
          common: {
            ...ctx.common,
            issues: []
          },
          parent: null
        };
        const result = option._parseSync({
          data: ctx.data,
          path: ctx.path,
          parent: childCtx
        });
        if (result.status === "valid") {
          return result;
        } else if (result.status === "dirty" && !dirty) {
          dirty = { result, ctx: childCtx };
        }
        if (childCtx.common.issues.length) {
          issues.push(childCtx.common.issues);
        }
      }
      if (dirty) {
        ctx.common.issues.push(...dirty.ctx.common.issues);
        return dirty.result;
      }
      const unionErrors = issues.map((issues) => new ZodError(issues));
      addIssueToContext(ctx, {
        code: ZodIssueCode.invalid_union,
        unionErrors
      });
      return INVALID;
    }
  }
  get options() {
    return this._def.options;
  }
}
ZodUnion.create = (types, params) => {
  return new ZodUnion({
    options: types,
    typeName: ZodFirstPartyTypeKind.ZodUnion,
    ...processCreateParams(params)
  });
};
var getDiscriminator = (type) => {
  if (type instanceof ZodLazy) {
    return getDiscriminator(type.schema);
  } else if (type instanceof ZodEffects) {
    return getDiscriminator(type.innerType());
  } else if (type instanceof ZodLiteral) {
    return [type.value];
  } else if (type instanceof ZodEnum) {
    return type.options;
  } else if (type instanceof ZodNativeEnum) {
    return util.objectValues(type.enum);
  } else if (type instanceof ZodDefault) {
    return getDiscriminator(type._def.innerType);
  } else if (type instanceof ZodUndefined) {
    return [undefined];
  } else if (type instanceof ZodNull) {
    return [null];
  } else if (type instanceof ZodOptional) {
    return [undefined, ...getDiscriminator(type.unwrap())];
  } else if (type instanceof ZodNullable) {
    return [null, ...getDiscriminator(type.unwrap())];
  } else if (type instanceof ZodBranded) {
    return getDiscriminator(type.unwrap());
  } else if (type instanceof ZodReadonly) {
    return getDiscriminator(type.unwrap());
  } else if (type instanceof ZodCatch) {
    return getDiscriminator(type._def.innerType);
  } else {
    return [];
  }
};

class ZodDiscriminatedUnion extends ZodType {
  _parse(input) {
    const { ctx } = this._processInputParams(input);
    if (ctx.parsedType !== ZodParsedType.object) {
      addIssueToContext(ctx, {
        code: ZodIssueCode.invalid_type,
        expected: ZodParsedType.object,
        received: ctx.parsedType
      });
      return INVALID;
    }
    const discriminator = this.discriminator;
    const discriminatorValue = ctx.data[discriminator];
    const option = this.optionsMap.get(discriminatorValue);
    if (!option) {
      addIssueToContext(ctx, {
        code: ZodIssueCode.invalid_union_discriminator,
        options: Array.from(this.optionsMap.keys()),
        path: [discriminator]
      });
      return INVALID;
    }
    if (ctx.common.async) {
      return option._parseAsync({
        data: ctx.data,
        path: ctx.path,
        parent: ctx
      });
    } else {
      return option._parseSync({
        data: ctx.data,
        path: ctx.path,
        parent: ctx
      });
    }
  }
  get discriminator() {
    return this._def.discriminator;
  }
  get options() {
    return this._def.options;
  }
  get optionsMap() {
    return this._def.optionsMap;
  }
  static create(discriminator, options, params) {
    const optionsMap = new Map;
    for (const type of options) {
      const discriminatorValues = getDiscriminator(type.shape[discriminator]);
      if (!discriminatorValues.length) {
        throw new Error(`A discriminator value for key \`${discriminator}\` could not be extracted from all schema options`);
      }
      for (const value of discriminatorValues) {
        if (optionsMap.has(value)) {
          throw new Error(`Discriminator property ${String(discriminator)} has duplicate value ${String(value)}`);
        }
        optionsMap.set(value, type);
      }
    }
    return new ZodDiscriminatedUnion({
      typeName: ZodFirstPartyTypeKind.ZodDiscriminatedUnion,
      discriminator,
      options,
      optionsMap,
      ...processCreateParams(params)
    });
  }
}
function mergeValues(a, b) {
  const aType = getParsedType(a);
  const bType = getParsedType(b);
  if (a === b) {
    return { valid: true, data: a };
  } else if (aType === ZodParsedType.object && bType === ZodParsedType.object) {
    const bKeys = util.objectKeys(b);
    const sharedKeys = util.objectKeys(a).filter((key) => bKeys.indexOf(key) !== -1);
    const newObj = { ...a, ...b };
    for (const key of sharedKeys) {
      const sharedValue = mergeValues(a[key], b[key]);
      if (!sharedValue.valid) {
        return { valid: false };
      }
      newObj[key] = sharedValue.data;
    }
    return { valid: true, data: newObj };
  } else if (aType === ZodParsedType.array && bType === ZodParsedType.array) {
    if (a.length !== b.length) {
      return { valid: false };
    }
    const newArray = [];
    for (let index = 0;index < a.length; index++) {
      const itemA = a[index];
      const itemB = b[index];
      const sharedValue = mergeValues(itemA, itemB);
      if (!sharedValue.valid) {
        return { valid: false };
      }
      newArray.push(sharedValue.data);
    }
    return { valid: true, data: newArray };
  } else if (aType === ZodParsedType.date && bType === ZodParsedType.date && +a === +b) {
    return { valid: true, data: a };
  } else {
    return { valid: false };
  }
}

class ZodIntersection extends ZodType {
  _parse(input) {
    const { status, ctx } = this._processInputParams(input);
    const handleParsed = (parsedLeft, parsedRight) => {
      if (isAborted(parsedLeft) || isAborted(parsedRight)) {
        return INVALID;
      }
      const merged = mergeValues(parsedLeft.value, parsedRight.value);
      if (!merged.valid) {
        addIssueToContext(ctx, {
          code: ZodIssueCode.invalid_intersection_types
        });
        return INVALID;
      }
      if (isDirty(parsedLeft) || isDirty(parsedRight)) {
        status.dirty();
      }
      return { status: status.value, value: merged.data };
    };
    if (ctx.common.async) {
      return Promise.all([
        this._def.left._parseAsync({
          data: ctx.data,
          path: ctx.path,
          parent: ctx
        }),
        this._def.right._parseAsync({
          data: ctx.data,
          path: ctx.path,
          parent: ctx
        })
      ]).then(([left, right]) => handleParsed(left, right));
    } else {
      return handleParsed(this._def.left._parseSync({
        data: ctx.data,
        path: ctx.path,
        parent: ctx
      }), this._def.right._parseSync({
        data: ctx.data,
        path: ctx.path,
        parent: ctx
      }));
    }
  }
}
ZodIntersection.create = (left, right, params) => {
  return new ZodIntersection({
    left,
    right,
    typeName: ZodFirstPartyTypeKind.ZodIntersection,
    ...processCreateParams(params)
  });
};

class ZodTuple extends ZodType {
  _parse(input) {
    const { status, ctx } = this._processInputParams(input);
    if (ctx.parsedType !== ZodParsedType.array) {
      addIssueToContext(ctx, {
        code: ZodIssueCode.invalid_type,
        expected: ZodParsedType.array,
        received: ctx.parsedType
      });
      return INVALID;
    }
    if (ctx.data.length < this._def.items.length) {
      addIssueToContext(ctx, {
        code: ZodIssueCode.too_small,
        minimum: this._def.items.length,
        inclusive: true,
        exact: false,
        type: "array"
      });
      return INVALID;
    }
    const rest = this._def.rest;
    if (!rest && ctx.data.length > this._def.items.length) {
      addIssueToContext(ctx, {
        code: ZodIssueCode.too_big,
        maximum: this._def.items.length,
        inclusive: true,
        exact: false,
        type: "array"
      });
      status.dirty();
    }
    const items = [...ctx.data].map((item, itemIndex) => {
      const schema = this._def.items[itemIndex] || this._def.rest;
      if (!schema)
        return null;
      return schema._parse(new ParseInputLazyPath(ctx, item, ctx.path, itemIndex));
    }).filter((x) => !!x);
    if (ctx.common.async) {
      return Promise.all(items).then((results) => {
        return ParseStatus.mergeArray(status, results);
      });
    } else {
      return ParseStatus.mergeArray(status, items);
    }
  }
  get items() {
    return this._def.items;
  }
  rest(rest) {
    return new ZodTuple({
      ...this._def,
      rest
    });
  }
}
ZodTuple.create = (schemas, params) => {
  if (!Array.isArray(schemas)) {
    throw new Error("You must pass an array of schemas to z.tuple([ ... ])");
  }
  return new ZodTuple({
    items: schemas,
    typeName: ZodFirstPartyTypeKind.ZodTuple,
    rest: null,
    ...processCreateParams(params)
  });
};

class ZodRecord extends ZodType {
  get keySchema() {
    return this._def.keyType;
  }
  get valueSchema() {
    return this._def.valueType;
  }
  _parse(input) {
    const { status, ctx } = this._processInputParams(input);
    if (ctx.parsedType !== ZodParsedType.object) {
      addIssueToContext(ctx, {
        code: ZodIssueCode.invalid_type,
        expected: ZodParsedType.object,
        received: ctx.parsedType
      });
      return INVALID;
    }
    const pairs = [];
    const keyType = this._def.keyType;
    const valueType = this._def.valueType;
    for (const key in ctx.data) {
      pairs.push({
        key: keyType._parse(new ParseInputLazyPath(ctx, key, ctx.path, key)),
        value: valueType._parse(new ParseInputLazyPath(ctx, ctx.data[key], ctx.path, key)),
        alwaysSet: key in ctx.data
      });
    }
    if (ctx.common.async) {
      return ParseStatus.mergeObjectAsync(status, pairs);
    } else {
      return ParseStatus.mergeObjectSync(status, pairs);
    }
  }
  get element() {
    return this._def.valueType;
  }
  static create(first, second, third) {
    if (second instanceof ZodType) {
      return new ZodRecord({
        keyType: first,
        valueType: second,
        typeName: ZodFirstPartyTypeKind.ZodRecord,
        ...processCreateParams(third)
      });
    }
    return new ZodRecord({
      keyType: ZodString.create(),
      valueType: first,
      typeName: ZodFirstPartyTypeKind.ZodRecord,
      ...processCreateParams(second)
    });
  }
}

class ZodMap extends ZodType {
  get keySchema() {
    return this._def.keyType;
  }
  get valueSchema() {
    return this._def.valueType;
  }
  _parse(input) {
    const { status, ctx } = this._processInputParams(input);
    if (ctx.parsedType !== ZodParsedType.map) {
      addIssueToContext(ctx, {
        code: ZodIssueCode.invalid_type,
        expected: ZodParsedType.map,
        received: ctx.parsedType
      });
      return INVALID;
    }
    const keyType = this._def.keyType;
    const valueType = this._def.valueType;
    const pairs = [...ctx.data.entries()].map(([key, value], index) => {
      return {
        key: keyType._parse(new ParseInputLazyPath(ctx, key, ctx.path, [index, "key"])),
        value: valueType._parse(new ParseInputLazyPath(ctx, value, ctx.path, [index, "value"]))
      };
    });
    if (ctx.common.async) {
      const finalMap = new Map;
      return Promise.resolve().then(async () => {
        for (const pair of pairs) {
          const key = await pair.key;
          const value = await pair.value;
          if (key.status === "aborted" || value.status === "aborted") {
            return INVALID;
          }
          if (key.status === "dirty" || value.status === "dirty") {
            status.dirty();
          }
          finalMap.set(key.value, value.value);
        }
        return { status: status.value, value: finalMap };
      });
    } else {
      const finalMap = new Map;
      for (const pair of pairs) {
        const key = pair.key;
        const value = pair.value;
        if (key.status === "aborted" || value.status === "aborted") {
          return INVALID;
        }
        if (key.status === "dirty" || value.status === "dirty") {
          status.dirty();
        }
        finalMap.set(key.value, value.value);
      }
      return { status: status.value, value: finalMap };
    }
  }
}
ZodMap.create = (keyType, valueType, params) => {
  return new ZodMap({
    valueType,
    keyType,
    typeName: ZodFirstPartyTypeKind.ZodMap,
    ...processCreateParams(params)
  });
};

class ZodSet extends ZodType {
  _parse(input) {
    const { status, ctx } = this._processInputParams(input);
    if (ctx.parsedType !== ZodParsedType.set) {
      addIssueToContext(ctx, {
        code: ZodIssueCode.invalid_type,
        expected: ZodParsedType.set,
        received: ctx.parsedType
      });
      return INVALID;
    }
    const def = this._def;
    if (def.minSize !== null) {
      if (ctx.data.size < def.minSize.value) {
        addIssueToContext(ctx, {
          code: ZodIssueCode.too_small,
          minimum: def.minSize.value,
          type: "set",
          inclusive: true,
          exact: false,
          message: def.minSize.message
        });
        status.dirty();
      }
    }
    if (def.maxSize !== null) {
      if (ctx.data.size > def.maxSize.value) {
        addIssueToContext(ctx, {
          code: ZodIssueCode.too_big,
          maximum: def.maxSize.value,
          type: "set",
          inclusive: true,
          exact: false,
          message: def.maxSize.message
        });
        status.dirty();
      }
    }
    const valueType = this._def.valueType;
    function finalizeSet(elements) {
      const parsedSet = new Set;
      for (const element of elements) {
        if (element.status === "aborted")
          return INVALID;
        if (element.status === "dirty")
          status.dirty();
        parsedSet.add(element.value);
      }
      return { status: status.value, value: parsedSet };
    }
    const elements = [...ctx.data.values()].map((item, i) => valueType._parse(new ParseInputLazyPath(ctx, item, ctx.path, i)));
    if (ctx.common.async) {
      return Promise.all(elements).then((elements) => finalizeSet(elements));
    } else {
      return finalizeSet(elements);
    }
  }
  min(minSize, message) {
    return new ZodSet({
      ...this._def,
      minSize: { value: minSize, message: errorUtil.toString(message) }
    });
  }
  max(maxSize, message) {
    return new ZodSet({
      ...this._def,
      maxSize: { value: maxSize, message: errorUtil.toString(message) }
    });
  }
  size(size, message) {
    return this.min(size, message).max(size, message);
  }
  nonempty(message) {
    return this.min(1, message);
  }
}
ZodSet.create = (valueType, params) => {
  return new ZodSet({
    valueType,
    minSize: null,
    maxSize: null,
    typeName: ZodFirstPartyTypeKind.ZodSet,
    ...processCreateParams(params)
  });
};

class ZodFunction extends ZodType {
  constructor() {
    super(...arguments);
    this.validate = this.implement;
  }
  _parse(input) {
    const { ctx } = this._processInputParams(input);
    if (ctx.parsedType !== ZodParsedType.function) {
      addIssueToContext(ctx, {
        code: ZodIssueCode.invalid_type,
        expected: ZodParsedType.function,
        received: ctx.parsedType
      });
      return INVALID;
    }
    function makeArgsIssue(args, error) {
      return makeIssue({
        data: args,
        path: ctx.path,
        errorMaps: [ctx.common.contextualErrorMap, ctx.schemaErrorMap, getErrorMap(), en_default].filter((x) => !!x),
        issueData: {
          code: ZodIssueCode.invalid_arguments,
          argumentsError: error
        }
      });
    }
    function makeReturnsIssue(returns, error) {
      return makeIssue({
        data: returns,
        path: ctx.path,
        errorMaps: [ctx.common.contextualErrorMap, ctx.schemaErrorMap, getErrorMap(), en_default].filter((x) => !!x),
        issueData: {
          code: ZodIssueCode.invalid_return_type,
          returnTypeError: error
        }
      });
    }
    const params = { errorMap: ctx.common.contextualErrorMap };
    const fn = ctx.data;
    if (this._def.returns instanceof ZodPromise) {
      const me = this;
      return OK(async function(...args) {
        const error = new ZodError([]);
        const parsedArgs = await me._def.args.parseAsync(args, params).catch((e) => {
          error.addIssue(makeArgsIssue(args, e));
          throw error;
        });
        const result = await Reflect.apply(fn, this, parsedArgs);
        const parsedReturns = await me._def.returns._def.type.parseAsync(result, params).catch((e) => {
          error.addIssue(makeReturnsIssue(result, e));
          throw error;
        });
        return parsedReturns;
      });
    } else {
      const me = this;
      return OK(function(...args) {
        const parsedArgs = me._def.args.safeParse(args, params);
        if (!parsedArgs.success) {
          throw new ZodError([makeArgsIssue(args, parsedArgs.error)]);
        }
        const result = Reflect.apply(fn, this, parsedArgs.data);
        const parsedReturns = me._def.returns.safeParse(result, params);
        if (!parsedReturns.success) {
          throw new ZodError([makeReturnsIssue(result, parsedReturns.error)]);
        }
        return parsedReturns.data;
      });
    }
  }
  parameters() {
    return this._def.args;
  }
  returnType() {
    return this._def.returns;
  }
  args(...items) {
    return new ZodFunction({
      ...this._def,
      args: ZodTuple.create(items).rest(ZodUnknown.create())
    });
  }
  returns(returnType) {
    return new ZodFunction({
      ...this._def,
      returns: returnType
    });
  }
  implement(func) {
    const validatedFunc = this.parse(func);
    return validatedFunc;
  }
  strictImplement(func) {
    const validatedFunc = this.parse(func);
    return validatedFunc;
  }
  static create(args, returns, params) {
    return new ZodFunction({
      args: args ? args : ZodTuple.create([]).rest(ZodUnknown.create()),
      returns: returns || ZodUnknown.create(),
      typeName: ZodFirstPartyTypeKind.ZodFunction,
      ...processCreateParams(params)
    });
  }
}

class ZodLazy extends ZodType {
  get schema() {
    return this._def.getter();
  }
  _parse(input) {
    const { ctx } = this._processInputParams(input);
    const lazySchema = this._def.getter();
    return lazySchema._parse({ data: ctx.data, path: ctx.path, parent: ctx });
  }
}
ZodLazy.create = (getter, params) => {
  return new ZodLazy({
    getter,
    typeName: ZodFirstPartyTypeKind.ZodLazy,
    ...processCreateParams(params)
  });
};

class ZodLiteral extends ZodType {
  _parse(input) {
    if (input.data !== this._def.value) {
      const ctx = this._getOrReturnCtx(input);
      addIssueToContext(ctx, {
        received: ctx.data,
        code: ZodIssueCode.invalid_literal,
        expected: this._def.value
      });
      return INVALID;
    }
    return { status: "valid", value: input.data };
  }
  get value() {
    return this._def.value;
  }
}
ZodLiteral.create = (value, params) => {
  return new ZodLiteral({
    value,
    typeName: ZodFirstPartyTypeKind.ZodLiteral,
    ...processCreateParams(params)
  });
};
function createZodEnum(values, params) {
  return new ZodEnum({
    values,
    typeName: ZodFirstPartyTypeKind.ZodEnum,
    ...processCreateParams(params)
  });
}

class ZodEnum extends ZodType {
  _parse(input) {
    if (typeof input.data !== "string") {
      const ctx = this._getOrReturnCtx(input);
      const expectedValues = this._def.values;
      addIssueToContext(ctx, {
        expected: util.joinValues(expectedValues),
        received: ctx.parsedType,
        code: ZodIssueCode.invalid_type
      });
      return INVALID;
    }
    if (!this._cache) {
      this._cache = new Set(this._def.values);
    }
    if (!this._cache.has(input.data)) {
      const ctx = this._getOrReturnCtx(input);
      const expectedValues = this._def.values;
      addIssueToContext(ctx, {
        received: ctx.data,
        code: ZodIssueCode.invalid_enum_value,
        options: expectedValues
      });
      return INVALID;
    }
    return OK(input.data);
  }
  get options() {
    return this._def.values;
  }
  get enum() {
    const enumValues = {};
    for (const val of this._def.values) {
      enumValues[val] = val;
    }
    return enumValues;
  }
  get Values() {
    const enumValues = {};
    for (const val of this._def.values) {
      enumValues[val] = val;
    }
    return enumValues;
  }
  get Enum() {
    const enumValues = {};
    for (const val of this._def.values) {
      enumValues[val] = val;
    }
    return enumValues;
  }
  extract(values, newDef = this._def) {
    return ZodEnum.create(values, {
      ...this._def,
      ...newDef
    });
  }
  exclude(values, newDef = this._def) {
    return ZodEnum.create(this.options.filter((opt) => !values.includes(opt)), {
      ...this._def,
      ...newDef
    });
  }
}
ZodEnum.create = createZodEnum;

class ZodNativeEnum extends ZodType {
  _parse(input) {
    const nativeEnumValues = util.getValidEnumValues(this._def.values);
    const ctx = this._getOrReturnCtx(input);
    if (ctx.parsedType !== ZodParsedType.string && ctx.parsedType !== ZodParsedType.number) {
      const expectedValues = util.objectValues(nativeEnumValues);
      addIssueToContext(ctx, {
        expected: util.joinValues(expectedValues),
        received: ctx.parsedType,
        code: ZodIssueCode.invalid_type
      });
      return INVALID;
    }
    if (!this._cache) {
      this._cache = new Set(util.getValidEnumValues(this._def.values));
    }
    if (!this._cache.has(input.data)) {
      const expectedValues = util.objectValues(nativeEnumValues);
      addIssueToContext(ctx, {
        received: ctx.data,
        code: ZodIssueCode.invalid_enum_value,
        options: expectedValues
      });
      return INVALID;
    }
    return OK(input.data);
  }
  get enum() {
    return this._def.values;
  }
}
ZodNativeEnum.create = (values, params) => {
  return new ZodNativeEnum({
    values,
    typeName: ZodFirstPartyTypeKind.ZodNativeEnum,
    ...processCreateParams(params)
  });
};

class ZodPromise extends ZodType {
  unwrap() {
    return this._def.type;
  }
  _parse(input) {
    const { ctx } = this._processInputParams(input);
    if (ctx.parsedType !== ZodParsedType.promise && ctx.common.async === false) {
      addIssueToContext(ctx, {
        code: ZodIssueCode.invalid_type,
        expected: ZodParsedType.promise,
        received: ctx.parsedType
      });
      return INVALID;
    }
    const promisified = ctx.parsedType === ZodParsedType.promise ? ctx.data : Promise.resolve(ctx.data);
    return OK(promisified.then((data) => {
      return this._def.type.parseAsync(data, {
        path: ctx.path,
        errorMap: ctx.common.contextualErrorMap
      });
    }));
  }
}
ZodPromise.create = (schema, params) => {
  return new ZodPromise({
    type: schema,
    typeName: ZodFirstPartyTypeKind.ZodPromise,
    ...processCreateParams(params)
  });
};

class ZodEffects extends ZodType {
  innerType() {
    return this._def.schema;
  }
  sourceType() {
    return this._def.schema._def.typeName === ZodFirstPartyTypeKind.ZodEffects ? this._def.schema.sourceType() : this._def.schema;
  }
  _parse(input) {
    const { status, ctx } = this._processInputParams(input);
    const effect = this._def.effect || null;
    const checkCtx = {
      addIssue: (arg) => {
        addIssueToContext(ctx, arg);
        if (arg.fatal) {
          status.abort();
        } else {
          status.dirty();
        }
      },
      get path() {
        return ctx.path;
      }
    };
    checkCtx.addIssue = checkCtx.addIssue.bind(checkCtx);
    if (effect.type === "preprocess") {
      const processed = effect.transform(ctx.data, checkCtx);
      if (ctx.common.async) {
        return Promise.resolve(processed).then(async (processed) => {
          if (status.value === "aborted")
            return INVALID;
          const result = await this._def.schema._parseAsync({
            data: processed,
            path: ctx.path,
            parent: ctx
          });
          if (result.status === "aborted")
            return INVALID;
          if (result.status === "dirty")
            return DIRTY(result.value);
          if (status.value === "dirty")
            return DIRTY(result.value);
          return result;
        });
      } else {
        if (status.value === "aborted")
          return INVALID;
        const result = this._def.schema._parseSync({
          data: processed,
          path: ctx.path,
          parent: ctx
        });
        if (result.status === "aborted")
          return INVALID;
        if (result.status === "dirty")
          return DIRTY(result.value);
        if (status.value === "dirty")
          return DIRTY(result.value);
        return result;
      }
    }
    if (effect.type === "refinement") {
      const executeRefinement = (acc) => {
        const result = effect.refinement(acc, checkCtx);
        if (ctx.common.async) {
          return Promise.resolve(result);
        }
        if (result instanceof Promise) {
          throw new Error("Async refinement encountered during synchronous parse operation. Use .parseAsync instead.");
        }
        return acc;
      };
      if (ctx.common.async === false) {
        const inner = this._def.schema._parseSync({
          data: ctx.data,
          path: ctx.path,
          parent: ctx
        });
        if (inner.status === "aborted")
          return INVALID;
        if (inner.status === "dirty")
          status.dirty();
        executeRefinement(inner.value);
        return { status: status.value, value: inner.value };
      } else {
        return this._def.schema._parseAsync({ data: ctx.data, path: ctx.path, parent: ctx }).then((inner) => {
          if (inner.status === "aborted")
            return INVALID;
          if (inner.status === "dirty")
            status.dirty();
          return executeRefinement(inner.value).then(() => {
            return { status: status.value, value: inner.value };
          });
        });
      }
    }
    if (effect.type === "transform") {
      if (ctx.common.async === false) {
        const base = this._def.schema._parseSync({
          data: ctx.data,
          path: ctx.path,
          parent: ctx
        });
        if (!isValid(base))
          return INVALID;
        const result = effect.transform(base.value, checkCtx);
        if (result instanceof Promise) {
          throw new Error(`Asynchronous transform encountered during synchronous parse operation. Use .parseAsync instead.`);
        }
        return { status: status.value, value: result };
      } else {
        return this._def.schema._parseAsync({ data: ctx.data, path: ctx.path, parent: ctx }).then((base) => {
          if (!isValid(base))
            return INVALID;
          return Promise.resolve(effect.transform(base.value, checkCtx)).then((result) => ({
            status: status.value,
            value: result
          }));
        });
      }
    }
    util.assertNever(effect);
  }
}
ZodEffects.create = (schema, effect, params) => {
  return new ZodEffects({
    schema,
    typeName: ZodFirstPartyTypeKind.ZodEffects,
    effect,
    ...processCreateParams(params)
  });
};
ZodEffects.createWithPreprocess = (preprocess, schema, params) => {
  return new ZodEffects({
    schema,
    effect: { type: "preprocess", transform: preprocess },
    typeName: ZodFirstPartyTypeKind.ZodEffects,
    ...processCreateParams(params)
  });
};
class ZodOptional extends ZodType {
  _parse(input) {
    const parsedType = this._getType(input);
    if (parsedType === ZodParsedType.undefined) {
      return OK(undefined);
    }
    return this._def.innerType._parse(input);
  }
  unwrap() {
    return this._def.innerType;
  }
}
ZodOptional.create = (type, params) => {
  return new ZodOptional({
    innerType: type,
    typeName: ZodFirstPartyTypeKind.ZodOptional,
    ...processCreateParams(params)
  });
};

class ZodNullable extends ZodType {
  _parse(input) {
    const parsedType = this._getType(input);
    if (parsedType === ZodParsedType.null) {
      return OK(null);
    }
    return this._def.innerType._parse(input);
  }
  unwrap() {
    return this._def.innerType;
  }
}
ZodNullable.create = (type, params) => {
  return new ZodNullable({
    innerType: type,
    typeName: ZodFirstPartyTypeKind.ZodNullable,
    ...processCreateParams(params)
  });
};

class ZodDefault extends ZodType {
  _parse(input) {
    const { ctx } = this._processInputParams(input);
    let data = ctx.data;
    if (ctx.parsedType === ZodParsedType.undefined) {
      data = this._def.defaultValue();
    }
    return this._def.innerType._parse({
      data,
      path: ctx.path,
      parent: ctx
    });
  }
  removeDefault() {
    return this._def.innerType;
  }
}
ZodDefault.create = (type, params) => {
  return new ZodDefault({
    innerType: type,
    typeName: ZodFirstPartyTypeKind.ZodDefault,
    defaultValue: typeof params.default === "function" ? params.default : () => params.default,
    ...processCreateParams(params)
  });
};

class ZodCatch extends ZodType {
  _parse(input) {
    const { ctx } = this._processInputParams(input);
    const newCtx = {
      ...ctx,
      common: {
        ...ctx.common,
        issues: []
      }
    };
    const result = this._def.innerType._parse({
      data: newCtx.data,
      path: newCtx.path,
      parent: {
        ...newCtx
      }
    });
    if (isAsync(result)) {
      return result.then((result) => {
        return {
          status: "valid",
          value: result.status === "valid" ? result.value : this._def.catchValue({
            get error() {
              return new ZodError(newCtx.common.issues);
            },
            input: newCtx.data
          })
        };
      });
    } else {
      return {
        status: "valid",
        value: result.status === "valid" ? result.value : this._def.catchValue({
          get error() {
            return new ZodError(newCtx.common.issues);
          },
          input: newCtx.data
        })
      };
    }
  }
  removeCatch() {
    return this._def.innerType;
  }
}
ZodCatch.create = (type, params) => {
  return new ZodCatch({
    innerType: type,
    typeName: ZodFirstPartyTypeKind.ZodCatch,
    catchValue: typeof params.catch === "function" ? params.catch : () => params.catch,
    ...processCreateParams(params)
  });
};

class ZodNaN extends ZodType {
  _parse(input) {
    const parsedType = this._getType(input);
    if (parsedType !== ZodParsedType.nan) {
      const ctx = this._getOrReturnCtx(input);
      addIssueToContext(ctx, {
        code: ZodIssueCode.invalid_type,
        expected: ZodParsedType.nan,
        received: ctx.parsedType
      });
      return INVALID;
    }
    return { status: "valid", value: input.data };
  }
}
ZodNaN.create = (params) => {
  return new ZodNaN({
    typeName: ZodFirstPartyTypeKind.ZodNaN,
    ...processCreateParams(params)
  });
};
var BRAND = Symbol("zod_brand");

class ZodBranded extends ZodType {
  _parse(input) {
    const { ctx } = this._processInputParams(input);
    const data = ctx.data;
    return this._def.type._parse({
      data,
      path: ctx.path,
      parent: ctx
    });
  }
  unwrap() {
    return this._def.type;
  }
}

class ZodPipeline extends ZodType {
  _parse(input) {
    const { status, ctx } = this._processInputParams(input);
    if (ctx.common.async) {
      const handleAsync = async () => {
        const inResult = await this._def.in._parseAsync({
          data: ctx.data,
          path: ctx.path,
          parent: ctx
        });
        if (inResult.status === "aborted")
          return INVALID;
        if (inResult.status === "dirty") {
          status.dirty();
          return DIRTY(inResult.value);
        } else {
          return this._def.out._parseAsync({
            data: inResult.value,
            path: ctx.path,
            parent: ctx
          });
        }
      };
      return handleAsync();
    } else {
      const inResult = this._def.in._parseSync({
        data: ctx.data,
        path: ctx.path,
        parent: ctx
      });
      if (inResult.status === "aborted")
        return INVALID;
      if (inResult.status === "dirty") {
        status.dirty();
        return {
          status: "dirty",
          value: inResult.value
        };
      } else {
        return this._def.out._parseSync({
          data: inResult.value,
          path: ctx.path,
          parent: ctx
        });
      }
    }
  }
  static create(a, b) {
    return new ZodPipeline({
      in: a,
      out: b,
      typeName: ZodFirstPartyTypeKind.ZodPipeline
    });
  }
}

class ZodReadonly extends ZodType {
  _parse(input) {
    const result = this._def.innerType._parse(input);
    const freeze = (data) => {
      if (isValid(data)) {
        data.value = Object.freeze(data.value);
      }
      return data;
    };
    return isAsync(result) ? result.then((data) => freeze(data)) : freeze(result);
  }
  unwrap() {
    return this._def.innerType;
  }
}
ZodReadonly.create = (type, params) => {
  return new ZodReadonly({
    innerType: type,
    typeName: ZodFirstPartyTypeKind.ZodReadonly,
    ...processCreateParams(params)
  });
};
var late = {
  object: ZodObject.lazycreate
};
var ZodFirstPartyTypeKind;
(function(ZodFirstPartyTypeKind) {
  ZodFirstPartyTypeKind["ZodString"] = "ZodString";
  ZodFirstPartyTypeKind["ZodNumber"] = "ZodNumber";
  ZodFirstPartyTypeKind["ZodNaN"] = "ZodNaN";
  ZodFirstPartyTypeKind["ZodBigInt"] = "ZodBigInt";
  ZodFirstPartyTypeKind["ZodBoolean"] = "ZodBoolean";
  ZodFirstPartyTypeKind["ZodDate"] = "ZodDate";
  ZodFirstPartyTypeKind["ZodSymbol"] = "ZodSymbol";
  ZodFirstPartyTypeKind["ZodUndefined"] = "ZodUndefined";
  ZodFirstPartyTypeKind["ZodNull"] = "ZodNull";
  ZodFirstPartyTypeKind["ZodAny"] = "ZodAny";
  ZodFirstPartyTypeKind["ZodUnknown"] = "ZodUnknown";
  ZodFirstPartyTypeKind["ZodNever"] = "ZodNever";
  ZodFirstPartyTypeKind["ZodVoid"] = "ZodVoid";
  ZodFirstPartyTypeKind["ZodArray"] = "ZodArray";
  ZodFirstPartyTypeKind["ZodObject"] = "ZodObject";
  ZodFirstPartyTypeKind["ZodUnion"] = "ZodUnion";
  ZodFirstPartyTypeKind["ZodDiscriminatedUnion"] = "ZodDiscriminatedUnion";
  ZodFirstPartyTypeKind["ZodIntersection"] = "ZodIntersection";
  ZodFirstPartyTypeKind["ZodTuple"] = "ZodTuple";
  ZodFirstPartyTypeKind["ZodRecord"] = "ZodRecord";
  ZodFirstPartyTypeKind["ZodMap"] = "ZodMap";
  ZodFirstPartyTypeKind["ZodSet"] = "ZodSet";
  ZodFirstPartyTypeKind["ZodFunction"] = "ZodFunction";
  ZodFirstPartyTypeKind["ZodLazy"] = "ZodLazy";
  ZodFirstPartyTypeKind["ZodLiteral"] = "ZodLiteral";
  ZodFirstPartyTypeKind["ZodEnum"] = "ZodEnum";
  ZodFirstPartyTypeKind["ZodEffects"] = "ZodEffects";
  ZodFirstPartyTypeKind["ZodNativeEnum"] = "ZodNativeEnum";
  ZodFirstPartyTypeKind["ZodOptional"] = "ZodOptional";
  ZodFirstPartyTypeKind["ZodNullable"] = "ZodNullable";
  ZodFirstPartyTypeKind["ZodDefault"] = "ZodDefault";
  ZodFirstPartyTypeKind["ZodCatch"] = "ZodCatch";
  ZodFirstPartyTypeKind["ZodPromise"] = "ZodPromise";
  ZodFirstPartyTypeKind["ZodBranded"] = "ZodBranded";
  ZodFirstPartyTypeKind["ZodPipeline"] = "ZodPipeline";
  ZodFirstPartyTypeKind["ZodReadonly"] = "ZodReadonly";
})(ZodFirstPartyTypeKind || (ZodFirstPartyTypeKind = {}));
var stringType = ZodString.create;
var numberType = ZodNumber.create;
var nanType = ZodNaN.create;
var bigIntType = ZodBigInt.create;
var booleanType = ZodBoolean.create;
var dateType = ZodDate.create;
var symbolType = ZodSymbol.create;
var undefinedType = ZodUndefined.create;
var nullType = ZodNull.create;
var anyType = ZodAny.create;
var unknownType = ZodUnknown.create;
var neverType = ZodNever.create;
var voidType = ZodVoid.create;
var arrayType = ZodArray.create;
var objectType = ZodObject.create;
var strictObjectType = ZodObject.strictCreate;
var unionType = ZodUnion.create;
var discriminatedUnionType = ZodDiscriminatedUnion.create;
var intersectionType = ZodIntersection.create;
var tupleType = ZodTuple.create;
var recordType = ZodRecord.create;
var mapType = ZodMap.create;
var setType = ZodSet.create;
var functionType = ZodFunction.create;
var lazyType = ZodLazy.create;
var literalType = ZodLiteral.create;
var enumType = ZodEnum.create;
var nativeEnumType = ZodNativeEnum.create;
var promiseType = ZodPromise.create;
var effectsType = ZodEffects.create;
var optionalType = ZodOptional.create;
var nullableType = ZodNullable.create;
var preprocessType = ZodEffects.createWithPreprocess;
var pipelineType = ZodPipeline.create;
// packages/shared/src/codeSecurityTypes.ts
var COVERAGE_REASONS = [
  "none",
  "too_many_commits",
  "lockfile_too_large",
  "too_many_lockfiles",
  "too_many_findings",
  "output_too_large",
  "tool_timeout",
  "parse_error",
  "fetch_failed",
  "upstream_error",
  "osv_unreachable",
  "scan_job_failed",
  "base_unavailable"
];
var DEFAULT_POLICY = Object.freeze({ mode: "block", secretsBlock: true, vulnBlockSeverity: "high" });

// packages/github/src/scan/report.ts
var REPORT_VERSION = 1;
var LIMITS = {
  maxCommits: 250,
  maxLockfileBytes: 20 * 1024 * 1024,
  maxLockfiles: 200,
  maxFindingsPerTool: 500,
  maxBodyBytes: 2 * 1024 * 1024,
  maxPathBytes: 1024,
  maxInventory: 20000,
  maxChunkChars: 90000,
  maxChunks: 4,
  maxDecompressedBytes: 4 * 1024 * 1024
};
var bytesAtMost = (n) => (s) => Buffer.byteLength(s, "utf8") <= n;
var Sha = stringType().regex(/^[0-9a-f]{40}$/);
var Digest = stringType().regex(/^[0-9a-f]{64}$/);
var RepoPath = stringType().min(1).refine(bytesAtMost(LIMITS.maxPathBytes), { message: `path is longer than ${LIMITS.maxPathBytes} bytes` }).refine((p) => !p.startsWith("/") && !p.split("/").some((seg) => seg === "" || seg === "..") && !/[\x00-\x1f\x7f]/.test(p), { message: 'path must be relative, without empty or ".." segments or control characters' });
var AdvisoryId = stringType().regex(/^(GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}|CVE-\d{4}-\d{4,}|[A-Z][A-Z0-9]{1,15}-[A-Za-z0-9.-]{1,64})$/);
var Ecosystem = stringType().regex(/^[A-Za-z][A-Za-z0-9.+ -]{0,39}$/);
var PackageName = stringType().min(1).max(214).regex(/^[^\s\x00-\x1f\x7f]+$/);
var Version = stringType().min(1).max(128).regex(/^[^\s\x00-\x1f\x7f]+$/);
var ToolVersion = stringType().regex(/^v?\d+\.\d+\.\d+(-[A-Za-z0-9.]+)?$/);
var BranchRef = stringType().max(256).regex(/^refs\/heads\/[^\s\x00-\x1f\x7f]+$/);
var PrMergeRef = stringType().regex(/^refs\/pull\/([1-9]\d{0,9})\/merge$/);
var RuleId = stringType().regex(/^[a-z0-9][a-z0-9-]{0,63}$/);
var CoverageZ = enumType(["complete", "incomplete_input", "failed"]);
var CoverageReasonZ = enumType(COVERAGE_REASONS);
var SecretFinding = objectType({
  ruleId: RuleId,
  path: RepoPath,
  startLine: numberType().int().positive(),
  endLine: numberType().int().positive(),
  commitSha: Sha,
  valueDigest: Digest,
  inHeadTree: booleanType()
}).strict().refine((f) => f.endLine >= f.startLine, { message: "endLine is before startLine", path: ["endLine"] });
var VulnFinding = objectType({
  advisoryIds: arrayType(AdvisoryId).min(1).max(16),
  ecosystem: Ecosystem,
  package: PackageName,
  version: Version,
  manifestPath: RepoPath,
  introduced: booleanType()
}).strict();
var ManifestCoverage = objectType({
  side: enumType(["head", "base"]),
  path: RepoPath,
  status: enumType(["scanned", "unsupported", "parse_error", "too_large"])
}).strict();
var InventoryRow = objectType({
  ecosystem: Ecosystem,
  package: PackageName,
  version: Version,
  manifestPath: RepoPath
}).strict();
var ScanOutput = objectType({
  version: literalType(REPORT_VERSION),
  scanResult: literalType("success"),
  commits: arrayType(Sha).max(LIMITS.maxCommits),
  secrets: objectType({
    coverage: CoverageZ,
    reason: CoverageReasonZ,
    tool: objectType({ name: literalType("gitleaks"), version: ToolVersion }).strict(),
    findings: arrayType(SecretFinding).max(LIMITS.maxFindingsPerTool)
  }).strict(),
  vulnerabilities: objectType({
    coverage: objectType({ head: CoverageZ, base: enumType(["complete", "incomplete", "none"]) }).strict(),
    reason: objectType({ head: CoverageReasonZ, base: CoverageReasonZ }).strict(),
    manifests: arrayType(ManifestCoverage).max(2 * LIMITS.maxLockfiles),
    tool: objectType({ name: literalType("osv-scanner"), version: ToolVersion }).strict(),
    queriedAt: stringType().datetime(),
    findings: arrayType(VulnFinding).max(LIMITS.maxFindingsPerTool)
  }).strict(),
  inventory: unionType([arrayType(InventoryRow).max(LIMITS.maxInventory), literalType("omitted")]).optional(),
  treeScanned: booleanType()
}).strict().refine((o) => o.secrets.coverage === "complete" === (o.secrets.reason === "none"), { message: "secrets: coverage is complete exactly when the reason is none", path: ["secrets", "reason"] }).refine((o) => o.vulnerabilities.coverage.head === "complete" === (o.vulnerabilities.reason.head === "none"), { message: "vulnerabilities: head coverage is complete exactly when the head reason is none", path: ["vulnerabilities", "reason", "head"] }).refine((o) => o.vulnerabilities.coverage.base === "incomplete" === (o.vulnerabilities.reason.base !== "none"), { message: "vulnerabilities: base coverage is incomplete exactly when the base reason is not none", path: ["vulnerabilities", "reason", "base"] });
var FailureEnvelope = objectType({
  version: literalType(REPORT_VERSION),
  scanResult: enumType(["failure", "cancelled", "timed_out", "skipped"])
}).strict();
var idBase = { headSha: Sha, sha: Sha, runId: numberType().int().positive(), runAttempt: numberType().int().positive() };
var ReportIdentity = discriminatedUnionType("event", [
  objectType({
    event: literalType("pull_request"),
    prNumber: numberType().int().positive(),
    ref: PrMergeRef,
    baseRef: stringType().min(1).max(256),
    baseSha: Sha,
    ...idBase
  }).strict(),
  objectType({ event: literalType("push"), ref: BranchRef, before: Sha, after: Sha, ...idBase }).strict(),
  objectType({ event: literalType("workflow_dispatch"), ref: BranchRef, ...idBase }).strict()
]).superRefine((i, ctx) => {
  if (i.event === "pull_request" && i.ref !== `refs/pull/${i.prNumber}/merge`) {
    ctx.addIssue({ code: ZodIssueCode.custom, path: ["ref"], message: "ref must be refs/pull/<prNumber>/merge" });
  }
  if (i.event === "push" && !(i.sha === i.after && i.headSha === i.after)) {
    ctx.addIssue({ code: ZodIssueCode.custom, path: ["sha"], message: "a push must have sha = headSha = after" });
  }
  if (i.event === "workflow_dispatch" && i.headSha !== i.sha) {
    ctx.addIssue({ code: ZodIssueCode.custom, path: ["headSha"], message: "a dispatch must have headSha = sha" });
  }
});
var Report = objectType({ identity: ReportIdentity, scan: unionType([ScanOutput, FailureEnvelope]) }).strict();
var SealedScan = stringType().min(1).max(LIMITS.maxChunkChars * LIMITS.maxChunks).regex(/^[A-Za-z0-9+/]*={0,2}$/);
var WireReport = unionType([
  objectType({ identity: ReportIdentity, sealed: SealedScan }).strict(),
  objectType({ identity: ReportIdentity, scan: FailureEnvelope }).strict()
]);
function encodeScanOutput(json, sealer) {
  const gzipped = import_node_zlib.gzipSync(Buffer.from(json, "utf8"));
  const encoded = (sealer ? sealer(gzipped) : gzipped).toString("base64");
  const chunks = [];
  for (let i = 0;i < encoded.length; i += LIMITS.maxChunkChars) {
    chunks.push(encoded.slice(i, i + LIMITS.maxChunkChars));
  }
  if (chunks.length > LIMITS.maxChunks) {
    throw new RangeError(`scan output needs ${chunks.length} chunks, more than ${LIMITS.maxChunks}`);
  }
  return chunks;
}

// apps/github-scan-action/src/event.ts
var ZERO_SHA = "0".repeat(40);
var CALLER_WORKFLOW_PATH = ".github/workflows/jutsu-security.yml";
var SHA = /^[0-9a-f]{40}$/;
var BRANCH_REF = /^refs\/heads\/[^\s\x00-\x1f\x7f]+$/;
function obj(v) {
  return v !== null && typeof v === "object" && !Array.isArray(v) ? v : null;
}
function sha(v) {
  return typeof v === "string" && SHA.test(v) ? v : null;
}
function readTarget(eventName, event, env) {
  const e = obj(event);
  if (e === null)
    return { kind: "unsupported", why: "the event payload could not be read" };
  switch (eventName) {
    case "pull_request": {
      const pr = obj(e.pull_request);
      const head = obj(pr?.head);
      const base = obj(pr?.base);
      const prNumber = pr?.number;
      const headSha = sha(head?.sha);
      const baseSha = sha(base?.sha);
      const baseRef = base?.ref;
      if (e.action === "closed")
        return { kind: "unsupported", why: "the pull request is closed" };
      if (typeof prNumber !== "number" || !Number.isSafeInteger(prNumber) || prNumber < 1 || headSha === null || baseSha === null || typeof baseRef !== "string" || baseRef.length === 0) {
        return { kind: "unsupported", why: "the pull_request event lacks a number, head or base" };
      }
      return { kind: "pull_request", prNumber, headSha, baseSha, baseRef };
    }
    case "push": {
      const ref = env.GITHUB_REF ?? (typeof e.ref === "string" ? e.ref : "");
      const before = sha(e.before);
      const after = sha(e.after);
      if (e.deleted === true || after === null || after === ZERO_SHA) {
        return { kind: "unsupported", why: "the push deleted the branch" };
      }
      if (!BRANCH_REF.test(ref))
        return { kind: "unsupported", why: `the push is to ${ref || "an unknown ref"}, not a branch` };
      if (before === null)
        return { kind: "unsupported", why: "the push event lacks before" };
      return { kind: "push", ref, before, after };
    }
    case "workflow_dispatch": {
      const ref = env.GITHUB_REF ?? "";
      const s = sha(env.GITHUB_SHA);
      if (!BRANCH_REF.test(ref))
        return { kind: "unsupported", why: `the run is on ${ref || "an unknown ref"}, not a branch` };
      if (s === null)
        return { kind: "unsupported", why: "GITHUB_SHA is not a commit SHA" };
      return { kind: "workflow_dispatch", ref, sha: s };
    }
    default:
      return { kind: "unsupported", why: `the ${eventName ?? "unknown"} event is not scanned` };
  }
}
function planScan(t, f) {
  switch (t.kind) {
    case "pull_request":
      return f.mergeBase === null ? { head: t.headSha, base: null, baseUnavailable: true, range: null, rangeUnavailable: true, treeScan: false, inventory: false } : {
        head: t.headSha,
        base: f.mergeBase,
        baseUnavailable: false,
        range: { from: f.mergeBase, to: t.headSha },
        rangeUnavailable: false,
        treeScan: false,
        inventory: false
      };
    case "push":
      if (t.before === ZERO_SHA) {
        return { head: t.after, base: null, baseUnavailable: false, range: null, rangeUnavailable: false, treeScan: true, inventory: true };
      }
      if (!f.beforeAvailable) {
        return { head: t.after, base: null, baseUnavailable: true, range: null, rangeUnavailable: true, treeScan: true, inventory: true };
      }
      return {
        head: t.after,
        base: t.before,
        baseUnavailable: false,
        range: { from: t.before, to: t.after },
        rangeUnavailable: false,
        treeScan: f.workflowTouched,
        inventory: true
      };
    case "workflow_dispatch":
      return { head: t.sha, base: null, baseUnavailable: false, range: null, rangeUnavailable: false, treeScan: true, inventory: true };
  }
}
function buildIdentity(t, env) {
  const runId = Number(env.GITHUB_RUN_ID);
  const runAttempt = Number(env.GITHUB_RUN_ATTEMPT);
  const runSha = env.GITHUB_SHA ?? "";
  let candidate;
  switch (t.kind) {
    case "pull_request":
      candidate = {
        event: "pull_request",
        prNumber: t.prNumber,
        ref: env.GITHUB_REF ?? "",
        sha: runSha,
        headSha: t.headSha,
        baseRef: t.baseRef,
        baseSha: t.baseSha,
        runId,
        runAttempt
      };
      break;
    case "push":
      candidate = { event: "push", ref: t.ref, before: t.before, after: t.after, sha: runSha, headSha: t.after, runId, runAttempt };
      break;
    case "workflow_dispatch":
      candidate = { event: "workflow_dispatch", ref: t.ref, sha: runSha, headSha: t.sha, runId, runAttempt };
      break;
  }
  const parsed = ReportIdentity.safeParse(candidate);
  if (!parsed.success) {
    const fields = [...new Set(parsed.error.issues.map((i) => i.path.join(".") || "(root)"))].join(", ");
    return { ok: false, why: `the run's identity does not validate (${fields})` };
  }
  return { ok: true, identity: parsed.data };
}

// apps/github-scan-action/src/git.ts
var import_node_fs = require("node:fs");
var import_node_path = require("node:path");
var PASSED = [
  "PATH",
  "HOME",
  "LANG",
  "LC_ALL",
  "TMPDIR",
  "TMP",
  "TEMP",
  "RUNNER_TEMP",
  "SSL_CERT_FILE",
  "SSL_CERT_DIR",
  "HTTP_PROXY",
  "HTTPS_PROXY",
  "NO_PROXY",
  "http_proxy",
  "https_proxy",
  "no_proxy"
];
function childBaseEnv(parent) {
  const env = {};
  for (const k of PASSED) {
    const v = parent[k];
    if (v !== undefined)
      env[k] = v;
  }
  return env;
}
function basicAuthValue(token) {
  return `basic ${Buffer.from(`x-access-token:${token}`, "utf8").toString("base64")}`;
}
function gitEnv(parent, auth) {
  const env = childBaseEnv(parent);
  env.GIT_TERMINAL_PROMPT = "0";
  env.GIT_CONFIG_NOSYSTEM = "1";
  env.GIT_CONFIG_GLOBAL = "/dev/null";
  env.GIT_LITERAL_PATHSPECS = "1";
  env.GIT_OPTIONAL_LOCKS = "0";
  const entries = [];
  if (auth !== null) {
    const server = auth.serverUrl.replace(/\/+$/, "");
    entries.push([`http.${server}/.extraheader`, `AUTHORIZATION: ${basicAuthValue(auth.token)}`]);
  }
  entries.push(["promisor.quiet", "true"], ["gc.auto", "0"], ["maintenance.auto", "false"], ["core.hooksPath", "/dev/null"], ["core.attributesFile", "/dev/null"], ["core.fsmonitor", "false"], ["fetch.recurseSubmodules", "false"], ["protocol.version", "2"]);
  env.GIT_CONFIG_COUNT = String(entries.length);
  entries.forEach(([k, v], i) => {
    env[`GIT_CONFIG_KEY_${i}`] = k;
    env[`GIT_CONFIG_VALUE_${i}`] = v;
  });
  return env;
}
function parseLsTree(out) {
  const entries = [];
  for (const rec of out.toString("utf8").split("\x00")) {
    if (rec.length === 0)
      continue;
    const tab = rec.indexOf("\t");
    if (tab === -1)
      continue;
    const [mode, type, oid] = rec.slice(0, tab).split(" ");
    if (mode === undefined || type === undefined || oid === undefined)
      continue;
    entries.push({ mode, type, oid, path: rec.slice(tab + 1) });
  }
  return entries;
}
function parseCatFileBatch(out) {
  const objects = new Map;
  let off = 0;
  while (off < out.length) {
    const nl = out.indexOf(10, off);
    if (nl === -1)
      break;
    const header = out.toString("utf8", off, nl).split(" ");
    off = nl + 1;
    if (header[1] === "missing" || header.length < 3)
      continue;
    const size = Number(header[2]);
    if (!Number.isSafeInteger(size) || size < 0 || off + size > out.length)
      break;
    objects.set(header[0] ?? "", out.subarray(off, off + size));
    off += size + 1;
  }
  return objects;
}
var BATCH_BLOB_MAX = 8 * 1024 * 1024;
var BATCH_GROUP_BYTES = 64 * 1024 * 1024;
var PREFETCH_CHUNK = 5000;

class Git {
  runner;
  dir;
  env;
  timeouts;
  constructor(runner, dir, env, timeouts = { fetchMs: 300000, localMs: 120000 }) {
    this.runner = runner;
    this.dir = dir;
    this.env = env;
    this.timeouts = timeouts;
  }
  run(args, opts = {}) {
    return this.runner.run("git", ["-C", this.dir, ...args], {
      env: this.env,
      timeoutMs: opts.timeoutMs ?? this.timeouts.localMs,
      ...opts.input === undefined ? {} : { input: opts.input },
      ...opts.stdout === undefined ? {} : { stdout: opts.stdout }
    });
  }
  async init(remoteUrl) {
    const init = await this.runner.run("git", ["init", "-q", this.dir], { env: this.env, timeoutMs: this.timeouts.localMs });
    if (init.code !== 0)
      return false;
    return (await this.run(["remote", "add", "origin", remoteUrl])).code === 0;
  }
  async fetch(refspecs) {
    const r = await this.run([
      "fetch",
      "--quiet",
      "--filter=blob:none",
      "--no-tags",
      "--no-recurse-submodules",
      "origin",
      ...refspecs
    ], { stdout: "ignore", timeoutMs: this.timeouts.fetchMs });
    return r.code === 0;
  }
  async commit(rev) {
    const r = await this.run(["rev-parse", "--verify", "--quiet", `${rev}^{commit}`]);
    const out = r.stdout.toString("utf8").trim();
    return r.code === 0 && /^[0-9a-f]{40}$/.test(out) ? out : null;
  }
  async mergeBase(a, b) {
    const r = await this.run(["merge-base", a, b]);
    const out = r.stdout.toString("utf8").trim();
    return r.code === 0 && /^[0-9a-f]{40}$/.test(out) ? out : null;
  }
  async revList(from, to, max) {
    const r = await this.run(["rev-list", ...max === null ? [] : [`--max-count=${max}`], `${from}..${to}`]);
    if (r.code !== 0)
      return null;
    return r.stdout.toString("utf8").split(`
`).filter((l) => /^[0-9a-f]{40}$/.test(l));
  }
  async countRange(from, to) {
    const r = await this.run(["rev-list", "--count", `${from}..${to}`]);
    const n = Number(r.stdout.toString("utf8").trim());
    return r.code === 0 && Number.isSafeInteger(n) ? n : null;
  }
  async touched(from, to, path) {
    const r = await this.run(["log", "--full-history", "--format=%H", `${from}..${to}`, "--", path]);
    return r.code === 0 ? r.stdout.toString("utf8").trim().length > 0 : null;
  }
  async lsTree(commit, paths) {
    const r = await this.run(["ls-tree", "-r", "-z", "--full-tree", commit, ...paths === undefined ? [] : ["--", ...paths]]);
    return r.code === 0 ? parseLsTree(r.stdout) : null;
  }
  async prefetch(oids) {
    const unique = [...new Set(oids)];
    for (let i = 0;i < unique.length; i += PREFETCH_CHUNK) {
      const chunk = unique.slice(i, i + PREFETCH_CHUNK);
      const r = await this.runner.run("git", [
        "-C",
        this.dir,
        "-c",
        "fetch.negotiationAlgorithm=noop",
        "fetch",
        "--quiet",
        "--no-tags",
        "--no-write-fetch-head",
        "--no-recurse-submodules",
        "--filter=blob:none",
        "--stdin",
        "origin"
      ], { env: this.env, input: `${chunk.join(`
`)}
`, stdout: "ignore", timeoutMs: this.timeouts.fetchMs });
      if (r.code !== 0)
        return false;
    }
    return true;
  }
  async sizes(oids) {
    const unique = [...new Set(oids)];
    if (unique.length === 0)
      return new Map;
    const r = await this.run(["cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize)"], { input: `${unique.join(`
`)}
`, timeoutMs: this.timeouts.fetchMs });
    if (r.code !== 0)
      return null;
    const sizes = new Map;
    for (const line of r.stdout.toString("utf8").split(`
`)) {
      const [oid, type, size] = line.split(" ");
      if (oid !== undefined && type === "blob" && size !== undefined)
        sizes.set(oid, Number(size));
    }
    return sizes;
  }
  async readBlobs(oids) {
    const unique = [...new Set(oids)];
    if (unique.length === 0)
      return new Map;
    const r = await this.run(["cat-file", "--batch"], { input: `${unique.join(`
`)}
`, timeoutMs: this.timeouts.fetchMs });
    return r.code === 0 ? parseCatFileBatch(r.stdout) : null;
  }
  async writeBlobs(items) {
    const small = items.filter((i) => i.size <= BATCH_BLOB_MAX);
    const large = items.filter((i) => i.size > BATCH_BLOB_MAX);
    let group = [];
    let groupBytes = 0;
    const flush = async () => {
      if (group.length === 0)
        return true;
      const blobs = await this.readBlobs(group.map((g) => g.oid));
      if (blobs === null)
        return false;
      for (const g of group) {
        const content = blobs.get(g.oid);
        if (content === undefined)
          return false;
        import_node_fs.mkdirSync(import_node_path.dirname(g.dest), { recursive: true, mode: 448 });
        import_node_fs.writeFileSync(g.dest, content, { mode: 384 });
      }
      group = [];
      groupBytes = 0;
      return true;
    };
    for (const item of small) {
      if (groupBytes + item.size > BATCH_GROUP_BYTES && !await flush())
        return false;
      group.push(item);
      groupBytes += item.size;
    }
    if (!await flush())
      return false;
    for (const item of large) {
      import_node_fs.mkdirSync(import_node_path.dirname(item.dest), { recursive: true, mode: 448 });
      const r = await this.run(["cat-file", "blob", item.oid], { stdout: { file: item.dest }, timeoutMs: this.timeouts.fetchMs });
      if (r.code !== 0)
        return false;
    }
    return true;
  }
}

// apps/github-scan-action/src/runner.ts
var import_node_child_process = require("node:child_process");
var import_node_fs2 = require("node:fs");
var DEFAULT_MAX_STDOUT = 256 * 1024 * 1024;
var nodeRunner = {
  run(cmd, args, opts) {
    const started = Date.now();
    return new Promise((resolve) => {
      const mode = opts.stdout ?? "capture";
      let fd = null;
      let settled = false;
      const finish = (r) => {
        if (settled)
          return;
        settled = true;
        if (fd !== null) {
          try {
            import_node_fs2.closeSync(fd);
          } catch {}
          fd = null;
        }
        resolve(r);
      };
      if (typeof mode === "object") {
        try {
          fd = import_node_fs2.openSync(mode.file, "w", 384);
        } catch (err) {
          finish({ code: null, timedOut: false, stdout: Buffer.alloc(0), elapsedMs: 0, error: `cannot open ${mode.file}: ${String(err)}` });
          return;
        }
      }
      const stdoutSpec = mode === "capture" ? "pipe" : mode === "ignore" ? "ignore" : fd;
      let child;
      try {
        child = import_node_child_process.spawn(cmd, [...args], {
          cwd: opts.cwd,
          env: opts.env,
          stdio: [opts.input === undefined ? "ignore" : "pipe", stdoutSpec, "ignore"],
          windowsHide: true
        });
      } catch (err) {
        finish({ code: null, timedOut: false, stdout: Buffer.alloc(0), elapsedMs: Date.now() - started, error: String(err) });
        return;
      }
      const chunks = [];
      let size = 0;
      let overflow = false;
      let timedOut = false;
      const max = opts.maxStdoutBytes ?? DEFAULT_MAX_STDOUT;
      const timer = opts.timeoutMs === undefined ? null : setTimeout(() => {
        timedOut = true;
        child.kill("SIGKILL");
      }, opts.timeoutMs);
      child.stdout?.on("data", (c) => {
        size += c.length;
        if (size > max) {
          if (!overflow) {
            overflow = true;
            child.kill("SIGKILL");
          }
          return;
        }
        chunks.push(c);
      });
      child.on("error", (err) => {
        if (child.pid === undefined) {
          if (timer !== null)
            clearTimeout(timer);
          finish({ code: null, timedOut: false, stdout: Buffer.alloc(0), elapsedMs: Date.now() - started, error: String(err) });
        }
      });
      if (opts.input !== undefined && child.stdin !== null) {
        child.stdin.on("error", () => {});
        child.stdin.end(opts.input);
      }
      child.on("close", (code) => {
        if (timer !== null)
          clearTimeout(timer);
        finish({
          code: timedOut || overflow ? null : code,
          timedOut,
          stdout: Buffer.concat(chunks),
          elapsedMs: Date.now() - started,
          ...overflow ? { error: `stdout exceeded ${max} bytes` } : {}
        });
      });
    });
  }
};

// apps/github-scan-action/src/scanner.ts
var import_node_fs4 = require("node:fs");
var import_node_path2 = require("node:path");

// apps/github-scan-action/src/gitleaks.ts
var import_node_crypto2 = require("node:crypto");
var GITLEAKS_TIMEOUT_S = 600;
var MERGE_DIFF_OPTION = "--diff-merges=remerge";
function commonArgs(configPath, reportPath) {
  return [
    "--config",
    configPath,
    "--ignore-gitleaks-allow",
    "--gitleaks-ignore-path",
    "/dev/null",
    "--report-format",
    "json",
    "--report-path",
    reportPath,
    "--exit-code",
    "0",
    "--timeout",
    String(GITLEAKS_TIMEOUT_S),
    "--no-banner",
    "--log-level",
    "error"
  ];
}
function gitleaksGitArgs(o) {
  const logOpts = [
    MERGE_DIFF_OPTION,
    ...o.maxCount === null ? [] : [`--max-count=${o.maxCount}`],
    `${o.range.from}..${o.range.to}`
  ].join(" ");
  return ["git", ...commonArgs(o.configPath, o.reportPath), `--log-opts=${logOpts}`, o.repoDir];
}
function gitleaksDirArgs(o) {
  return ["dir", ...commonArgs(o.configPath, o.reportPath), o.source];
}
function parseGitleaksReport(text) {
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    return null;
  }
  if (!Array.isArray(data))
    return null;
  const out = [];
  for (const item of data) {
    if (item === null || typeof item !== "object")
      return null;
    const f = item;
    const secret = typeof f.Secret === "string" && f.Secret.length > 0 ? f.Secret : typeof f.Match === "string" ? f.Match : "";
    if (typeof f.RuleID !== "string" || typeof f.File !== "string" || secret.length === 0)
      return null;
    const startLine = typeof f.StartLine === "number" && Number.isFinite(f.StartLine) ? Math.max(1, Math.trunc(f.StartLine)) : 1;
    const endLineRaw = typeof f.EndLine === "number" && Number.isFinite(f.EndLine) ? Math.trunc(f.EndLine) : startLine;
    out.push({
      ruleId: f.RuleID,
      file: f.File,
      startLine,
      endLine: Math.max(startLine, endLineRaw),
      commit: typeof f.Commit === "string" ? f.Commit : "",
      value: secret
    });
  }
  return out;
}
function treeRelativePath(file, prefixes) {
  const normalised = file.replace(/\\/g, "/");
  for (const p of prefixes) {
    const withSlash = p.endsWith("/") ? p : `${p}/`;
    if (normalised.startsWith(withSlash))
      return normalised.slice(withSlash.length);
  }
  return null;
}
function digestSecret(value) {
  return import_node_crypto2.createHash("sha256").update(value, "utf8").digest("hex");
}
function toSecretFinding(raw, inHeadTree) {
  const candidate = {
    ruleId: raw.ruleId,
    path: raw.path,
    startLine: raw.startLine,
    endLine: raw.endLine,
    commitSha: raw.commit,
    valueDigest: digestSecret(raw.value),
    inHeadTree
  };
  const parsed = SecretFinding.safeParse(candidate);
  if (parsed.success)
    return { ok: true, finding: parsed.data };
  const tooLong = Buffer.byteLength(raw.path, "utf8") > LIMITS.maxPathBytes;
  return { ok: false, reason: tooLong ? "output_too_large" : "upstream_error" };
}

// apps/github-scan-action/src/osv.ts
var LOCKFILE_BASENAMES = [
  "Cargo.lock",
  "Gemfile.lock",
  "Pipfile.lock",
  "buildscript-gradle.lockfile",
  "bun.lock",
  "cabal.project.freeze",
  "composer.lock",
  "conan.lock",
  "deps.json",
  "gems.locked",
  "go.mod",
  "gradle.lockfile",
  "mix.lock",
  "package-lock.json",
  "packages.config",
  "packages.lock.json",
  "pdm.lock",
  "pnpm-lock.yaml",
  "poetry.lock",
  "pom.xml",
  "pubspec.lock",
  "pylock.toml",
  "renv.lock",
  "requirements.txt",
  "stack.yaml.lock",
  "uv.lock",
  "verification-metadata.xml",
  "yarn.lock"
];
var LOCKFILES = new Set(LOCKFILE_BASENAMES);
function basenameOf(path) {
  const i = path.lastIndexOf("/");
  return i === -1 ? path : path.slice(i + 1);
}
function isLockfile(path) {
  return LOCKFILES.has(basenameOf(path));
}
var OSV_EXIT = { clean: 0, vulnerable: 1, error: 127, noPackages: 128, apiFailed: 129 };
var OSV_TIMEOUT_S = 300;
function osvArgs(o) {
  return [
    "scan",
    "source",
    "--format",
    "json",
    "--output-file",
    o.outputPath,
    "--config",
    o.configPath,
    "--no-resolve",
    "--no-ignore",
    "--no-call-analysis=all",
    ...o.allPackages ? ["--all-packages"] : [],
    ...o.lockfiles.flatMap((p) => ["-L", `${basenameOf(p)}:${p}`])
  ];
}
function strings(v) {
  return Array.isArray(v) ? v.filter((x) => typeof x === "string") : [];
}
function parseOsvJson(text) {
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    return null;
  }
  if (data === null || typeof data !== "object")
    return null;
  const results = data.results;
  if (!Array.isArray(results))
    return null;
  const out = [];
  for (const r of results) {
    if (r === null || typeof r !== "object")
      return null;
    const source = r.source;
    if (source === undefined || typeof source.path !== "string")
      return null;
    const packages = [];
    const rawPackages = r.packages;
    for (const p of Array.isArray(rawPackages) ? rawPackages : []) {
      if (p === null || typeof p !== "object")
        continue;
      const pkg = p.package;
      if (pkg === undefined || pkg === null)
        continue;
      const groups = [];
      const rawGroups = p.groups;
      if (Array.isArray(rawGroups) && rawGroups.length > 0) {
        for (const g of rawGroups) {
          if (g === null || typeof g !== "object")
            continue;
          groups.push([...strings(g.ids), ...strings(g.aliases)]);
        }
      } else {
        const vulns = p.vulnerabilities;
        for (const v of Array.isArray(vulns) ? vulns : []) {
          if (v === null || typeof v !== "object")
            continue;
          const id = v.id;
          groups.push([...typeof id === "string" ? [id] : [], ...strings(v.aliases)]);
        }
      }
      packages.push({
        ecosystem: typeof pkg.ecosystem === "string" ? pkg.ecosystem : "",
        name: typeof pkg.name === "string" ? pkg.name : "",
        version: typeof pkg.version === "string" ? pkg.version : "",
        advisoryGroups: groups.filter((g) => g.length > 0)
      });
    }
    out.push({ path: source.path, packages });
  }
  return out;
}
function advisoryIdsOf(group) {
  const out = [];
  for (const id of group) {
    if (out.length === 16)
      break;
    if (!out.includes(id) && AdvisoryId.safeParse(id).success)
      out.push(id);
  }
  return out;
}
function sideRelativePath(sourcePath, roots) {
  const p = sourcePath.startsWith("/") ? sourcePath : `/${sourcePath}`;
  for (const root of roots) {
    const r = root.endsWith("/") ? root : `${root}/`;
    if (p.startsWith(r))
      return p.slice(r.length);
  }
  return null;
}

// apps/github-scan-action/src/output.ts
var RANK = { complete: 0, incomplete_input: 1, failed: 2 };
function worse(a, b) {
  return RANK[b.coverage] > RANK[a.coverage] ? b : a;
}
function incomplete(reason) {
  return { coverage: "incomplete_input", reason };
}
function failed(reason) {
  return { coverage: "failed", reason };
}
function vulnKey(v) {
  return `${v.manifestPath}\x00${v.ecosystem}\x00${v.package}`;
}
function markIntroduced(head, base) {
  const seen = new Map;
  for (const b of base ?? []) {
    const k = vulnKey(b);
    let ids = seen.get(k);
    if (ids === undefined) {
      ids = new Set;
      seen.set(k, ids);
    }
    for (const id of b.advisoryIds)
      ids.add(id);
  }
  return head.map((h) => {
    const ids = base === null ? undefined : seen.get(vulnKey(h));
    const introduced = ids === undefined || !h.advisoryIds.some((id) => ids.has(id));
    return {
      advisoryIds: [...h.advisoryIds],
      ecosystem: h.ecosystem,
      package: h.package,
      version: h.version,
      manifestPath: h.manifestPath,
      introduced
    };
  });
}
function compareStrings(a, b) {
  return a < b ? -1 : a > b ? 1 : 0;
}
function secretOrder(a, b) {
  return compareStrings(a.path, b.path) || a.startLine - b.startLine || compareStrings(a.commitSha, b.commitSha) || compareStrings(a.ruleId, b.ruleId) || compareStrings(a.valueDigest, b.valueDigest) || Number(b.inHeadTree) - Number(a.inHeadTree);
}
function vulnOrder(a, b) {
  return compareStrings(a.manifestPath, b.manifestPath) || compareStrings(a.ecosystem, b.ecosystem) || compareStrings(a.package, b.package) || compareStrings(a.version, b.version) || compareStrings(a.advisoryIds.join(","), b.advisoryIds.join(","));
}
function dedupe(items, key) {
  const out = new Map;
  for (const i of items) {
    const k = key(i);
    if (!out.has(k))
      out.set(k, i);
  }
  return [...out.values()];
}
function buildScanOutput(p) {
  let secretsCov = { coverage: p.secrets.coverage, reason: p.secrets.reason };
  let secrets = dedupe(p.secrets.findings, (f) => `${f.ruleId}\x00${f.path}\x00${f.startLine}\x00${f.endLine}\x00${f.commitSha}\x00${f.valueDigest}`).sort(secretOrder);
  if (secrets.length > LIMITS.maxFindingsPerTool) {
    secrets = secrets.slice(0, LIMITS.maxFindingsPerTool);
    secretsCov = worse(secretsCov, incomplete("too_many_findings"));
  }
  let headCov = p.vulnerabilities.head;
  let vulns = dedupe(p.vulnerabilities.findings, (f) => `${f.manifestPath}\x00${f.ecosystem}\x00${f.package}\x00${f.version}\x00${[...f.advisoryIds].sort().join(",")}`).sort(vulnOrder);
  if (vulns.length > LIMITS.maxFindingsPerTool) {
    vulns = vulns.slice(0, LIMITS.maxFindingsPerTool);
    headCov = worse(headCov, incomplete("too_many_findings"));
  }
  const out = {
    version: REPORT_VERSION,
    scanResult: "success",
    commits: p.commits.slice(0, LIMITS.maxCommits),
    secrets: {
      coverage: secretsCov.coverage,
      reason: secretsCov.coverage === "complete" ? "none" : secretsCov.reason,
      tool: { name: "gitleaks", version: p.secrets.version },
      findings: secrets
    },
    vulnerabilities: {
      coverage: { head: headCov.coverage, base: p.vulnerabilities.base },
      reason: {
        head: headCov.coverage === "complete" ? "none" : headCov.reason,
        base: p.vulnerabilities.base === "incomplete" ? "base_unavailable" : "none"
      },
      manifests: p.vulnerabilities.manifests.slice(0, 2 * LIMITS.maxLockfiles),
      tool: { name: "osv-scanner", version: p.vulnerabilities.version },
      queriedAt: p.vulnerabilities.queriedAt,
      findings: vulns
    },
    treeScanned: p.treeScanned
  };
  if (p.inventory !== undefined) {
    if (p.inventory === "omitted") {
      out.inventory = "omitted";
    } else {
      const rows = dedupe(p.inventory, (r) => `${r.manifestPath}\x00${r.ecosystem}\x00${r.package}\x00${r.version}`).sort((a, b) => compareStrings(a.manifestPath, b.manifestPath) || compareStrings(a.ecosystem, b.ecosystem) || compareStrings(a.package, b.package) || compareStrings(a.version, b.version));
      out.inventory = rows.length > LIMITS.maxInventory ? "omitted" : rows;
    }
  }
  if (out.secrets.coverage !== "complete" && out.secrets.reason === "none")
    out.secrets.reason = "upstream_error";
  if (out.vulnerabilities.coverage.head !== "complete" && out.vulnerabilities.reason.head === "none") {
    out.vulnerabilities.reason.head = "upstream_error";
  }
  return out;
}
var IDENTITY_HEADROOM_BYTES = 8 * 1024;
var DEFAULT_BUDGET = {
  maxJsonBytes: LIMITS.maxBodyBytes - IDENTITY_HEADROOM_BYTES,
  maxEncodedChars: LIMITS.maxChunkChars * LIMITS.maxChunks
};
function encodeWithin(json, budget, sealer) {
  if (Buffer.byteLength(json, "utf8") > budget.maxJsonBytes)
    return null;
  let chunks;
  try {
    chunks = encodeScanOutput(json, sealer);
  } catch (err) {
    if (err instanceof RangeError)
      return null;
    throw err;
  }
  const total = chunks.reduce((n, c) => n + c.length, 0);
  return total > budget.maxEncodedChars ? null : chunks;
}
function findingsWeight(o, tool) {
  return JSON.stringify(tool === "secrets" ? o.secrets.findings : o.vulnerabilities.findings).length;
}
function dropFindings(o, tool) {
  if (tool === "secrets") {
    const s = o.secrets;
    return s.coverage === "failed" ? { ...o, secrets: { ...s, findings: [] } } : { ...o, secrets: { ...s, coverage: "incomplete_input", reason: "output_too_large", findings: [] } };
  }
  const v = o.vulnerabilities;
  return v.coverage.head === "failed" ? { ...o, vulnerabilities: { ...v, findings: [] } } : { ...o, vulnerabilities: {
    ...v,
    coverage: { ...v.coverage, head: "incomplete_input" },
    reason: { ...v.reason, head: "output_too_large" },
    findings: []
  } };
}
function fitBudget(output, sealer, budget = DEFAULT_BUDGET) {
  const shed = [];
  let o = output;
  const steps = [
    () => {
      if (!Array.isArray(o.inventory))
        return false;
      o = { ...o, inventory: "omitted" };
      shed.push("inventory");
      return true;
    },
    () => {
      const first = findingsWeight(o, "secrets") >= findingsWeight(o, "vulnerabilities") ? "secrets" : "vulnerabilities";
      o = dropFindings(o, first);
      shed.push(first);
      return true;
    },
    () => {
      const second = shed.includes("secrets") ? "vulnerabilities" : "secrets";
      o = dropFindings(o, second);
      shed.push(second);
      return true;
    },
    () => {
      o = { ...o, vulnerabilities: { ...o.vulnerabilities, manifests: [] } };
      shed.push("manifests");
      return true;
    }
  ];
  let next = 0;
  for (;; ) {
    const parsed = ScanOutput.safeParse(o);
    if (!parsed.success) {
      const where = [...new Set(parsed.error.issues.map((x) => x.path.join(".")))].join(", ");
      throw new Error(`the scan output does not validate (${where})`);
    }
    const json = JSON.stringify(o);
    const chunks = encodeWithin(json, budget, sealer);
    if (chunks !== null)
      return { output: o, json, chunks, shed };
    let applied = false;
    while (!applied && next < steps.length) {
      const step = steps[next];
      next++;
      if (step !== undefined)
        applied = step();
    }
    if (!applied)
      throw new Error("the scan output does not fit the transport budget even after shedding");
  }
}

// apps/github-scan-action/src/tools.ts
var import_node_crypto3 = require("node:crypto");
var import_node_fs3 = require("node:fs");
var import_node_zlib2 = require("node:zlib");
var PLATFORMS = ["linux-x64", "linux-arm64", "darwin-x64", "darwin-arm64"];
var HEX64 = /^[0-9a-f]{64}$/;
var VERSION = /^\d+\.\d+\.\d+$/;
function fail(what) {
  throw new TypeError(`tools.json: ${what}`);
}
function httpsUrl(v, what) {
  if (typeof v !== "string" || !v.startsWith("https://"))
    fail(`${what} must be an https URL`);
  return v;
}
function spec(raw, what) {
  if (raw === null || typeof raw !== "object")
    fail(`${what} is missing`);
  const r = raw;
  if (typeof r.version !== "string" || !VERSION.test(r.version))
    fail(`${what}.version must be x.y.z`);
  if (r.assets === null || typeof r.assets !== "object")
    fail(`${what}.assets is missing`);
  const assets = {};
  for (const [key, value] of Object.entries(r.assets)) {
    if (!PLATFORMS.includes(key))
      fail(`${what}.assets.${key} is not a known platform`);
    const a = value;
    if (a === null || typeof a !== "object")
      fail(`${what}.assets.${key} is not an object`);
    const url = httpsUrl(a.url, `${what}.assets.${key}.url`);
    if (typeof a.sha256 !== "string" || !HEX64.test(a.sha256))
      fail(`${what}.assets.${key}.sha256 must be 64 hex characters`);
    if (a.archive !== "tar.gz" && a.archive !== "binary")
      fail(`${what}.assets.${key}.archive must be tar.gz or binary`);
    if (a.archive === "tar.gz" && (typeof a.member !== "string" || a.member.length === 0)) {
      fail(`${what}.assets.${key}.member names the file to take from the archive`);
    }
    assets[key] = {
      url,
      sha256: a.sha256,
      archive: a.archive,
      ...typeof a.member === "string" ? { member: a.member } : {}
    };
  }
  return { version: r.version, assets };
}
function parseToolsManifest(raw) {
  if (raw === null || typeof raw !== "object")
    fail("not an object");
  const r = raw;
  const gitleaks = spec(r.gitleaks, "gitleaks");
  const dc = r.gitleaks.defaultConfig;
  if (dc === undefined || dc === null || typeof dc !== "object")
    fail("gitleaks.defaultConfig is missing");
  const dcUrl = httpsUrl(dc.url, "gitleaks.defaultConfig.url");
  if (typeof dc.sha256 !== "string" || !HEX64.test(dc.sha256))
    fail("gitleaks.defaultConfig.sha256 must be 64 hex characters");
  return {
    gitleaks: { ...gitleaks, defaultConfig: { url: dcUrl, sha256: dc.sha256 } },
    osvScanner: spec(r.osvScanner, "osvScanner")
  };
}
function platformKey(platform = process.platform, arch = process.arch) {
  const key = `${platform}-${arch}`;
  return PLATFORMS.includes(key) ? key : null;
}
function sha256Hex(bytes) {
  return import_node_crypto3.createHash("sha256").update(bytes).digest("hex");
}
function extractTarGzMember(archive, member) {
  let tar;
  try {
    tar = import_node_zlib2.gunzipSync(archive);
  } catch {
    return null;
  }
  const want = member.replace(/^\.\//, "");
  let off = 0;
  let longName = null;
  while (off + 512 <= tar.length) {
    const header = tar.subarray(off, off + 512);
    if (header.every((b) => b === 0))
      break;
    const field = (start, len) => {
      const raw = header.subarray(start, start + len);
      const nul = raw.indexOf(0);
      return raw.subarray(0, nul === -1 ? len : nul).toString("utf8");
    };
    const sizeText = field(124, 12).trim();
    const size = Number.parseInt(sizeText.length === 0 ? "0" : sizeText, 8);
    if (!Number.isFinite(size) || size < 0)
      return null;
    const type = field(156, 1);
    const prefix = header.subarray(257, 263).toString("latin1").startsWith("ustar") ? field(345, 155) : "";
    const base = field(0, 100);
    const name = (longName ?? (prefix.length > 0 ? `${prefix}/${base}` : base)).replace(/^\.\//, "");
    const dataStart = off + 512;
    const dataEnd = dataStart + size;
    if (dataEnd > tar.length)
      return null;
    if (type === "L") {
      longName = tar.subarray(dataStart, dataEnd).toString("utf8").replace(/\0+$/, "");
    } else {
      longName = null;
      if ((type === "0" || type === "" || type === "\x00") && name === want) {
        return Buffer.from(tar.subarray(dataStart, dataEnd));
      }
    }
    off = dataStart + Math.ceil(size / 512) * 512;
  }
  return null;
}
async function installTool(o) {
  let bytes;
  try {
    const res = await o.fetchImpl(o.asset.url, { redirect: "follow", signal: AbortSignal.timeout(o.timeoutMs ?? 180000) });
    if (!res.ok)
      return { ok: false, why: `download answered HTTP ${res.status}` };
    bytes = new Uint8Array(await res.arrayBuffer());
  } catch (err) {
    return { ok: false, why: `download failed: ${err instanceof Error ? err.message : String(err)}` };
  }
  const digest = sha256Hex(bytes);
  if (digest !== o.asset.sha256)
    return { ok: false, why: `sha256 mismatch (got ${digest})` };
  let binary;
  if (o.asset.archive === "tar.gz") {
    const m = extractTarGzMember(bytes, o.asset.member ?? "");
    if (m === null)
      return { ok: false, why: `the archive holds no ${o.asset.member ?? "binary"}` };
    binary = m;
  } else {
    binary = bytes;
  }
  try {
    import_node_fs3.writeFileSync(o.destPath, binary, { mode: 493 });
    import_node_fs3.chmodSync(o.destPath, 493);
  } catch (err) {
    return { ok: false, why: `cannot write the binary: ${String(err)}` };
  }
  return { ok: true };
}

// apps/github-scan-action/src/types.ts
var COMPLETE = { coverage: "complete", reason: "none" };

// apps/github-scan-action/src/scanner.ts
var MAX_TREE_FILES = 1e5;
var MAX_TREE_BYTES = 2 * 1024 * 1024 * 1024;
function safeJoin(root, repoPath) {
  const segments = repoPath.split("/");
  if (segments.some((s) => s === "" || s === "." || s === ".." || s.includes("\x00")))
    return null;
  const full = import_node_path2.resolve(root, ...segments);
  return full.startsWith(root.endsWith(import_node_path2.sep) ? root : root + import_node_path2.sep) ? full : null;
}
function isRegularBlob(e) {
  return e.type === "blob" && (e.mode === "100644" || e.mode === "100755");
}
function realpathOr(p) {
  try {
    return import_node_fs4.realpathSync(p);
  } catch {
    return p;
  }
}

class Scan {
  input;
  deps;
  work;
  repoDir;
  git;
  gitEnvVars;
  baseEnv;
  gitleaks = null;
  osv = null;
  emptyOsvConfig = "";
  constructor(input, deps, work) {
    this.input = input;
    this.deps = deps;
    this.work = work;
    this.repoDir = import_node_path2.join(work, "repo");
    this.gitEnvVars = gitEnv(input.parentEnv, input.auth);
    this.baseEnv = childBaseEnv(input.parentEnv);
    this.git = new Git(deps.runner, this.repoDir, this.gitEnvVars);
  }
  async installOne(name, asset, preset) {
    if (preset !== undefined)
      return preset;
    if (asset === undefined) {
      this.deps.log(`${name}: no pinned binary for this runner's platform`);
      return null;
    }
    const dest = import_node_path2.join(this.work, "bin", name);
    const r = await installTool({ asset, destPath: dest, fetchImpl: this.deps.fetch });
    if (!r.ok) {
      this.deps.log(`${name}: ${r.why}`);
      return null;
    }
    return dest;
  }
  async installTools() {
    import_node_fs4.mkdirSync(import_node_path2.join(this.work, "bin"), { recursive: true, mode: 448 });
    const platform = platformKey();
    const { tools, toolPaths } = this.input;
    const [g, o] = await Promise.all([
      this.installOne("gitleaks", platform === null ? undefined : tools.gitleaks.assets[platform], toolPaths?.gitleaks),
      this.installOne("osv-scanner", platform === null ? undefined : tools.osvScanner.assets[platform], toolPaths?.osvScanner)
    ]);
    this.gitleaks = g;
    this.osv = o;
    this.emptyOsvConfig = import_node_path2.join(this.work, "osv-scanner-empty.toml");
    import_node_fs4.writeFileSync(this.emptyOsvConfig, "", { mode: 384 });
  }
  async fetchAndPlan() {
    const t = this.input.target;
    import_node_fs4.mkdirSync(this.repoDir, { recursive: true, mode: 448 });
    if (!await this.git.init(this.input.remoteUrl))
      return null;
    switch (t.kind) {
      case "pull_request": {
        const compared = await this.deps.compare(t.baseSha, t.headSha);
        let ok = await this.git.fetch([`+refs/pull/${t.prNumber}/head:refs/jutsu/pr-head`, `+${t.baseSha}:refs/jutsu/base-tip`]);
        if (!ok || await this.git.commit("refs/jutsu/pr-head") !== t.headSha) {
          ok = await this.git.fetch([`+${t.headSha}:refs/jutsu/head`, `+${t.baseSha}:refs/jutsu/base-tip`]) || await this.git.fetch([`+${t.headSha}:refs/jutsu/head`]);
        }
        if (!ok || await this.git.commit(t.headSha) !== t.headSha)
          return null;
        let mergeBase = null;
        if (compared !== null && await this.git.commit(compared.mergeBase) === compared.mergeBase) {
          mergeBase = compared.mergeBase;
        } else if (await this.git.commit(t.baseSha) !== null) {
          mergeBase = await this.git.mergeBase(t.baseSha, t.headSha);
        }
        return planScan(t, { mergeBase, beforeAvailable: false, workflowTouched: false });
      }
      case "push": {
        if (t.before === ZERO_SHA) {
          if (!await this.git.fetch([`+${t.after}:refs/jutsu/head`]) || await this.git.commit(t.after) !== t.after)
            return null;
          return planScan(t, { mergeBase: null, beforeAvailable: false, workflowTouched: false });
        }
        const both = await this.git.fetch([`+${t.after}:refs/jutsu/head`, `+${t.before}:refs/jutsu/base`]);
        if (!both && !await this.git.fetch([`+${t.after}:refs/jutsu/head`]))
          return null;
        if (await this.git.commit(t.after) !== t.after)
          return null;
        const beforeAvailable = await this.git.commit(t.before) === t.before;
        const workflowTouched = beforeAvailable ? await this.git.touched(t.before, t.after, CALLER_WORKFLOW_PATH) ?? true : true;
        return planScan(t, { mergeBase: null, beforeAvailable, workflowTouched });
      }
      case "workflow_dispatch": {
        if (!await this.git.fetch([`+${t.sha}:refs/jutsu/head`]) || await this.git.commit(t.sha) !== t.sha)
          return null;
        return planScan(t, { mergeBase: null, beforeAvailable: false, workflowTouched: false });
      }
    }
  }
  async runGitleaks(args, reportPath, env) {
    const r = await this.deps.runner.run(this.gitleaks, args, {
      env,
      cwd: this.work,
      stdout: "ignore",
      timeoutMs: (GITLEAKS_TIMEOUT_S + 60) * 1000
    });
    let text = null;
    try {
      text = import_node_fs4.readFileSync(reportPath, "utf8");
    } catch {
      text = null;
    } finally {
      import_node_fs4.rmSync(reportPath, { force: true });
    }
    const items = text === null ? null : parseGitleaksReport(text);
    if (r.timedOut)
      return { coverage: incomplete("tool_timeout"), items: items ?? [] };
    if (r.code === 0) {
      return items === null ? { coverage: failed("upstream_error"), items: [] } : { coverage: COMPLETE, items };
    }
    const ownTimeout = r.code === 1 && r.elapsedMs >= GITLEAKS_TIMEOUT_S * 1000 - 5000;
    return { coverage: ownTimeout ? incomplete("tool_timeout") : failed("upstream_error"), items: items ?? [] };
  }
  async repairPaths(items) {
    const byCommit = new Map;
    for (const i of items) {
      const list = byCommit.get(i.commit) ?? [];
      list.push(i);
      byCommit.set(i.commit, list);
    }
    const out = [];
    for (const [commit, list] of byCommit) {
      const candidates = new Set;
      for (const i of list) {
        candidates.add(i.file);
        if (i.file.startsWith("b/"))
          candidates.add(i.file.slice(2));
      }
      const entries = /^[0-9a-f]{40}$/.test(commit) ? await this.git.lsTree(commit, [...candidates]) : null;
      const present = new Set((entries ?? []).map((e) => e.path));
      for (const i of list) {
        const fixed = entries !== null && !present.has(i.file) && i.file.startsWith("b/") && present.has(i.file.slice(2)) ? i.file.slice(2) : i.file;
        out.push({ ...i, file: fixed });
      }
    }
    return out;
  }
  async inHeadTree(items, headBlobs) {
    const oids = [...new Set(items.map((i) => headBlobs.get(i.file)).filter((o) => o !== undefined))];
    if (oids.length === 0)
      return items.map(() => false);
    const fetched = await this.git.prefetch(oids);
    const sizes = fetched ? await this.git.sizes(oids) : null;
    const readable = oids.filter((o) => (sizes?.get(o) ?? Infinity) <= LIMITS.maxLockfileBytes);
    const blobs = sizes === null ? null : await this.git.readBlobs(readable);
    return items.map((i) => {
      const oid = headBlobs.get(i.file);
      if (oid === undefined)
        return false;
      const content = blobs?.get(oid);
      if (content === undefined)
        return true;
      return content.indexOf(i.value, 0, "utf8") !== -1;
    });
  }
  async scanRange(plan, headBlobs) {
    const range = plan.range;
    if (range === null)
      return { coverage: COMPLETE, commits: [], findings: [] };
    const count = await this.git.countRange(range.from, range.to);
    if (count === null)
      return { coverage: failed("fetch_failed"), commits: [], findings: [] };
    const over = count > LIMITS.maxCommits;
    const commits = await this.git.revList(range.from, range.to, over ? LIMITS.maxCommits : null);
    if (commits === null)
      return { coverage: failed("fetch_failed"), commits: [], findings: [] };
    this.deps.log(`Range ${range.from.slice(0, 12)}..${range.to.slice(0, 12)}: ${count} commit${count === 1 ? "" : "s"}` + (over ? `, over the cap of ${LIMITS.maxCommits}: the newest ${LIMITS.maxCommits} are scanned` : ""));
    let coverage = over ? incomplete("too_many_commits") : COMPLETE;
    if (count === 0)
      return { coverage, commits: [], findings: [] };
    if (this.gitleaks === null)
      return { coverage: worse(coverage, failed("fetch_failed")), commits, findings: [] };
    const reportPath = import_node_path2.join(this.work, "gitleaks-range.json");
    const run = await this.runGitleaks(gitleaksGitArgs({
      repoDir: this.repoDir,
      configPath: this.input.gitleaksConfigPath,
      reportPath,
      range,
      maxCount: over ? LIMITS.maxCommits : null
    }), reportPath, this.gitEnvVars);
    coverage = worse(coverage, run.coverage);
    const items = await this.repairPaths(run.items);
    const present = await this.inHeadTree(items, headBlobs);
    const findings = [];
    items.forEach((i, n) => {
      const f = toSecretFinding({
        ruleId: i.ruleId,
        path: i.file,
        startLine: i.startLine,
        endLine: i.endLine,
        commit: i.commit,
        value: i.value
      }, present[n] ?? true);
      if (f.ok)
        findings.push(f.finding);
      else
        coverage = worse(coverage, incomplete(f.reason));
    });
    return { coverage, commits, findings };
  }
  async scanTree(plan, headTree) {
    if (this.gitleaks === null)
      return { coverage: failed("fetch_failed"), findings: [] };
    const files = headTree.filter(isRegularBlob);
    if (files.length > MAX_TREE_FILES) {
      this.deps.log(`Tree: ${files.length} files, over the cap of ${MAX_TREE_FILES}; not scanned`);
      return { coverage: incomplete("fetch_failed"), findings: [] };
    }
    const source = import_node_path2.join(this.work, "tree");
    const root = import_node_path2.join(source, "r");
    import_node_fs4.mkdirSync(root, { recursive: true, mode: 448 });
    try {
      if (!await this.git.prefetch(files.map((f) => f.oid)))
        return { coverage: failed("fetch_failed"), findings: [] };
      const sizes = await this.git.sizes(files.map((f) => f.oid));
      if (sizes === null)
        return { coverage: failed("fetch_failed"), findings: [] };
      const total = files.reduce((n, f) => n + (sizes.get(f.oid) ?? 0), 0);
      if (total > MAX_TREE_BYTES) {
        this.deps.log(`Tree: ${total} bytes, over the cap of ${MAX_TREE_BYTES}; not scanned`);
        return { coverage: incomplete("fetch_failed"), findings: [] };
      }
      let coverage = COMPLETE;
      const items = [];
      for (const f of files) {
        const dest = safeJoin(root, f.path);
        if (dest === null) {
          coverage = worse(coverage, incomplete("upstream_error"));
          continue;
        }
        items.push({ oid: f.oid, dest, size: sizes.get(f.oid) ?? 0 });
      }
      if (!await this.git.writeBlobs(items))
        return { coverage: failed("fetch_failed"), findings: [] };
      this.deps.log(`Tree: ${items.length} files`);
      const reportPath = import_node_path2.join(this.work, "gitleaks-tree.json");
      const run = await this.runGitleaks(gitleaksDirArgs({ source: "tree", configPath: this.input.gitleaksConfigPath, reportPath }), reportPath, this.baseEnv);
      coverage = worse(coverage, run.coverage);
      const prefixes = ["tree/r", `${source}/r`, `${realpathOr(source)}/r`];
      const findings = [];
      for (const i of run.items) {
        const path = treeRelativePath(i.file, prefixes);
        if (path === null) {
          coverage = worse(coverage, incomplete("upstream_error"));
          continue;
        }
        const f = toSecretFinding({
          ruleId: i.ruleId,
          path,
          startLine: i.startLine,
          endLine: i.endLine,
          commit: plan.head,
          value: i.value
        }, true);
        if (f.ok)
          findings.push(f.finding);
        else
          coverage = worse(coverage, incomplete(f.reason));
      }
      return { coverage, findings };
    } finally {
      import_node_fs4.rmSync(source, { recursive: true, force: true });
    }
  }
  async runOsv(lockfiles, allPackages, outputPath) {
    const r = await this.deps.runner.run(this.osv, osvArgs({
      lockfiles,
      configPath: this.emptyOsvConfig,
      outputPath,
      allPackages
    }), { env: this.baseEnv, cwd: this.work, stdout: "ignore", timeoutMs: OSV_TIMEOUT_S * 1000 });
    let text = null;
    try {
      text = import_node_fs4.readFileSync(outputPath, "utf8");
    } catch {
      text = null;
    } finally {
      import_node_fs4.rmSync(outputPath, { force: true });
    }
    return { code: r.code, timedOut: r.timedOut, text };
  }
  async scanSide(side, entries, allPackages) {
    const result = { coverage: COMPLETE, manifests: new Map, vulns: [], inventory: [] };
    const lockfiles = entries.filter((e) => isRegularBlob(e) && isLockfile(e.path)).sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
    const reportable = [];
    for (const e of lockfiles) {
      if (ManifestCoverage.safeParse({ side, path: e.path, status: "scanned" }).success) {
        reportable.push(e);
      } else {
        const tooLong = Buffer.byteLength(e.path, "utf8") > LIMITS.maxPathBytes;
        result.coverage = worse(result.coverage, incomplete(tooLong ? "output_too_large" : "upstream_error"));
      }
    }
    if (reportable.length > LIMITS.maxLockfiles)
      result.coverage = worse(result.coverage, incomplete("too_many_lockfiles"));
    const selected = reportable.slice(0, LIMITS.maxLockfiles);
    if (selected.length === 0)
      return result;
    if (!await this.git.prefetch(selected.map((e) => e.oid))) {
      result.coverage = worse(result.coverage, failed("fetch_failed"));
      return result;
    }
    const sizes = await this.git.sizes(selected.map((e) => e.oid));
    if (sizes === null) {
      result.coverage = worse(result.coverage, failed("fetch_failed"));
      return result;
    }
    const root = import_node_path2.join(this.work, "deps", side);
    import_node_fs4.mkdirSync(root, { recursive: true, mode: 448 });
    const toWrite = [];
    for (const e of selected) {
      const size = sizes.get(e.oid);
      const dest = safeJoin(root, e.path);
      if (size === undefined || dest === null) {
        result.coverage = worse(result.coverage, failed("fetch_failed"));
        continue;
      }
      if (size > LIMITS.maxLockfileBytes) {
        result.manifests.set(e.path, "too_large");
        result.coverage = worse(result.coverage, incomplete("lockfile_too_large"));
        continue;
      }
      toWrite.push({ oid: e.oid, dest, size, path: e.path });
    }
    if (toWrite.length === 0)
      return result;
    if (!await this.git.writeBlobs(toWrite)) {
      result.coverage = worse(result.coverage, failed("fetch_failed"));
      return result;
    }
    if (this.osv === null) {
      result.coverage = worse(result.coverage, failed("fetch_failed"));
      return result;
    }
    const roots = [root, realpathOr(root)];
    const byDest = new Map(toWrite.map((w) => [w.dest, w.path]));
    const absorb = (text) => {
      const sources = parseOsvJson(text);
      if (sources === null)
        return false;
      for (const s of sources) {
        const path = sideRelativePath(s.path, roots) ?? byDest.get(s.path) ?? null;
        if (path === null)
          continue;
        for (const p of s.packages) {
          for (const g of p.advisoryGroups) {
            const advisoryIds = advisoryIdsOf(g);
            const candidate = {
              advisoryIds,
              ecosystem: p.ecosystem,
              package: p.name,
              version: p.version,
              manifestPath: path,
              introduced: false
            };
            if (advisoryIds.length === 0 || !VulnFinding.safeParse(candidate).success) {
              result.coverage = worse(result.coverage, incomplete("parse_error"));
              continue;
            }
            result.vulns.push({ advisoryIds, ecosystem: p.ecosystem, package: p.name, version: p.version, manifestPath: path });
          }
          const row = { ecosystem: p.ecosystem, package: p.name, version: p.version, manifestPath: path };
          if (InventoryRow.safeParse(row).success)
            result.inventory.push(row);
        }
      }
      return true;
    };
    const outputPath = import_node_path2.join(this.work, `osv-${side}.json`);
    const all = await this.runOsv(toWrite.map((w) => w.dest), allPackages, outputPath);
    if (all.code === OSV_EXIT.clean || all.code === OSV_EXIT.vulnerable) {
      if (all.text !== null && absorb(all.text)) {
        for (const w of toWrite)
          result.manifests.set(w.path, "scanned");
        return result;
      }
      result.coverage = worse(result.coverage, failed("upstream_error"));
      return result;
    }
    if (all.code === OSV_EXIT.noPackages) {
      for (const w of toWrite)
        result.manifests.set(w.path, "scanned");
      return result;
    }
    if (all.code === OSV_EXIT.apiFailed) {
      result.coverage = worse(result.coverage, failed("osv_unreachable"));
      return result;
    }
    if (all.timedOut) {
      result.coverage = worse(result.coverage, incomplete("tool_timeout"));
      return result;
    }
    for (const w of toWrite) {
      const one = await this.runOsv([w.dest], allPackages, outputPath);
      if (one.code === OSV_EXIT.clean || one.code === OSV_EXIT.vulnerable) {
        if (one.text !== null && absorb(one.text))
          result.manifests.set(w.path, "scanned");
        else
          result.coverage = worse(result.coverage, failed("upstream_error"));
      } else if (one.code === OSV_EXIT.noPackages) {
        result.manifests.set(w.path, "scanned");
      } else if (one.code === OSV_EXIT.apiFailed) {
        result.coverage = worse(result.coverage, failed("osv_unreachable"));
        return result;
      } else if (one.timedOut) {
        result.coverage = worse(result.coverage, incomplete("tool_timeout"));
        return result;
      } else {
        result.manifests.set(w.path, "parse_error");
      }
    }
    return result;
  }
  async scanDependencies(plan, headTree) {
    const queriedAt = this.deps.now().toISOString();
    const head = await this.scanSide("head", headTree, plan.inventory);
    let base = null;
    let baseCoverage = plan.baseUnavailable ? "incomplete" : "none";
    if (plan.base !== null) {
      const baseTree = await this.git.lsTree(plan.base);
      if (baseTree === null) {
        baseCoverage = "incomplete";
      } else {
        base = await this.scanSide("base", baseTree, false);
        baseCoverage = base.coverage.coverage === "complete" ? "complete" : "incomplete";
      }
    }
    let headCoverage = head.coverage;
    for (const [path, status] of head.manifests) {
      if (status === "parse_error" && base?.manifests.get(path) !== "parse_error") {
        headCoverage = worse(headCoverage, incomplete("parse_error"));
      }
    }
    if (base !== null) {
      for (const [path, status] of base.manifests) {
        if (status === "parse_error" && head.manifests.get(path) === "scanned")
          baseCoverage = "incomplete";
      }
    }
    const findings = markIntroduced(head.vulns, baseCoverage === "complete" && base !== null ? base.vulns : null);
    const manifests = [
      ...[...head.manifests].map(([path, status]) => ({ side: "head", path, status })),
      ...[...base?.manifests ?? []].map(([path, status]) => ({ side: "base", path, status }))
    ];
    const inventory = plan.inventory ? headCoverage.coverage === "complete" ? head.inventory : "omitted" : undefined;
    return { head: headCoverage, base: baseCoverage, manifests, findings, inventory, queriedAt };
  }
  async run() {
    const { tools } = this.input;
    await this.installTools();
    const plan = await this.fetchAndPlan();
    if (plan === null) {
      this.deps.log("The commits under review could not be fetched");
      const hasBase = this.input.target.kind === "pull_request" || this.input.target.kind === "push" && this.input.target.before !== ZERO_SHA;
      return this.finish(null, {
        commits: [],
        treeScanned: false,
        secrets: { ...failed("fetch_failed"), version: tools.gitleaks.version, findings: [] },
        vulnerabilities: {
          head: failed("fetch_failed"),
          base: hasBase ? "incomplete" : "none",
          manifests: [],
          version: tools.osvScanner.version,
          queriedAt: this.deps.now().toISOString(),
          findings: []
        },
        ...this.input.target.kind === "pull_request" ? {} : { inventory: "omitted" }
      });
    }
    const headTree = await this.git.lsTree(plan.head);
    if (headTree === null) {
      return this.finish(plan, {
        commits: [],
        treeScanned: false,
        secrets: { ...failed("fetch_failed"), version: tools.gitleaks.version, findings: [] },
        vulnerabilities: {
          head: failed("fetch_failed"),
          base: plan.base !== null || plan.baseUnavailable ? "incomplete" : "none",
          manifests: [],
          version: tools.osvScanner.version,
          queriedAt: this.deps.now().toISOString(),
          findings: []
        },
        ...plan.inventory ? { inventory: "omitted" } : {}
      });
    }
    const headBlobs = new Map(headTree.filter(isRegularBlob).map((e) => [e.path, e.oid]));
    let secretsCoverage = COMPLETE;
    if (plan.rangeUnavailable)
      secretsCoverage = plan.treeScan ? incomplete("fetch_failed") : failed("fetch_failed");
    const range = await this.scanRange(plan, headBlobs);
    secretsCoverage = worse(secretsCoverage, range.coverage);
    let treeFindings = [];
    if (plan.treeScan) {
      const tree = await this.scanTree(plan, headTree);
      secretsCoverage = worse(secretsCoverage, tree.coverage);
      treeFindings = tree.findings;
    }
    const secrets = [...range.findings, ...treeFindings];
    this.deps.log(`Secrets: ${secrets.length} finding${secrets.length === 1 ? "" : "s"}, coverage ${secretsCoverage.coverage}` + (secretsCoverage.reason === "none" ? "" : ` (${secretsCoverage.reason})`));
    const deps = await this.scanDependencies(plan, headTree);
    this.deps.log(`Dependencies: ${deps.findings.length} finding${deps.findings.length === 1 ? "" : "s"}, ` + `head ${deps.head.coverage}${deps.head.reason === "none" ? "" : ` (${deps.head.reason})`}, base ${deps.base}`);
    return this.finish(plan, {
      commits: range.commits,
      treeScanned: plan.treeScan,
      secrets: { ...secretsCoverage, version: tools.gitleaks.version, findings: secrets },
      vulnerabilities: {
        head: deps.head,
        base: deps.base,
        manifests: deps.manifests,
        version: tools.osvScanner.version,
        queriedAt: deps.queriedAt,
        findings: deps.findings
      },
      ...deps.inventory === undefined ? {} : { inventory: deps.inventory }
    });
  }
  finish(plan, parts) {
    const fitted = fitBudget(buildScanOutput(parts), this.deps.sealer, this.deps.budget);
    if (fitted.shed.length > 0)
      this.deps.log(`Output over budget; shed: ${fitted.shed.join(", ")}`);
    return { ...fitted, plan };
  }
}
async function runScan(input, deps) {
  import_node_fs4.mkdirSync(input.workRoot, { recursive: true });
  const work = import_node_fs4.mkdtempSync(import_node_path2.join(input.workRoot, "jutsu-scan-"));
  import_node_fs4.chmodSync(work, 448);
  try {
    return await new Scan(input, deps, work).run();
  } finally {
    import_node_fs4.rmSync(work, { recursive: true, force: true });
  }
}
function describeCoverage(c) {
  return c.reason === "none" ? c.coverage : `${c.coverage} (${c.reason})`;
}
function githubCompare(o) {
  return async (base, head) => {
    try {
      const url = `${o.apiUrl.replace(/\/+$/, "")}/repos/${o.repository}/compare/${base}...${head}?per_page=1`;
      const res = await o.fetchImpl(url, {
        headers: {
          Authorization: `Bearer ${o.token}`,
          Accept: "application/vnd.github+json",
          "X-GitHub-Api-Version": "2022-11-28",
          "User-Agent": "jutsu-security-scan"
        },
        signal: AbortSignal.timeout(60000)
      });
      if (!res.ok)
        return null;
      const body = await res.json();
      const mergeBase = body.merge_base_commit?.sha;
      if (typeof mergeBase !== "string" || !/^[0-9a-f]{40}$/.test(mergeBase))
        return null;
      return { mergeBase, totalCommits: typeof body.total_commits === "number" ? body.total_commits : -1 };
    } catch {
      return null;
    }
  };
}

// apps/github-scan-action/src/scanJob.ts
var REPOSITORY = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;
var DECIMAL = /^[1-9]\d{0,19}$/;
async function scanJob(env, io = {}) {
  const log = io.log ?? ((line) => {
    process.stdout.write(`${line}
`);
  });
  let event = null;
  try {
    event = JSON.parse(import_node_fs5.readFileSync(env.GITHUB_EVENT_PATH ?? "", "utf8"));
  } catch {
    event = null;
  }
  const target = readTarget(env.GITHUB_EVENT_NAME, event, env);
  if (target.kind === "unsupported") {
    log(`Jutsu Security: nothing to scan: ${target.why}.`);
    return 0;
  }
  const outputFile = env.GITHUB_OUTPUT;
  if (outputFile === undefined || outputFile.length === 0) {
    log("Jutsu Security: GITHUB_OUTPUT is not set, so the scan has nowhere to put its result.");
    return 1;
  }
  const repository = env.GITHUB_REPOSITORY ?? "";
  if (!REPOSITORY.test(repository)) {
    log("Jutsu Security: GITHUB_REPOSITORY is not <owner>/<repository>.");
    return 1;
  }
  const reportKey = parseReportPublicKey(env.INPUT_REPORT_KEY);
  if (reportKey === null) {
    log("Jutsu Security: the report_key input is missing or is not a 32-byte base64 key. " + "Use the workflow file from the Jutsu console unchanged; nothing was scanned.");
    return 1;
  }
  const run = { repositoryId: env.GITHUB_REPOSITORY_ID ?? "", runId: env.GITHUB_RUN_ID ?? "" };
  if (!DECIMAL.test(run.repositoryId) || !DECIMAL.test(run.runId)) {
    log("Jutsu Security: GITHUB_REPOSITORY_ID or GITHUB_RUN_ID is not set; nothing was scanned.");
    return 1;
  }
  const aad = sealAad(run);
  const root = io.actionRoot ?? import_node_path3.resolve(import_node_path3.dirname(process.argv[1] ?? "."), "..");
  const tools = parseToolsManifest(JSON.parse(import_node_fs5.readFileSync(import_node_path3.join(root, "tools.json"), "utf8")));
  const server = (env.GITHUB_SERVER_URL ?? "https://github.com").replace(/\/+$/, "");
  const token = env.INPUT_TOKEN ?? "";
  if (token.length > 0) {
    log(`::add-mask::${basicAuthValue(token).slice("basic ".length)}`);
  }
  const fetchImpl = io.fetch ?? fetch;
  const scanned = await runScan({
    target,
    remoteUrl: io.remoteUrl ?? `${server}/${repository}`,
    auth: token.length > 0 ? { serverUrl: server, token } : null,
    workRoot: env.RUNNER_TEMP ?? import_node_os.tmpdir(),
    gitleaksConfigPath: import_node_path3.join(root, "gitleaks.toml"),
    tools,
    ...io.toolPaths === undefined ? {} : { toolPaths: io.toolPaths },
    parentEnv: env
  }, {
    runner: io.runner ?? nodeRunner,
    fetch: fetchImpl,
    compare: io.compare ?? githubCompare({ apiUrl: env.GITHUB_API_URL ?? "https://api.github.com", repository, token, fetchImpl }),
    now: () => new Date,
    log,
    sealer: (gzipped) => seal(gzipped, reportKey, aad)
  });
  import_node_fs5.appendFileSync(outputFile, scanned.chunks.map((c, i) => `report_${i}=${c}
`).join(""));
  const o = scanned.output;
  log(`Jutsu Security: secrets ${describeCoverage(o.secrets)}, ${o.secrets.findings.length} finding(s); ` + `dependencies ${describeCoverage({ coverage: o.vulnerabilities.coverage.head, reason: o.vulnerabilities.reason.head })}, ` + `${o.vulnerabilities.findings.length} finding(s). The result is encrypted to Jutsu's key (${reportKey.kid}) ` + "before it leaves this job; the report job forwards it without reading it.");
  return 0;
}

// apps/github-scan-action/src/scan.ts
scanJob(process.env).then((code) => {
  process.exitCode = code;
}, (err) => {
  process.stdout.write(`Jutsu Security: the scan failed: ${err instanceof Error ? err.message : String(err)}
`);
  process.exitCode = 1;
});
