// The policy flags are opt-in. CLI argument validation applies to every run.

export interface Policy {
  /** Hide authoring tools and suppress script variable persistence. */
  readOnly: boolean;
  /** Hide execution headers and mask common credential patterns. */
  redact: boolean;
  /** Cap response bodies returned to the caller; 0 = no cap. */
  maxBodyChars: number;
  /** Environments exempt from the declared-method check; null disables the check. */
  mutationEnvs: string[] | null;
  /** Limit access to registered collections and workspaces and confine data files to their collection. */
  strictScope: boolean;
}

const DEFAULT_POLICY: Policy = { readOnly: false, redact: false, maxBodyChars: 0, mutationEnvs: null, strictScope: false };

let current: Policy = { ...DEFAULT_POLICY };

export const setPolicy = (policy: Partial<Policy>): void => {
  current = { ...DEFAULT_POLICY, ...policy };
};

export const getPolicy = (): Policy => current;

export const REDACTED = '<redacted>';

const SENSITIVE_KEY = /token|secret|password|passwd|authorization|cookie|session|api[-_]?key|jwt|bearer|credential|private[-_]?key/i;
const JWT = /\beyJ[\w-]+\.[\w-]+\.[\w-]*/g;
const BEARER = /\b(Bearer|Basic)\s+[\w.~+/=-]+/gi;

export const isSensitiveKey = (key: string): boolean => SENSITIVE_KEY.test(key);

const QUERY_SECRET = /([?&][^=&\s]*(?:token|secret|password|api[-_]?key|signature|session|auth)[^=&\s]*=)[^&\s#"]+/gi;

export const maskString = (text: string): string =>
  text.replace(JWT, REDACTED).replace(BEARER, `$1 ${REDACTED}`).replace(QUERY_SECRET, `$1${REDACTED}`);

// Deep copy with secrets removed: sensitive keys, {name, value} pairs whose name is sensitive
// (Bruno headers/vars), and JWT/Bearer-looking strings anywhere.
export const redactDeep = (value: unknown): unknown => {
  if (typeof value === 'string') return maskString(value);
  if (Array.isArray(value)) return value.map(redactDeep);
  if (value && typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    const namedSecret = typeof obj.name === 'string' && isSensitiveKey(obj.name);
    const out: Record<string, unknown> = {};
    for (const [key, val] of Object.entries(obj)) {
      if (isSensitiveKey(key) || (namedSecret && key === 'value')) out[key] = val == null ? val : REDACTED;
      else out[key] = redactDeep(val);
    }
    return out;
  }
  return value;
};

// Headers are dropped except content-type: they carry Authorization, Set-Cookie and session ids.
export const redactHeaders = (headers: unknown): unknown => {
  if (!headers || typeof headers !== 'object') return headers ?? null;
  const out: Record<string, unknown> = {};
  for (const [key, val] of Object.entries(headers as Record<string, unknown>)) {
    if (key.toLowerCase() === 'content-type') out[key] = val;
  }
  return out;
};

const capBody = (text: string, max: number): string =>
  max > 0 && text.length > max ? `${text.slice(0, max)}…[truncated ${text.length - max} chars]` : text;

export const redactBody = (body: string | null): string | null => {
  if (body == null) return body;
  const { redact, maxBodyChars } = current;
  let text = body;
  if (redact) {
    try {
      text = JSON.stringify(redactDeep(JSON.parse(body)));
    } catch (_) {
      text = maskString(body);
    }
  }
  return capBody(text, maxBodyChars);
};

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

export const requiresAllowedEnvironment = (method: string | null | undefined): boolean =>
  !SAFE_METHODS.has(String(method || '').toUpperCase());

// null when allowed, else the reason. A missing environment counts as not allowed.
export const mutationBlockedReason = (environment: string | undefined, findRestricted: () => string[]): string | null => {
  const { mutationEnvs } = current;
  if (mutationEnvs === null || (environment && mutationEnvs.includes(environment))) return null;
  const restricted = findRestricted();
  if (restricted.length === 0) return null;
  return (
    `Refused by the declared-method check in environment "${environment ?? '(none)'}": ${restricted.join(', ')}. ` +
    `Methods other than GET, HEAD, and OPTIONS, including unknown methods, require an allowed environment: ${mutationEnvs.join(', ') || '(none)'}.`
  );
};

// Every value placed in `bru run` argv must not be readable as an option (e.g. "--sandbox=developer").
export const assertSafeArg = (value: string, what: string): void => {
  if (value.startsWith('-')) {
    throw new Error(`${what} must not start with "-": ${value}`);
  }
};
