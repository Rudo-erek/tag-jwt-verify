import { constants, createPublicKey, generateKeyPairSync, randomUUID, sign, verify } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

export const VERSION = '0.2.0';
export const DEFAULT_ISSUER = 'https://ai.feishu.cn';
export const DEFAULT_JWKS = 'https://ai.feishu.cn/v1/openapi/federation/jwks.json';
export const DEFAULT_TYPE = 'tag-identity+jwt';
export const MAX_TOKEN_BYTES = 64 * 1024;
const MAX_KEY_BYTES = 1024 * 1024;

export class VerificationError extends Error {
  constructor(code, message, exitCode = 1) {
    super(message);
    this.code = code;
    this.exitCode = exitCode;
  }
}

function fail(code, message, exitCode = 1) {
  throw new VerificationError(code, message, exitCode);
}

export async function readLimited(stream, limit, code = 'INPUT_TOO_LARGE') {
  const chunks = [];
  let size = 0;
  for await (const chunk of stream) {
    const bytes = Buffer.from(chunk);
    size += bytes.length;
    if (size > limit) fail(code, 'Input exceeds the size limit.', 2);
    chunks.push(bytes);
  }
  return Buffer.concat(chunks).toString('utf8');
}

function parseObject(text, code) {
  let value;
  try { value = JSON.parse(text); } catch { fail(code, 'Invalid JSON object.'); }
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    fail(code, 'Expected a JSON object.');
  }
  return value;
}

function decodeSegment(segment) {
  if (!/^[A-Za-z0-9_-]+$/.test(segment)) fail('INVALID_JWT', 'Invalid JWT encoding.');
  const bytes = Buffer.from(segment, 'base64url');
  if (bytes.toString('base64url') !== segment) fail('INVALID_JWT', 'Invalid JWT encoding.');
  return bytes;
}

function decodeJWTParts(token) {
  if (typeof token !== 'string' || !token.trim()) fail('MISSING_TOKEN', 'TAG_IDENTITY or stdin must contain a JWT.', 2);
  if (Buffer.byteLength(token) > MAX_TOKEN_BYTES) fail('INVALID_JWT', 'JWT exceeds the size limit.');
  const parts = token.trim().split('.');
  if (parts.length !== 3) fail('INVALID_JWT', 'Expected a signed JWT with three segments.');
  const [encodedHeader, encodedClaims, encodedSignature] = parts;
  const header = parseObject(decodeSegment(encodedHeader).toString('utf8'), 'INVALID_JWT');
  const claims = parseObject(decodeSegment(encodedClaims).toString('utf8'), 'INVALID_JWT');
  const signature = decodeSegment(encodedSignature);
  return { encodedHeader, encodedClaims, header, claims, signature };
}

function formatUnixIso(value) {
  return Number.isSafeInteger(value) ? new Date(value * 1000).toISOString() : null;
}

export function buildTimingInfo(claims, nowSeconds = Math.floor(Date.now() / 1000)) {
  const exp = Number.isSafeInteger(claims.exp) ? claims.exp : null;
  const nbf = Number.isSafeInteger(claims.nbf) ? claims.nbf : null;
  const iat = Number.isSafeInteger(claims.iat) ? claims.iat : null;
  const ttlSeconds = exp !== null ? exp - nowSeconds : null;
  const expired = exp !== null ? nowSeconds >= exp : null;
  const active = (nbf === null || nowSeconds >= nbf) && (expired === null ? true : !expired);
  return {
    now: nowSeconds,
    issued_at: iat,
    issued_at_iso: formatUnixIso(iat),
    not_before: nbf,
    not_before_iso: formatUnixIso(nbf),
    expires_at: exp,
    expires_at_iso: formatUnixIso(exp),
    ttl_seconds: ttlSeconds,
    active,
    expired,
  };
}

export function parseJWT(token) {
  const { header, claims, signature } = decodeJWTParts(token);
  return {
    verified: false,
    warning: 'Signature is NOT verified by parse/decode. Use "verify" for cryptographic validation.',
    header,
    claims,
    timing: buildTimingInfo(claims),
    signature_bytes: signature.length,
  };
}

export function inspectEnvToken(rawToken = process.env.TAG_IDENTITY) {
  const base = {
    node_version: process.versions.node,
    env_var: 'TAG_IDENTITY',
    present: typeof rawToken === 'string' && rawToken.length > 0,
    non_empty: typeof rawToken === 'string' && rawToken.trim().length > 0,
    byte_length: typeof rawToken === 'string' ? Buffer.byteLength(rawToken) : 0,
  };
  if (!base.non_empty) {
    return { ...base, well_formed_jwt: false, error: 'MISSING_TOKEN', message: 'TAG_IDENTITY is unset or empty.' };
  }
  const trimmed = rawToken.trim();
  const segmentCount = trimmed.split('.').length;
  try {
    const parsed = parseJWT(trimmed);
    return {
      ...base,
      segment_count: segmentCount,
      well_formed_jwt: true,
      summary: {
        alg: parsed.header.alg ?? null,
        typ: parsed.header.typ ?? null,
        kid: parsed.header.kid ?? null,
        iss: parsed.claims.iss ?? null,
        aud: parsed.claims.aud ?? null,
        sub: parsed.claims.sub ?? null,
        jti: parsed.claims.jti ?? null,
        timing: parsed.timing,
      },
    };
  } catch (error) {
    return {
      ...base,
      segment_count: segmentCount,
      well_formed_jwt: false,
      error: error instanceof VerificationError ? error.code : 'INVALID_JWT',
      message: error instanceof VerificationError ? error.message : 'TAG_IDENTITY is not a valid 3-part JWT.',
    };
  }
}

async function readKeyFile(path) {
  try { return await readLimited(createReadStream(path), MAX_KEY_BYTES); }
  catch (error) {
    if (error instanceof VerificationError) throw error;
    fail('KEY_FILE_ERROR', 'Cannot read the public key file.', 2);
  }
}

async function fetchJWKS(address, timeout, usePpe = true) {
  let url;
  try { url = new URL(address); } catch { fail('INVALID_JWKS_URL', 'Invalid JWKS URL.', 2); }
  if (url.protocol !== 'https:' || url.username || url.password || url.hash) {
    fail('INVALID_JWKS_URL', 'JWKS must use HTTPS without credentials or a fragment.', 2);
  }
  const headers = { accept: 'application/jwk-set+json, application/json' };
  if (usePpe) {
    headers['x-use-ppe'] = '1';
    headers['X-TT-ENV'] = 'ppe_tag_jwt_identity';
  }
  try {
    // Only the operator-selected URL is used; JWT jku/x5u/jwk headers are never trusted.
    const response = await fetch(url, {
      redirect: 'error',
      signal: AbortSignal.timeout(timeout),
      headers,
    });
    if (!response.ok || !response.body) {
      await response.body?.cancel();
      fail('JWKS_HTTP_ERROR', `JWKS request failed (HTTP ${response.status}).`, 2);
    }
    return parseObject(await readLimited(response.body, MAX_KEY_BYTES), 'INVALID_JWKS');
  } catch (error) {
    if (error instanceof VerificationError) throw error;
    fail('JWKS_FETCH_FAILED', 'Cannot fetch JWKS: check the HTTPS endpoint, TLS and network.', 2);
  }
}

function validateJwkForRS256(jwk) {
  if (!jwk || typeof jwk !== 'object' ||
      jwk.kty !== 'RSA' || typeof jwk.n !== 'string' || typeof jwk.e !== 'string' ||
      (jwk.alg !== undefined && jwk.alg !== 'RS256') ||
      (jwk.use !== undefined && jwk.use !== 'sig') ||
      (jwk.key_ops !== undefined && (!Array.isArray(jwk.key_ops) || !jwk.key_ops.includes('verify'))) ||
      ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth'].some((name) => name in jwk)) {
    fail('INVALID_PUBLIC_KEY', 'JWKS key is not an RS256 verification public key.', 2);
  }
  let key;
  try { key = createPublicKey({ key: { kty: 'RSA', n: jwk.n, e: jwk.e }, format: 'jwk' }); }
  catch { fail('INVALID_PUBLIC_KEY', 'Cannot parse the RSA public key.', 2); }
  if (key.asymmetricKeyType !== 'rsa' || !(key.asymmetricKeyDetails?.modulusLength >= 2048)) {
    fail('INVALID_PUBLIC_KEY', 'RS256 requires an RSA public key of at least 2048 bits.', 2);
  }
  return key;
}

async function loadPublicKey(header, options) {
  let key;
  if (options.publicKey) {
    const pem = await readKeyFile(options.publicKey);
    if (!/^-----BEGIN (RSA )?PUBLIC KEY-----/.test(pem.trim())) {
      fail('INVALID_PUBLIC_KEY', 'Expected a PEM public key, not a private key.', 2);
    }
    try { key = createPublicKey(pem); }
    catch { fail('INVALID_PUBLIC_KEY', 'Cannot parse the PEM public key.', 2); }
    if (key.asymmetricKeyType !== 'rsa' || !(key.asymmetricKeyDetails?.modulusLength >= 2048)) {
      fail('INVALID_PUBLIC_KEY', 'RS256 requires an RSA public key of at least 2048 bits.', 2);
    }
    return key;
  }
  const jwks = options.jwksFile
    ? parseObject(await readKeyFile(options.jwksFile), 'INVALID_JWKS')
    : await fetchJWKS(options.jwksUrl, options.timeout, options.usePpe !== false);
  if (!Array.isArray(jwks.keys) || jwks.keys.length > 100) {
    fail('INVALID_JWKS', 'JWKS must contain at most 100 keys.', 2);
  }
  const keys = jwks.keys.filter((item) => item && item.kid === header.kid);
  if (keys.length !== 1) fail('KEY_NOT_FOUND', 'Expected exactly one public key matching kid.');
  return validateJwkForRS256(keys[0]);
}

export async function inspectJWKS(input = {}) {
  const options = { jwksUrl: DEFAULT_JWKS, timeout: 10000, usePpe: true, ...input };
  if (!Number.isInteger(options.timeout) || options.timeout < 1 || options.timeout > 60000) {
    fail('INVALID_OPTIONS', 'Timeout must be 1–60000 ms.', 2);
  }
  const started = Date.now();
  const jwks = options.jwksFile
    ? parseObject(await readKeyFile(options.jwksFile), 'INVALID_JWKS')
    : await fetchJWKS(options.jwksUrl, options.timeout, options.usePpe !== false);
  const latencyMs = Date.now() - started;
  if (!Array.isArray(jwks.keys) || jwks.keys.length > 100) {
    fail('INVALID_JWKS', 'JWKS must contain at most 100 keys.', 2);
  }
  const summaries = jwks.keys.map((item, index) => {
    try {
      const key = validateJwkForRS256(item);
      return {
        index,
        kid: item?.kid ?? null,
        kty: item?.kty ?? null,
        alg: item?.alg ?? 'RS256',
        use: item?.use ?? 'sig',
        modulus_bits: key.asymmetricKeyDetails?.modulusLength ?? null,
        valid_rs256: true,
      };
    } catch (error) {
      return {
        index,
        kid: item?.kid ?? null,
        kty: item?.kty ?? null,
        alg: item?.alg ?? null,
        use: item?.use ?? null,
        valid_rs256: false,
        error: error instanceof VerificationError ? error.code : 'INVALID_PUBLIC_KEY',
      };
    }
  });
  const result = {
    ok: summaries.length > 0 && summaries.every((item) => item.valid_rs256),
    source: options.jwksFile ? { type: 'file', path: options.jwksFile } : { type: 'https', url: options.jwksUrl, ppe_headers: options.usePpe !== false },
    latency_ms: latencyMs,
    key_count: summaries.length,
    keys: summaries,
  };
  if (options.kid) {
    const matches = summaries.filter((item) => item.kid === options.kid && item.valid_rs256);
    result.target_kid = options.kid;
    result.kid_matched = matches.length === 1;
    if (matches.length !== 1) result.ok = false;
  }
  return result;
}

export async function verifyJWT(token, input) {
  const options = {
    issuer: DEFAULT_ISSUER, jwksUrl: DEFAULT_JWKS, type: DEFAULT_TYPE,
    tolerance: 0, timeout: 10000, usePpe: true, ...input,
  };
  if (!options.audience || typeof options.audience !== 'string' ||
      !options.issuer || typeof options.issuer !== 'string' ||
      !options.type || typeof options.type !== 'string') {
    fail('INVALID_OPTIONS', 'Expected audience, issuer and JWT type are required.', 2);
  }
  if (!Number.isInteger(options.tolerance) || options.tolerance < 0 || options.tolerance > 300 ||
      !Number.isInteger(options.timeout) || options.timeout < 1 || options.timeout > 60000) {
    fail('INVALID_OPTIONS', 'Clock tolerance must be 0–300 seconds; timeout must be 1–60000 ms.', 2);
  }
  const { encodedHeader, encodedClaims, header, claims, signature } = decodeJWTParts(token);
  if (header.alg !== 'RS256') fail('UNSUPPORTED_ALGORITHM', 'Only RS256 is accepted.');
  if (header.typ !== options.type) fail('TYPE_MISMATCH', 'JWT type does not match the expected type.');
  if (typeof header.kid !== 'string' || !header.kid) fail('INVALID_JWT', 'JWT header must contain kid.');
  if ('crit' in header || 'b64' in header) fail('UNSUPPORTED_HEADER', 'Critical or unencoded-payload headers are not supported.');
  const key = await loadPublicKey(header, options);
  let validSignature;
  try {
    validSignature = verify('RSA-SHA256', Buffer.from(`${encodedHeader}.${encodedClaims}`), {
      key, padding: constants.RSA_PKCS1_PADDING,
    }, signature);
  } catch { fail('SIGNATURE_INVALID', 'JWT signature verification failed.'); }
  if (!validSignature) fail('SIGNATURE_INVALID', 'JWT signature verification failed.');
  if (claims.iss !== options.issuer) fail('ISSUER_MISMATCH', 'JWT issuer does not match the expected issuer.');
  const audiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (!audiences.length || !audiences.every((aud) => typeof aud === 'string' && aud.length > 0) ||
      !audiences.includes(options.audience)) {
    fail('AUDIENCE_MISMATCH', 'JWT audience does not match the expected audience.');
  }
  const now = Date.now() / 1000;
  for (const name of ['exp', 'nbf', 'iat']) {
    if ((name === 'exp' || name in claims) && !Number.isSafeInteger(claims[name])) {
      fail('INVALID_TIME', 'JWT time claims must be integer Unix timestamps; exp is required.');
    }
  }
  if (now >= claims.exp + options.tolerance) fail('TOKEN_EXPIRED', 'JWT has expired.');
  if (claims.nbf !== undefined && now + options.tolerance < claims.nbf) fail('TOKEN_NOT_ACTIVE', 'JWT is not active yet.');
  if (claims.iat !== undefined && now + options.tolerance < claims.iat) fail('ISSUED_IN_FUTURE', 'JWT was issued in the future.');
  if ((claims.iat !== undefined && claims.exp <= claims.iat) ||
      (claims.nbf !== undefined && claims.exp <= claims.nbf)) fail('INVALID_TIME', 'JWT has an invalid validity interval.');
  if (options.subject !== undefined && claims.sub !== options.subject) {
    fail('SUBJECT_MISMATCH', 'JWT subject does not match the expected subject.');
  }
  return { header, claims };
}

export function generateMockBundle(input = {}) {
  const audience = input.audience || 'mock_plugin/mock_connector';
  const issuer = input.issuer || DEFAULT_ISSUER;
  const subject = input.subject || 'wimse://ai.feishu.cn/tenant/mock_tenant/agent/mock_agent';
  const kid = input.kid || `mock-key-${randomUUID().slice(0, 8)}`;
  const type = input.type || DEFAULT_TYPE;
  const ttlSeconds = input.ttlSeconds ?? 300;
  if (!Number.isInteger(ttlSeconds) || ttlSeconds < 1 || ttlSeconds > 86400) {
    fail('INVALID_OPTIONS', 'TTL must be between 1 and 86400 seconds.', 2);
  }
  const now = Math.floor(Date.now() / 1000);
  const iat = input.expired ? now - ttlSeconds - 60 : now;
  const nbf = iat - 5;
  const exp = input.expired ? now - 60 : now + ttlSeconds;

  const pair = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = { ...pair.publicKey.export({ format: 'jwk' }), kid, alg: 'RS256', use: 'sig' };
  const publicKeyPem = pair.publicKey.export({ type: 'spki', format: 'pem' }).toString();
  const header = { alg: 'RS256', typ: type, kid };
  const claims = {
    iss: issuer,
    aud: audience,
    sub: subject,
    iat,
    nbf,
    exp,
    jti: `mock-${randomUUID()}`,
    tenant_key: 'mock_tenant',
    lark_user_id: 'ou_mock_user',
  };
  const signingInput = [header, claims].map((v) => Buffer.from(JSON.stringify(v)).toString('base64url')).join('.');
  const sig = sign('RSA-SHA256', Buffer.from(signingInput), pair.privateKey).toString('base64url');
  return {
    test_only: true,
    header,
    claims,
    token: `${signingInput}.${sig}`,
    jwks: { keys: [jwk] },
    public_key_pem: publicKeyPem,
  };
}

export async function runSelfTest() {
  const started = Date.now();
  const dir = await mkdtemp(join(tmpdir(), 'tag-jwt-selftest-'));
  try {
    const bundle = generateMockBundle();
    const jwksFile = join(dir, 'jwks.json');
    await writeFile(jwksFile, JSON.stringify(bundle.jwks));
    const checks = [];

    const parsed = parseJWT(bundle.token);
    if (parsed.verified !== false || parsed.claims.aud !== bundle.claims.aud || parsed.header.kid !== bundle.header.kid) {
      fail('SELFTEST_FAILED', 'parseJWT failed to decode synthetic token.', 1);
    }
    checks.push({ name: 'parse_valid_jwt', passed: true });

    const verified = await verifyJWT(bundle.token, { audience: bundle.claims.aud, jwksFile });
    if (verified.claims.jti !== bundle.claims.jti) {
      fail('SELFTEST_FAILED', 'verifyJWT failed on valid synthetic token.', 1);
    }
    checks.push({ name: 'verify_valid_jwt', passed: true });

    const parts = bundle.token.split('.');
    const sigBytes = Buffer.from(parts[2], 'base64url');
    sigBytes[0] ^= 0xff;
    parts[2] = sigBytes.toString('base64url');
    let rejectedTampered = false;
    try { await verifyJWT(parts.join('.'), { audience: bundle.claims.aud, jwksFile }); }
    catch (err) { rejectedTampered = err instanceof VerificationError && err.code === 'SIGNATURE_INVALID'; }
    if (!rejectedTampered) fail('SELFTEST_FAILED', 'Tampered signature was not rejected.', 1);
    checks.push({ name: 'reject_tampered_signature', passed: true });

    let rejectedAud = false;
    try { await verifyJWT(bundle.token, { audience: 'wrong/audience', jwksFile }); }
    catch (err) { rejectedAud = err instanceof VerificationError && err.code === 'AUDIENCE_MISMATCH'; }
    if (!rejectedAud) fail('SELFTEST_FAILED', 'Mismatched audience was not rejected.', 1);
    checks.push({ name: 'reject_audience_mismatch', passed: true });

    const expiredBundle = generateMockBundle({ expired: true, kid: bundle.header.kid });
    const expiredJwksFile = join(dir, 'expired-jwks.json');
    await writeFile(expiredJwksFile, JSON.stringify(expiredBundle.jwks));
    let rejectedExpired = false;
    try { await verifyJWT(expiredBundle.token, { audience: expiredBundle.claims.aud, jwksFile: expiredJwksFile }); }
    catch (err) { rejectedExpired = err instanceof VerificationError && err.code === 'TOKEN_EXPIRED'; }
    if (!rejectedExpired) fail('SELFTEST_FAILED', 'Expired token was not rejected.', 1);
    checks.push({ name: 'reject_expired_token', passed: true });

    return {
      ok: true,
      version: VERSION,
      node_version: process.versions.node,
      duration_ms: Date.now() - started,
      passed: checks.length,
      checks,
    };
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}
