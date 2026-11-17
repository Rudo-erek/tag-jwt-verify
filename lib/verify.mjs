import { constants, createPublicKey, verify } from 'node:crypto';
import { createReadStream } from 'node:fs';

export const DEFAULT_ISSUER = 'https://tag.feishu.cn';
export const DEFAULT_JWKS = 'https://ai.feishu.cn/v1/openapi/federation/jwks.json';
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

async function readKeyFile(path) {
  try { return await readLimited(createReadStream(path), MAX_KEY_BYTES); }
  catch (error) {
    if (error instanceof VerificationError) throw error;
    fail('KEY_FILE_ERROR', 'Cannot read the public key file.', 2);
  }
}

async function fetchJWKS(address, timeout) {
  let url;
  try { url = new URL(address); } catch { fail('INVALID_JWKS_URL', 'Invalid JWKS URL.', 2); }
  if (url.protocol !== 'https:' || url.username || url.password || url.hash) {
    fail('INVALID_JWKS_URL', 'JWKS must use HTTPS without credentials or a fragment.', 2);
  }
  try {
    // Only the operator-selected URL is used; JWT jku/x5u/jwk headers are never trusted.
    const response = await fetch(url, {
      redirect: 'error',
      signal: AbortSignal.timeout(timeout),
      headers: { accept: 'application/jwk-set+json, application/json' },
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

async function loadPublicKey(header, options) {
  let key;
  if (options.publicKey) {
    const pem = await readKeyFile(options.publicKey);
    if (!/^-----BEGIN (RSA )?PUBLIC KEY-----/.test(pem.trim())) {
      fail('INVALID_PUBLIC_KEY', 'Expected a PEM public key, not a private key.', 2);
    }
    try { key = createPublicKey(pem); }
    catch { fail('INVALID_PUBLIC_KEY', 'Cannot parse the PEM public key.', 2); }
  } else {
    const jwks = options.jwksFile
      ? parseObject(await readKeyFile(options.jwksFile), 'INVALID_JWKS')
      : await fetchJWKS(options.jwksUrl, options.timeout);
    if (!Array.isArray(jwks.keys) || jwks.keys.length > 100) {
      fail('INVALID_JWKS', 'JWKS must contain at most 100 keys.', 2);
    }
    const keys = jwks.keys.filter((item) => item && item.kid === header.kid);
    if (keys.length !== 1) fail('KEY_NOT_FOUND', 'Expected exactly one public key matching kid.');
    const jwk = keys[0];
    if (jwk.kty !== 'RSA' || typeof jwk.n !== 'string' || typeof jwk.e !== 'string' ||
        (jwk.alg !== undefined && jwk.alg !== 'RS256') ||
        (jwk.use !== undefined && jwk.use !== 'sig') ||
        (jwk.key_ops !== undefined && (!Array.isArray(jwk.key_ops) || !jwk.key_ops.includes('verify'))) ||
        ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth'].some((name) => name in jwk)) {
      fail('INVALID_PUBLIC_KEY', 'JWKS key is not an RS256 verification public key.', 2);
    }
    try { key = createPublicKey({ key: { kty: 'RSA', n: jwk.n, e: jwk.e }, format: 'jwk' }); }
    catch { fail('INVALID_PUBLIC_KEY', 'Cannot parse the RSA public key.', 2); }
  }
  if (key.asymmetricKeyType !== 'rsa' || !(key.asymmetricKeyDetails?.modulusLength >= 2048)) {
    fail('INVALID_PUBLIC_KEY', 'RS256 requires an RSA public key of at least 2048 bits.', 2);
  }
  return key;
}

export async function verifyJWT(token, input) {
  const options = {
    issuer: DEFAULT_ISSUER, jwksUrl: DEFAULT_JWKS, type: 'tag-identity+jwt',
    tolerance: 0, timeout: 10000, ...input,
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
  if (typeof token !== 'string' || !token.trim()) fail('MISSING_TOKEN', 'TAG_IDENTITY or stdin must contain a JWT.', 2);
  if (Buffer.byteLength(token) > MAX_TOKEN_BYTES) fail('INVALID_JWT', 'JWT exceeds the size limit.');
  const parts = token.trim().split('.');
  if (parts.length !== 3) fail('INVALID_JWT', 'Expected a signed JWT with three segments.');
  const [encodedHeader, encodedClaims, encodedSignature] = parts;
  const header = parseObject(decodeSegment(encodedHeader).toString('utf8'), 'INVALID_JWT');
  const claims = parseObject(decodeSegment(encodedClaims).toString('utf8'), 'INVALID_JWT');
  const signature = decodeSegment(encodedSignature);
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
