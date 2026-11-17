import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { DEFAULT_ISSUER, verifyJWT } from '../lib/verify.mjs';

const pair = generateKeyPairSync('rsa', { modulusLength: 2048 });
const jwk = { ...pair.publicKey.export({ format: 'jwk' }), kid: 'fixture-key', alg: 'RS256', use: 'sig' };
const audience = 'example_plugin/example_connector';
const header = { alg: 'RS256', typ: 'tag-identity+jwt', kid: jwk.kid };
const now = Math.floor(Date.now() / 1000);
const baseClaims = { iss: DEFAULT_ISSUER, aud: audience, sub: 'urn:test:agent', iat: now, nbf: now - 60, exp: now + 300, jti: 'fixture', lark_user_id: 'fixture-user' };

function token(claims = baseClaims, tokenHeader = header, privateKey = pair.privateKey) {
  const input = [tokenHeader, claims].map((value) => Buffer.from(JSON.stringify(value)).toString('base64url')).join('.');
  return `${input}.${sign('RSA-SHA256', Buffer.from(input), privateKey).toString('base64url')}`;
}

async function fixture(t, keys = [jwk]) {
  const dir = await mkdtemp(join(tmpdir(), 'tag-jwt-test-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const jwksFile = join(dir, 'jwks.json');
  await writeFile(jwksFile, JSON.stringify({ keys }));
  return { dir, options: { audience, jwksFile } };
}

test('verify a signed identity and preserve verified claims', async (t) => {
  const { options } = await fixture(t);
  const result = await verifyJWT(token(), options);
  assert.deepEqual(result.claims, baseClaims);
  await verifyJWT(token({ ...baseClaims, aud: ['other', audience] }), options);
  await verifyJWT(token(), { ...options, subject: baseClaims.sub });
});

test('reject invalid signatures, claims and header confusion', async (t) => {
  const { options } = await fixture(t);
  const wrongPair = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const cases = [
    ['wrong key', token(baseClaims, header, wrongPair.privateKey), {}, 'SIGNATURE_INVALID'],
    ['wrong issuer', token({ ...baseClaims, iss: 'https://attacker.invalid' }), {}, 'ISSUER_MISMATCH'],
    ['wrong audience', token({ ...baseClaims, aud: 'other' }), {}, 'AUDIENCE_MISMATCH'],
    ['mixed audience types', token({ ...baseClaims, aud: [audience, 7] }), {}, 'AUDIENCE_MISMATCH'],
    ['expired', token({ ...baseClaims, iat: now - 30, exp: now - 1 }), {}, 'TOKEN_EXPIRED'],
    ['future nbf', token({ ...baseClaims, nbf: now + 60 }), {}, 'TOKEN_NOT_ACTIVE'],
    ['future iat', token({ ...baseClaims, iat: now + 60 }), {}, 'ISSUED_IN_FUTURE'],
    ['no expiry', token({ ...baseClaims, exp: undefined }), {}, 'INVALID_TIME'],
    ['string expiry', token({ ...baseClaims, exp: String(now + 300) }), {}, 'INVALID_TIME'],
    ['invalid interval', token({ ...baseClaims, iat: now - 60, nbf: now - 120, exp: now - 61 }), { tolerance: 300 }, 'INVALID_TIME'],
    ['wrong subject', token(), { subject: 'urn:other:agent' }, 'SUBJECT_MISMATCH'],
    ['exchange JWT', token(baseClaims, { ...header, typ: 'tag-exchange+jwt' }), {}, 'TYPE_MISMATCH'],
    ['alg none', token(baseClaims, { ...header, alg: 'none' }), {}, 'UNSUPPORTED_ALGORITHM'],
    ['HMAC confusion', token(baseClaims, { ...header, alg: 'HS256' }), {}, 'UNSUPPORTED_ALGORITHM'],
    ['critical header', token(baseClaims, { ...header, crit: ['custom'] }), {}, 'UNSUPPORTED_HEADER'],
    ['missing kid', token(baseClaims, { ...header, kid: undefined }), {}, 'INVALID_JWT'],
    ['unknown kid', token(baseClaims, { ...header, kid: 'unknown' }), {}, 'KEY_NOT_FOUND'],
    ['empty JWT', '', {}, 'MISSING_TOKEN'],
    ['malformed JWT', 'abc.def', {}, 'INVALID_JWT'],
    ['oversized JWT', 'a'.repeat(65537), {}, 'INVALID_JWT'],
    ['missing audience', token(), { audience: undefined }, 'INVALID_OPTIONS'],
    ['negative tolerance', token(), { tolerance: -1 }, 'INVALID_OPTIONS'],
  ];
  for (const [name, value, changes, code] of cases) {
    await t.test(name, () => assert.rejects(verifyJWT(value, { ...options, ...changes }), { code }));
  }
  const parts = token().split('.');
  const signature = Buffer.from(parts[2], 'base64url');
  signature[0] ^= 1;
  parts[2] = signature.toString('base64url');
  await assert.rejects(verifyJWT(parts.join('.'), options), { code: 'SIGNATURE_INVALID' });
});

test('PEM and JWK trust boundaries', async (t) => {
  const { dir, options } = await fixture(t);
  const pemPath = join(dir, 'public.pem');
  await writeFile(pemPath, pair.publicKey.export({ type: 'spki', format: 'pem' }));
  await verifyJWT(token(), { audience, publicKey: pemPath });
  await writeFile(pemPath, pair.privateKey.export({ type: 'pkcs8', format: 'pem' }));
  await assert.rejects(verifyJWT(token(), { audience, publicKey: pemPath }), { code: 'INVALID_PUBLIC_KEY' });
  for (const keys of [[jwk, jwk], [], [{ ...jwk, use: 'enc' }], [{ ...jwk, key_ops: ['sign'] }], [{ ...jwk, d: 'private' }]]) {
    await writeFile(options.jwksFile, JSON.stringify({ keys }));
    await assert.rejects(verifyJWT(token(), options));
  }
  const weak = generateKeyPairSync('rsa', { modulusLength: 1024 });
  await writeFile(options.jwksFile, JSON.stringify({ keys: [{ ...weak.publicKey.export({ format: 'jwk' }), kid: jwk.kid }] }));
  await assert.rejects(verifyJWT(token(baseClaims, header, weak.privateKey), options), { code: 'INVALID_PUBLIC_KEY' });
});

test('JWKS fetch uses configured HTTPS endpoint without forwarding JWT', async (t) => {
  let calls = 0;
  t.mock.method(globalThis, 'fetch', async (url, options) => {
    calls++;
    assert.equal(url.href, 'https://keys.example.com/jwks.json');
    assert.equal(options.redirect, 'error');
    assert.equal(options.headers.authorization, undefined);
    assert.equal(options.body, undefined);
    return new Response(JSON.stringify({ keys: [jwk] }));
  });
  const injected = { ...header, jku: 'https://attacker.invalid/jwks', x5u: 'https://attacker.invalid/cert', jwk: {} };
  await verifyJWT(token(baseClaims, injected), { audience, jwksUrl: 'https://keys.example.com/jwks.json' });
  assert.equal(calls, 1);
  for (const jwksUrl of ['http://keys.example.com/jwks', 'https://user:secret@keys.example.com/jwks']) {
    await assert.rejects(verifyJWT(token(), { audience, jwksUrl }), { code: 'INVALID_JWKS_URL' });
  }
  assert.equal(calls, 1);
});

test('JWKS rejects network errors, HTTP errors, malformed and oversized responses', async (t) => {
  for (const [name, fetcher, code] of [
    ['network', async () => { throw new Error('contains-sensitive-detail'); }, 'JWKS_FETCH_FAILED'],
    ['HTTP', async () => new Response('do not echo', { status: 503 }), 'JWKS_HTTP_ERROR'],
    ['JSON', async () => new Response('<html>login</html>'), 'INVALID_JWKS'],
    ['oversized', async () => new Response(' '.repeat(1024 * 1024 + 1)), 'INPUT_TOO_LARGE'],
  ]) {
    await t.test(name, async (sub) => {
      sub.mock.method(globalThis, 'fetch', fetcher);
      await assert.rejects(verifyJWT(token(), { audience }), { code });
    });
  }
});

test('CLI reads env/stdin, emits JSON and never echoes a rejected JWT', async (t) => {
  const { options } = await fixture(t);
  const bin = fileURLToPath(new URL('../bin/tag-jwt-verify.mjs', import.meta.url));
  const invoke = (args, value = token(), stdin) => spawnSync(process.execPath, [bin, ...args], {
    encoding: 'utf8', timeout: 10000, env: { PATH: process.env.PATH, TAG_IDENTITY: value }, input: stdin,
  });
  const flags = ['--aud', audience, '--jwks-file', options.jwksFile];
  let result = invoke(flags);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(JSON.parse(result.stdout).verified, true);
  assert.equal(JSON.parse(result.stdout).claims, undefined);
  result = invoke([...flags, '--show-claims']);
  assert.equal(JSON.parse(result.stdout).claims.lark_user_id, 'fixture-user');
  result = invoke([...flags, '--stdin'], 'invalid-env-token', token());
  assert.equal(result.status, 0, result.stderr);
  const invalid = 'not-a-token-secret';
  result = invoke(flags, invalid);
  assert.equal(result.status, 1);
  assert.equal(result.stdout, '');
  assert.equal(result.stderr.includes(invalid), false);
  result = invoke(['--token', invalid]);
  assert.equal(result.status, 2);
  assert.equal(result.stderr.includes(invalid), false);
  assert.equal(invoke([]).status, 2);
  assert.equal(invoke([...flags, '--public-key', 'key.pem']).status, 2);
  assert.equal(invoke([...flags, '--clock-tolerance', '']).status, 2);
  assert.equal(invoke(['--help']).status, 0);
  assert.equal(invoke(['--version']).stdout.trim(), '0.1.0');
});
