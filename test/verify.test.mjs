import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { mkdtemp, writeFile, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
  DEFAULT_ISSUER,
  VERSION,
  generateMockBundle,
  inspectEnvToken,
  inspectJWKS,
  parseJWT,
  runSelfTest,
  verifyJWT,
} from '../lib/verify.mjs';

const pair = generateKeyPairSync('rsa', { modulusLength: 2048 });
const jwk = { ...pair.publicKey.export({ format: 'jwk' }), kid: 'fixture-key', alg: 'RS256', use: 'sig' };
const audience = 'example_plugin/example_connector';
const header = { alg: 'RS256', typ: 'tag-identity+jwt', kid: jwk.kid };
const now = Math.floor(Date.now() / 1000);
const baseClaims = { iss: 'https://ai.feishu.cn', aud: audience, sub: 'urn:test:agent', iat: now, nbf: now - 60, exp: now + 300, jti: 'fixture', lark_user_id: 'fixture-user' };
const bin = fileURLToPath(new URL('../bin/tag-jwt-verify.mjs', import.meta.url));

function token(claims = baseClaims, tokenHeader = header, privateKey = pair.privateKey) {
  const input = [tokenHeader, claims].map((value) => Buffer.from(JSON.stringify(value)).toString('base64url')).join('.');
  return `${input}.${sign('RSA-SHA256', Buffer.from(input), privateKey).toString('base64url')}`;
}

function invokeCli(args, envValue = token(), stdin) {
  const env = { PATH: process.env.PATH };
  if (envValue !== null) env.TAG_IDENTITY = envValue;
  return spawnSync(process.execPath, [bin, ...args], {
    encoding: 'utf8',
    timeout: 10000,
    env,
    input: stdin,
  });
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
  assert.equal(DEFAULT_ISSUER, 'https://ai.feishu.cn');
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
    ['previous default issuer', token({ ...baseClaims, iss: 'https://tag.feishu.cn' }), {}, 'ISSUER_MISMATCH'],
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

test('JWKS fetch uses configured HTTPS endpoint without forwarding JWT and supports --no-ppe', async (t) => {
  const seenHeaders = [];
  t.mock.method(globalThis, 'fetch', async (url, options) => {
    seenHeaders.push(options.headers);
    assert.equal(url.href, 'https://keys.example.com/jwks.json');
    assert.equal(options.redirect, 'error');
    assert.equal(options.headers.authorization, undefined);
    assert.equal(options.body, undefined);
    return new Response(JSON.stringify({ keys: [jwk] }));
  });
  const injected = { ...header, jku: 'https://attacker.invalid/jwks', x5u: 'https://attacker.invalid/cert', jwk: {} };
  await verifyJWT(token(baseClaims, injected), { audience, jwksUrl: 'https://keys.example.com/jwks.json' });
  assert.equal(seenHeaders[0]['x-use-ppe'], '1');
  assert.equal(seenHeaders[0]['X-TT-ENV'], 'ppe_tag_jwt_identity');

  await inspectJWKS({ jwksUrl: 'https://keys.example.com/jwks.json', usePpe: false, kid: jwk.kid });
  assert.equal(seenHeaders[1]['x-use-ppe'], undefined);
  assert.equal(seenHeaders[1]['X-TT-ENV'], undefined);

  for (const jwksUrl of ['http://keys.example.com/jwks', 'https://user:secret@keys.example.com/jwks']) {
    await assert.rejects(verifyJWT(token(), { audience, jwksUrl }), { code: 'INVALID_JWKS_URL' });
  }
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

test('CLI verify (default and subcommand), version, and secret non-echo guarantees', async (t) => {
  const { options } = await fixture(t);
  const flags = ['--aud', audience, '--jwks-file', options.jwksFile];
  let result = invokeCli(flags);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(JSON.parse(result.stdout).verified, true);
  assert.equal(JSON.parse(result.stdout).claims, undefined);

  result = invokeCli(['verify', ...flags, '--show-claims']);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(JSON.parse(result.stdout).claims.lark_user_id, 'fixture-user');

  result = invokeCli([...flags, '--stdin'], 'invalid-env-token', token());
  assert.equal(result.status, 0, result.stderr);

  const invalid = 'not-a-token-secret';
  result = invokeCli(flags, invalid);
  assert.equal(result.status, 1);
  assert.equal(result.stdout, '');
  assert.equal(result.stderr.includes(invalid), false);

  result = invokeCli(['--token', invalid]);
  assert.equal(result.status, 2);
  assert.equal(result.stderr.includes(invalid), false);

  result = invokeCli([invalid]);
  assert.equal(result.status, 2);
  assert.equal(result.stderr.includes(invalid), false);

  assert.equal(invokeCli([]).status, 2);
  assert.equal(invokeCli([...flags, '--public-key', 'key.pem']).status, 2);
  assert.equal(invokeCli([...flags, '--clock-tolerance', '']).status, 2);
  assert.equal(invokeCli(['--version']).stdout.trim(), VERSION);
  assert.equal(invokeCli(['version']).stdout.trim(), VERSION);
});

test('CLI help command lists purpose, subcommands, and per-command details', () => {
  for (const args of [['help'], ['--help'], ['-h']]) {
    const res = invokeCli(args, null);
    assert.equal(res.status, 0, res.stderr);
    assert.match(res.stdout, /用途/);
    for (const cmd of ['verify', 'parse', 'env', 'jwks', 'mock', 'selftest', 'version']) {
      assert.ok(res.stdout.includes(cmd), `Expected help output to list ${cmd}`);
    }
  }
  for (const sub of ['verify', 'parse', 'decode', 'env', 'jwks', 'mock', 'selftest', 'version']) {
    const res = invokeCli(['help', sub], null);
    assert.equal(res.status, 0, res.stderr);
    assert.ok(res.stdout.length > 40);
  }
  const secretTopic = 'eyJhbGciOiJSUzI1NiJ9.secret';
  const bad = invokeCli(['help', secretTopic], null);
  assert.equal(bad.status, 2);
  assert.equal(bad.stderr.includes(secretTopic), false);
});

test('CLI parse / decode command returns header, claims, and timing without verifying signature', () => {
  const expiredWrongIss = token({ ...baseClaims, iss: 'https://other.example', exp: now - 120 });
  for (const sub of ['parse', 'decode']) {
    const res = invokeCli([sub], expiredWrongIss);
    assert.equal(res.status, 0, res.stderr);
    const body = JSON.parse(res.stdout);
    assert.equal(body.verified, false);
    assert.deepEqual(body.header, header);
    assert.equal(body.claims.iss, 'https://other.example');
    assert.equal(body.claims.lark_user_id, 'fixture-user');
    assert.equal(body.timing.expired, true);
    assert.ok(body.timing.ttl_seconds <= -120);
  }

  const claimsOnly = invokeCli(['parse', '--part', 'claims'], token());
  assert.equal(claimsOnly.status, 0, claimsOnly.stderr);
  assert.deepEqual(JSON.parse(claimsOnly.stdout), baseClaims);

  const headerOnly = invokeCli(['parse', '--part', 'header', '--stdin'], null, token());
  assert.equal(headerOnly.status, 0, headerOnly.stderr);
  assert.deepEqual(JSON.parse(headerOnly.stdout), header);

  const missing = invokeCli(['parse'], '');
  assert.equal(missing.status, 2);

  const secretMalformed = 'malformed-raw-secret-token';
  const bad = invokeCli(['parse'], secretMalformed);
  assert.equal(bad.status, 1);
  assert.equal(bad.stderr.includes(secretMalformed), false);
});

test('CLI env, jwks, mock, and selftest diagnostic commands', async (t) => {
  const { dir, options } = await fixture(t);

  // env command
  const rawJwt = token();
  let res = invokeCli(['env'], rawJwt);
  assert.equal(res.status, 0, res.stderr);
  assert.equal(res.stdout.includes(rawJwt), false);
  const envReport = JSON.parse(res.stdout);
  assert.equal(envReport.well_formed_jwt, true);
  assert.equal(envReport.summary.kid, jwk.kid);
  assert.equal(envReport.summary.aud, audience);

  assert.equal(invokeCli(['env'], null).status, 2);
  assert.equal(invokeCli(['env', '--allow-missing'], null).status, 0);
  const badSecret = 'bad-jwt-secret-value';
  const badEnv = invokeCli(['env'], badSecret);
  assert.equal(badEnv.status, 1);
  assert.equal(badEnv.stdout.includes(badSecret), false);

  // jwks command
  res = invokeCli(['jwks', '--jwks-file', options.jwksFile, '--from-env'], rawJwt);
  assert.equal(res.status, 0, res.stderr);
  const jwksReport = JSON.parse(res.stdout);
  assert.equal(jwksReport.ok, true);
  assert.equal(jwksReport.kid_matched, true);
  assert.equal(jwksReport.keys[0].modulus_bits, 2048);

  res = invokeCli(['jwks', '--jwks-file', options.jwksFile, '--kid', 'non-existent-kid'], null);
  assert.equal(res.status, 1);
  assert.equal(JSON.parse(res.stdout).kid_matched, false);

  // mock command (--out-dir + end-to-end verify & parse)
  const mockDir = join(dir, 'mock-out');
  res = invokeCli(['mock', '--aud', 'demo_plugin/demo_conn', '--out-dir', mockDir], null);
  assert.equal(res.status, 0, res.stderr);
  const mockMeta = JSON.parse(res.stdout);
  const mockJwt = (await readFile(mockMeta.files.token, 'utf8')).trim();
  const verifyMock = invokeCli(['verify', '--aud', 'demo_plugin/demo_conn', '--jwks-file', mockMeta.files.jwks], mockJwt);
  assert.equal(verifyMock.status, 0, verifyMock.stderr);
  assert.equal(JSON.parse(verifyMock.stdout).verified, true);

  const expiredMock = generateMockBundle({ audience: 'demo_plugin/demo_conn', expired: true });
  assert.equal(parseJWT(expiredMock.token).timing.expired, true);
  assert.equal(inspectEnvToken(expiredMock.token).summary.timing.expired, true);

  // selftest command
  const selfRes = await runSelfTest();
  assert.equal(selfRes.ok, true);
  assert.equal(selfRes.passed, 5);
  res = invokeCli(['selftest'], null);
  assert.equal(res.status, 0, res.stderr);
  assert.equal(JSON.parse(res.stdout).ok, true);
});
