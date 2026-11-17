#!/usr/bin/env node
import { parseArgs } from 'node:util';
import { DEFAULT_ISSUER, DEFAULT_JWKS, MAX_TOKEN_BYTES, readLimited, VerificationError, verifyJWT } from '../lib/verify.mjs';

const help = `tag-jwt-verify 0.1.2 — Verify JWT identity locally (Node.js 20+)

Usage: tag-jwt-verify --aud <expected-audience> [options]

JWT input: TAG_IDENTITY environment variable, or explicit --stdin.
  --aud <value>             Required expected audience (exact match)
  --issuer <value>          Expected issuer (default: ${DEFAULT_ISSUER})
  --jwks-url <https-url>    Trusted JWKS URL (default: ${DEFAULT_JWKS})
  --jwks-file <path>        Use a local JWKS file instead of HTTPS
  --public-key <path>       Use a local PEM public key instead of JWKS
  --subject <value>         Additionally require this exact subject URI
  --type <value>            Expected typ (default: tag-identity+jwt)
  --clock-tolerance <secs>  Clock tolerance, 0–300 (default: 0)
  --timeout <ms>           JWKS request timeout, 1–60000 (default: 10000)
  --stdin                  Read JWT from stdin instead of TAG_IDENTITY
  --show-claims            Include verified claims (may contain personal data)
  --help                   Show help
  --version                Show version

Output: JSON. Exit 0 = verified; 1 = rejected; 2 = usage/network/key error.
No JWT upload, token command-line argument, telemetry, or online revocation.
Verification is not business authorization. Pin a trusted key source and issuer.
`;

async function main() {
  let args;
  try {
    args = parseArgs({ options: {
      aud: { type: 'string' }, issuer: { type: 'string' },
      'jwks-url': { type: 'string' }, 'jwks-file': { type: 'string' },
      'public-key': { type: 'string' }, subject: { type: 'string' },
      type: { type: 'string' }, 'clock-tolerance': { type: 'string' },
      timeout: { type: 'string' }, stdin: { type: 'boolean' },
      'show-claims': { type: 'boolean' }, help: { type: 'boolean' }, version: { type: 'boolean' },
    }, allowPositionals: false, strict: true }).values;
  } catch { throw new VerificationError('INVALID_ARGUMENTS', 'Invalid arguments. See --help. Do not put JWTs in arguments.', 2); }
  if (args.help) { console.log(help); return; }
  if (args.version) { console.log('0.1.2'); return; }
  if (!args.aud || ['issuer', 'type', 'subject', 'jwks-url', 'jwks-file', 'public-key', 'timeout', 'clock-tolerance']
    .some((name) => args[name] !== undefined && !args[name].trim())) {
    throw new VerificationError('INVALID_ARGUMENTS', '--aud is required; option values must not be empty. See --help.', 2);
  }
  if (['jwks-url', 'jwks-file', 'public-key'].filter((name) => args[name] !== undefined).length > 1) {
    throw new VerificationError('INVALID_ARGUMENTS', 'Choose only one public key source.', 2);
  }
  const options = { audience: args.aud };
  const mapping = { issuer: 'issuer', type: 'type', subject: 'subject', 'jwks-url': 'jwksUrl', 'jwks-file': 'jwksFile', 'public-key': 'publicKey' };
  for (const [flag, name] of Object.entries(mapping)) if (args[flag] !== undefined) options[name] = args[flag];
  for (const [flag, name] of [['clock-tolerance', 'tolerance'], ['timeout', 'timeout']]) {
    if (args[flag] !== undefined) {
      if (!/^\d+$/.test(args[flag])) throw new VerificationError('INVALID_ARGUMENTS', 'Timeout and tolerance must be nonnegative integers.', 2);
      options[name] = Number(args[flag]);
    }
  }
  const token = args.stdin ? await readLimited(process.stdin, MAX_TOKEN_BYTES) : process.env.TAG_IDENTITY;
  const { header, claims } = await verifyJWT(token, options);
  const result = { verified: true, algorithm: header.alg, kid: header.kid, issuer: claims.iss, audience: claims.aud, expires_at: claims.exp };
  if (args['show-claims']) result.claims = claims;
  console.log(JSON.stringify(result, null, 2));
}

main().catch((error) => {
  const known = error instanceof VerificationError;
  console.error(JSON.stringify({ verified: false, error: known ? error.code : 'INPUT_ERROR', message: known ? error.message : 'Unable to read input or complete verification.' }));
  process.exitCode = known ? error.exitCode : 2;
});
