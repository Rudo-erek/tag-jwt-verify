#!/usr/bin/env node
import { mkdir, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { parseArgs } from 'node:util';
import {
  DEFAULT_ISSUER,
  DEFAULT_JWKS,
  DEFAULT_TYPE,
  MAX_TOKEN_BYTES,
  VERSION,
  VerificationError,
  generateMockBundle,
  inspectEnvToken,
  inspectJWKS,
  parseJWT,
  readLimited,
  runSelfTest,
  verifyJWT,
} from '../lib/verify.mjs';

const MAIN_HELP = `tag-jwt-verify ${VERSION} — Tag 身份 JWT 本地验证、解析与联调诊断工具 (Node.js 20+)

用途 (Purpose):
  在本机或沙箱环境中验证、解析和联调排查 Tag 身份 JWT（默认从环境变量 TAG_IDENTITY 读取，
  支持 --stdin 标准输入；零外部依赖，JWT 全程留在本机处理，不会上传到任何服务端）。

用法 (Usage):
  tag-jwt-verify <command> [options]
  tag-jwt-verify --aud <expected-audience> [options]   (不写子命令时默认执行 verify)

指令列表 (Commands):
  help [command]   显示 CLI 用途、指令列表，或查看指定子命令的详细参数说明
  verify           验签并校验身份 JWT（RS256 签名、iss、aud、exp/nbf/iat 等）
  parse (decode)   解析并解码 JWT 的 Header、Payload Claims 与有效期状态（不验签）
  env              检查当前环境中的 TAG_IDENTITY 注入状态与摘要元信息（不回显原始密文）
  jwks             测试 JWKS 公钥接口或本地文件的连通性、延迟、RSA 密钥强度与 kid 匹配
  mock             生成本地测试用的临时 RSA-2048 密钥对、JWKS、PEM 公钥与测试 JWT
  selftest         运行内置加解密与校验规则自检（无需联网或环境变量，适合冒烟测试）
  version          输出当前版本号 (${VERSION})

常用示例 (Examples):
  tag-jwt-verify help
  tag-jwt-verify help parse
  tag-jwt-verify verify --aud 'example_plugin/example_connector'
  tag-jwt-verify parse
  tag-jwt-verify parse --part claims
  tag-jwt-verify env
  tag-jwt-verify jwks --from-env
  tag-jwt-verify mock --aud 'example_plugin/example_connector' --out-dir ./tmp-jwt
  tag-jwt-verify selftest

退出码 (Exit Codes):
  0 = 成功 / 校验通过；1 = 令牌校验或检测未通过；2 = 参数、缺失凭证、网络或密钥读取错误。
`;

const COMMAND_HELP = {
  verify: `tag-jwt-verify verify — 本地验签并校验身份 JWT

用法:
  tag-jwt-verify verify --aud <expected-audience> [options]
  tag-jwt-verify --aud <expected-audience> [options]

参数:
  --aud <value>             必填，预期受众 aud（精确匹配，如 plugin_id/connector_id）
  --issuer <value>          预期签发方 iss（默认: ${DEFAULT_ISSUER}）
  --jwks-url <https-url>    可信 JWKS 地址（默认: ${DEFAULT_JWKS}）
  --jwks-file <path>        使用本地 JWKS JSON 文件替代远程拉取
  --public-key <path>       使用本地 PEM 公钥文件替代 JWKS
  --subject <value>         额外要求精确匹配 sub 主体 URI
  --type <value>            预期 Header typ（默认: ${DEFAULT_TYPE}）
  --clock-tolerance <secs>  时钟容差秒数，0–300（默认: 0）
  --timeout <ms>            拉取 JWKS 超时毫秒数，1–60000（默认: 10000）
  --stdin                   从标准输入读取 JWT（默认读取环境变量 TAG_IDENTITY）
  --show-claims             在验证结果中附带完整已验证 claims（注意日志脱敏）
  --no-ppe                  拉取 JWKS 时不附带默认 PPE 泳道请求头
  -h, --help                显示本指令帮助
`,
  parse: `tag-jwt-verify parse (别名: decode) — 解析并解码 JWT 内容（不执行签名校验）

用法:
  tag-jwt-verify parse [options]
  tag-jwt-verify decode [options]

参数:
  --stdin                   从标准输入读取 JWT（默认读取环境变量 TAG_IDENTITY）
  --part <section>          仅输出指定部分：header | claims | timing（默认输出完整结构）
  -h, --help                显示本指令帮助

说明:
  仅解码 Base64URL 的 Header 与 Payload 并计算有效期/剩余秒数，不请求 JWKS、不校验签名。
  输出结果显式包含 "verified": false，切勿将 parse 结果直接用于业务鉴权放行。
`,
  env: `tag-jwt-verify env — 检查环境变量 TAG_IDENTITY 的注入状态与结构摘要

用法:
  tag-jwt-verify env [options]

参数:
  --allow-missing           当 TAG_IDENTITY 未设置或为空时仍以退出码 0 返回检查报告
  -h, --help                显示本指令帮助

说明:
  用于沙箱/容器内快速排查 TAG_IDENTITY 是否已下发、字节长度、三段结构是否合法，以及
  kid / iss / aud / exp 等非敏感元信息摘要，全程不会回显原始 JWT 字符串。
`,
  jwks: `tag-jwt-verify jwks — 测试 JWKS 公钥服务连通性、密钥规格与 kid 匹配

用法:
  tag-jwt-verify jwks [options]

参数:
  --jwks-url <https-url>    待探测的 HTTPS JWKS 地址（默认: ${DEFAULT_JWKS}）
  --jwks-file <path>        检查本地 JWKS JSON 文件
  --kid <kid>               指定要检查是否存在的密钥 kid
  --from-env                自动从环境变量 TAG_IDENTITY 的 Header 中提取 kid 并匹配
  --timeout <ms>            请求超时毫秒数，1–60000（默认: 10000）
  --no-ppe                  请求时不携带默认 PPE 泳道请求头（x-use-ppe / X-TT-ENV）
  -h, --help                显示本指令帮助
`,
  mock: `tag-jwt-verify mock — 生成本地测试用临时 RSA-2048 密钥对与签名 JWT

用法:
  tag-jwt-verify mock [options]

参数:
  --aud <value>             测试令牌的 aud（默认: mock_plugin/mock_connector）
  --issuer <value>          测试令牌的 iss（默认: ${DEFAULT_ISSUER}）
  --subject <value>         测试令牌的 sub
  --kid <value>             测试密钥的 kid（默认随机生成）
  --type <value>            测试令牌的 typ（默认: ${DEFAULT_TYPE}）
  --ttl <seconds>           有效时长秒数，1–86400（默认: 300）
  --expired                 直接生成已过期的测试 JWT（用于反向测试）
  --out-dir <dir>           将 token.jwt、jwks.json、public.pem 写入指定目录
  -h, --help                显示本指令帮助
`,
  selftest: `tag-jwt-verify selftest — 运行内置加解密与校验规则自检

用法:
  tag-jwt-verify selftest

说明:
  在内存中临时生成 2048 位 RSA 密钥对，依次自检 JWT 解码、正常验签、篡改签名拦截、
  受众不匹配拦截与过期令牌拦截，无需联网或配置 TAG_IDENTITY，适合安装后冒烟验收。
`,
  version: `tag-jwt-verify version — 显示当前 CLI 版本号

用法:
  tag-jwt-verify version
  tag-jwt-verify --version
`,
};
COMMAND_HELP.decode = COMMAND_HELP.parse;
COMMAND_HELP.help = MAIN_HELP;

function parseStrict(argv, options) {
  try {
    return parseArgs({
      args: argv,
      options: { ...options, help: { type: 'boolean', short: 'h' } },
      allowPositionals: false,
      strict: true,
    }).values;
  } catch {
    throw new VerificationError('INVALID_ARGUMENTS', 'Invalid arguments. See "tag-jwt-verify help". Do not put JWTs in arguments.', 2);
  }
}

function parseIntOption(raw, label) {
  if (!/^\d+$/.test(raw)) {
    throw new VerificationError('INVALID_ARGUMENTS', `${label} must be a nonnegative integer.`, 2);
  }
  return Number(raw);
}

async function readTokenInput(useStdin) {
  return useStdin ? await readLimited(process.stdin, MAX_TOKEN_BYTES) : process.env.TAG_IDENTITY;
}

async function handleVerify(argv) {
  const args = parseStrict(argv, {
    aud: { type: 'string' },
    issuer: { type: 'string' },
    'jwks-url': { type: 'string' },
    'jwks-file': { type: 'string' },
    'public-key': { type: 'string' },
    subject: { type: 'string' },
    type: { type: 'string' },
    'clock-tolerance': { type: 'string' },
    timeout: { type: 'string' },
    stdin: { type: 'boolean' },
    'show-claims': { type: 'boolean' },
    'no-ppe': { type: 'boolean' },
    version: { type: 'boolean', short: 'v' },
  });
  if (args.help) { console.log(COMMAND_HELP.verify); return; }
  if (args.version) { console.log(VERSION); return; }
  if (!args.aud || ['issuer', 'type', 'subject', 'jwks-url', 'jwks-file', 'public-key', 'timeout', 'clock-tolerance']
    .some((name) => args[name] !== undefined && !args[name].trim())) {
    throw new VerificationError('INVALID_ARGUMENTS', '--aud is required; option values must not be empty. See "tag-jwt-verify help verify".', 2);
  }
  if (['jwks-url', 'jwks-file', 'public-key'].filter((name) => args[name] !== undefined).length > 1) {
    throw new VerificationError('INVALID_ARGUMENTS', 'Choose only one public key source.', 2);
  }
  const options = { audience: args.aud, usePpe: !args['no-ppe'] };
  const mapping = { issuer: 'issuer', type: 'type', subject: 'subject', 'jwks-url': 'jwksUrl', 'jwks-file': 'jwksFile', 'public-key': 'publicKey' };
  for (const [flag, name] of Object.entries(mapping)) if (args[flag] !== undefined) options[name] = args[flag];
  for (const [flag, name] of [['clock-tolerance', 'tolerance'], ['timeout', 'timeout']]) {
    if (args[flag] !== undefined) options[name] = parseIntOption(args[flag], 'Timeout and tolerance');
  }
  const token = await readTokenInput(args.stdin);
  const { header, claims } = await verifyJWT(token, options);
  const result = { verified: true, algorithm: header.alg, kid: header.kid, issuer: claims.iss, audience: claims.aud, expires_at: claims.exp };
  if (args['show-claims']) result.claims = claims;
  console.log(JSON.stringify(result, null, 2));
}

async function handleParse(argv) {
  const args = parseStrict(argv, {
    stdin: { type: 'boolean' },
    part: { type: 'string' },
  });
  if (args.help) { console.log(COMMAND_HELP.parse); return; }
  if (args.part !== undefined && !['header', 'claims', 'timing'].includes(args.part)) {
    throw new VerificationError('INVALID_ARGUMENTS', '--part must be one of: header, claims, timing.', 2);
  }
  const token = await readTokenInput(args.stdin);
  const parsed = parseJWT(token);
  const output = args.part ? parsed[args.part] : parsed;
  console.log(JSON.stringify(output, null, 2));
}

async function handleEnv(argv) {
  const args = parseStrict(argv, {
    'allow-missing': { type: 'boolean' },
  });
  if (args.help) { console.log(COMMAND_HELP.env); return; }
  const report = inspectEnvToken(process.env.TAG_IDENTITY);
  console.log(JSON.stringify(report, null, 2));
  if (!report.non_empty) {
    if (!args['allow-missing']) process.exitCode = 2;
    return;
  }
  if (!report.well_formed_jwt) process.exitCode = 1;
}

async function handleJwks(argv) {
  const args = parseStrict(argv, {
    'jwks-url': { type: 'string' },
    'jwks-file': { type: 'string' },
    kid: { type: 'string' },
    'from-env': { type: 'boolean' },
    timeout: { type: 'string' },
    'no-ppe': { type: 'boolean' },
  });
  if (args.help) { console.log(COMMAND_HELP.jwks); return; }
  if (args['jwks-url'] !== undefined && args['jwks-file'] !== undefined) {
    throw new VerificationError('INVALID_ARGUMENTS', 'Choose only one of --jwks-url or --jwks-file.', 2);
  }
  if (args.kid !== undefined && args['from-env']) {
    throw new VerificationError('INVALID_ARGUMENTS', 'Choose only one of --kid or --from-env.', 2);
  }
  for (const name of ['jwks-url', 'jwks-file', 'kid', 'timeout']) {
    if (args[name] !== undefined && !args[name].trim()) {
      throw new VerificationError('INVALID_ARGUMENTS', `--${name} must not be empty.`, 2);
    }
  }
  let targetKid = args.kid;
  if (args['from-env']) {
    const parsed = parseJWT(process.env.TAG_IDENTITY);
    if (typeof parsed.header.kid !== 'string' || !parsed.header.kid) {
      throw new VerificationError('INVALID_JWT', 'JWT in TAG_IDENTITY does not contain header.kid.', 1);
    }
    targetKid = parsed.header.kid;
  }
  const options = { usePpe: !args['no-ppe'] };
  if (args['jwks-url'] !== undefined) options.jwksUrl = args['jwks-url'];
  if (args['jwks-file'] !== undefined) options.jwksFile = args['jwks-file'];
  if (targetKid !== undefined) options.kid = targetKid;
  if (args.timeout !== undefined) options.timeout = parseIntOption(args.timeout, 'Timeout');

  const result = await inspectJWKS(options);
  console.log(JSON.stringify(result, null, 2));
  if (!result.ok) process.exitCode = 1;
}

async function handleMock(argv) {
  const args = parseStrict(argv, {
    aud: { type: 'string' },
    issuer: { type: 'string' },
    subject: { type: 'string' },
    kid: { type: 'string' },
    type: { type: 'string' },
    ttl: { type: 'string' },
    expired: { type: 'boolean' },
    'out-dir': { type: 'string' },
  });
  if (args.help) { console.log(COMMAND_HELP.mock); return; }
  for (const name of ['aud', 'issuer', 'subject', 'kid', 'type', 'ttl', 'out-dir']) {
    if (args[name] !== undefined && !args[name].trim()) {
      throw new VerificationError('INVALID_ARGUMENTS', `--${name} must not be empty.`, 2);
    }
  }
  const options = {
    audience: args.aud,
    issuer: args.issuer,
    subject: args.subject,
    kid: args.kid,
    type: args.type,
    expired: Boolean(args.expired),
  };
  if (args.ttl !== undefined) options.ttlSeconds = parseIntOption(args.ttl, 'TTL');
  const bundle = generateMockBundle(options);

  if (args['out-dir']) {
    const outDir = resolve(args['out-dir']);
    await mkdir(outDir, { recursive: true });
    const files = {
      token: join(outDir, 'token.jwt'),
      jwks: join(outDir, 'jwks.json'),
      public_key: join(outDir, 'public.pem'),
    };
    await writeFile(files.token, `${bundle.token}\n`, { mode: 0o600 });
    await writeFile(files.jwks, `${JSON.stringify(bundle.jwks, null, 2)}\n`);
    await writeFile(files.public_key, bundle.public_key_pem);
    console.log(JSON.stringify({
      test_only: true,
      out_dir: outDir,
      files,
      header: bundle.header,
      claims: bundle.claims,
      example_verify: `tag-jwt-verify verify --aud '${bundle.claims.aud}' --jwks-file '${files.jwks}' --stdin < '${files.token}'`,
      example_parse: `tag-jwt-verify parse --stdin < '${files.token}'`,
    }, null, 2));
    return;
  }
  console.log(JSON.stringify(bundle, null, 2));
}

async function handleSelfTest(argv) {
  const args = parseStrict(argv, {});
  if (args.help) { console.log(COMMAND_HELP.selftest); return; }
  const result = await runSelfTest();
  console.log(JSON.stringify(result, null, 2));
}

function handleHelp(argv) {
  if (argv.length === 0 || (argv.length === 1 && (argv[0] === '-h' || argv[0] === '--help'))) {
    console.log(MAIN_HELP);
    return;
  }
  if (argv.length === 1 && Object.hasOwn(COMMAND_HELP, argv[0])) {
    console.log(COMMAND_HELP[argv[0]]);
    return;
  }
  throw new VerificationError('INVALID_ARGUMENTS', 'Unknown help topic. Run "tag-jwt-verify help" to list available commands.', 2);
}

async function main() {
  const argv = process.argv.slice(2);
  if (argv.length === 0) {
    throw new VerificationError('INVALID_ARGUMENTS', 'Missing command or --aud. Run "tag-jwt-verify help" for usage.', 2);
  }
  const first = argv[0];
  if (first === '--help' || first === '-h') {
    console.log(MAIN_HELP);
    return;
  }
  if (first === '--version' || first === '-v' || first === 'version') {
    if (first === 'version' && argv.length > 1) {
      const args = parseStrict(argv.slice(1), {});
      if (args.help) { console.log(COMMAND_HELP.version); return; }
    } else if (argv.length > 1) {
      throw new VerificationError('INVALID_ARGUMENTS', '--version takes no extra arguments.', 2);
    }
    console.log(VERSION);
    return;
  }
  if (first === 'help') {
    handleHelp(argv.slice(1));
    return;
  }
  if (first === 'verify') {
    await handleVerify(argv.slice(1));
    return;
  }
  if (first === 'parse' || first === 'decode') {
    await handleParse(argv.slice(1));
    return;
  }
  if (first === 'env') {
    await handleEnv(argv.slice(1));
    return;
  }
  if (first === 'jwks') {
    await handleJwks(argv.slice(1));
    return;
  }
  if (first === 'mock') {
    await handleMock(argv.slice(1));
    return;
  }
  if (first === 'selftest') {
    await handleSelfTest(argv.slice(1));
    return;
  }
  if (first.startsWith('-')) {
    await handleVerify(argv);
    return;
  }
  throw new VerificationError('INVALID_ARGUMENTS', 'Unknown command. Run "tag-jwt-verify help" to list commands. Do not pass JWTs as arguments.', 2);
}

main().catch((error) => {
  const known = error instanceof VerificationError;
  console.error(JSON.stringify({
    verified: false,
    error: known ? error.code : 'INPUT_ERROR',
    message: known ? error.message : 'Unable to read input or complete command.',
  }));
  process.exitCode = known ? error.exitCode : 2;
});
