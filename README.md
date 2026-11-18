# tag-jwt-verify

在本机或沙箱中验证、解析与联调排查 Tag 身份 JWT。Node.js 20+，无第三方依赖，无安装脚本；支持 Linux、macOS、Windows。

## 安装与快速开始

从发布页复制安装包 HTTPS 地址（或使用一键安装脚本）：

```sh
npm install -g --ignore-scripts '<发布页提供的 tag-jwt-verify-0.2.0.tgz 地址>'
tag-jwt-verify help
```

工具默认读取执行环境中的 `TAG_IDENTITY`，不需要在命令行传递 JWT。

## 指令列表

| 指令 | 说明 |
|---|---|
| `help [command]` | 显示 CLI 用途与指令列表，或查看指定子命令详细参数（如 `tag-jwt-verify help parse`） |
| `verify` | 验签并校验身份 JWT（RS256 签名、`iss`、`aud`、`exp`/`nbf`/`iat`）；不写子命令直接传 `--aud` 时默认执行此指令 |
| `parse`（别名 `decode`） | 解析并解码 JWT 的 Header、Payload Claims 与有效期状态（**不验签**，用于查看内容与联调排查） |
| `env` | 检查环境变量 `TAG_IDENTITY` 的注入状态与结构摘要（全程不回显原始 JWT 字符串） |
| `jwks` | 测试 JWKS 公钥服务或本地文件的连通性、延迟、RSA 密钥规格与 `kid` 匹配 |
| `mock` | 生成本地测试用的临时 RSA-2048 密钥对、`jwks.json`、`public.pem` 与测试签名 JWT |
| `selftest` | 运行内置加解密与校验规则自检（无需联网或配置环境变量，适合冒烟验收） |
| `version` | 输出当前版本号（`0.2.0`） |

## 常用示例

```sh
# 1. 查看帮助与子命令说明
tag-jwt-verify help
tag-jwt-verify help parse

# 2. 验签校验（兼容旧用法直接传 --aud，或显式使用 verify 子命令）
tag-jwt-verify --aud 'example_plugin/example_connector'
tag-jwt-verify verify --aud 'example_plugin/example_connector' --show-claims

# 3. 解析查看 JWT 内容（不验签，支持只看 header / claims / timing）
tag-jwt-verify parse
tag-jwt-verify parse --part claims
tag-jwt-verify decode --stdin < token.jwt

# 4. 沙箱联调与环境诊断（不泄露原始 Token）
tag-jwt-verify env
tag-jwt-verify jwks --from-env
tag-jwt-verify selftest

# 5. 生成本地测试密钥与测试 JWT 做离线联调
tag-jwt-verify mock --aud 'example_plugin/example_connector' --out-dir ./tmp-jwt
tag-jwt-verify verify --aud 'example_plugin/example_connector' \
  --jwks-file ./tmp-jwt/jwks.json --stdin < ./tmp-jwt/token.jwt
```

## 校验与安全说明

- 默认签发方为 `https://ai.feishu.cn`，默认 JWKS 地址为 `https://ai.feishu.cn/v1/openapi/federation/jwks.json`。
- 此测试版本的 JWKS HTTP 请求默认携带 `x-use-ppe: 1` 和 `X-TT-ENV: ppe_tag_jwt_identity`（访问正式环境可加 `--no-ppe`）。
- `verify` 仅接受 RS256、RSA 2048 位及以上公钥，按 `kid` 唯一匹配 JWKS，默认要求 `typ=tag-identity+jwt`。
- `parse` / `decode` 仅解码结构并显式输出 `"verified": false`，不能代替 `verify` 作为业务鉴权依据。
- 成功结果输出到 stdout，错误结果输出到 stderr，格式均为 JSON；错误信息绝不回显待检 JWT 原文。

## 验证与构建

```sh
npm test
npm pack --ignore-scripts
```

格式及校验依据：[RFC 7519](https://www.rfc-editor.org/rfc/rfc7519)、[RFC 8725](https://www.rfc-editor.org/rfc/rfc8725)、[Node.js crypto](https://nodejs.org/api/crypto.html)。
