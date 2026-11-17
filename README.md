# tag-jwt-verify

在本机验证 Tag 身份 JWT。Node.js 20+，无第三方依赖，无安装脚本；支持 Linux、macOS、Windows。

## 安装与使用

从发布页复制安装包 HTTPS 地址：

```sh
npm install -g '<发布页提供的 tag-jwt-verify-0.1.0.tgz 地址>'
tag-jwt-verify --aud '插件唯一标识/连接器唯一标识'
```

工具默认读取执行环境中的 `TAG_IDENTITY`，不需要在命令行传递 JWT。
`--aud` 必填，逐字匹配企业预期受众；CLI 使用创建时填写的两个唯一标识，分别 URL PathEscape 编码后以 `/` 拼接，不使用显示名称或数字 ID。
设备调用填写服务端为该设备签发的完整 `aud`。

```sh
# 公网 JWKS 尚未就绪时，用配置页面提供的公钥离线验证。
tag-jwt-verify --aud 'example_plugin/example_connector' --public-key ./public.pem

# 从标准输入读取；不要把真实 JWT 放进命令参数或 shell 历史。
tag-jwt-verify --aud 'example_plugin/example_connector' --stdin < token.jwt

# 校验指定 Agent 身份并显式展示已验证的身份声明。
tag-jwt-verify --aud 'example_plugin/example_connector' \
  --subject 'wimse://tag.feishu.cn/tenant/<tenant>/agent/<agent>' --show-claims

# 使用企业自己可信的 JWKS 和签发方。
tag-jwt-verify --aud 'expected-audience' --issuer 'https://issuer.example.com' \
  --jwks-url 'https://issuer.example.com/jwks.json' --type 'JWT'
```

默认签发方为 `https://tag.feishu.cn`，默认 JWKS 地址为
`https://ai.feishu.cn/v1/openapi/federation/jwks.json`。
请与平台返回的校验信息核对，不能从待验证 JWT 自报的 `iss`、`jku` 或 `jwk` 建立信任。
JWKS 只接受 HTTPS，不跟随重定向；每次运行重新拉取，不缓存公钥。
`--jwks-file` 可指定事先通过可信渠道取得的本地 JWKS。

## 校验与输出

- 仅接受 RS256、RSA 2048 位及以上公钥；按 `kid` 唯一匹配 JWKS。
- 默认要求 `typ=tag-identity+jwt`，拒绝将换票 JWT 当作身份 JWT 使用。
- 校验签名、`iss`、`aud`、必填 `exp`、存在时的 `nbf` / `iat`。
- `--subject` 可额外精确匹配完整主体 URI；默认时钟容差为 0，`--clock-tolerance` 可指定 0–300 秒。
- 成功退出码 0；令牌校验失败 1；参数、网络或公钥读取错误 2。
- 成功结果输出到 stdout，错误结果输出到 stderr，格式均为 JSON。
- 默认不输出用户、Agent、邮箱等身份声明；`--show-claims` 输出完整已验证声明，注意日志中的个人信息。

JWT 不会上传到下载站或 JWKS 服务，不写日志、不落盘，无遥测。
程序退出前仍会在自身进程内存和继承的环境中持有 JWT；它不提供进程隔离、撤销、重放防护或业务授权。
企业接收端仍须校验租户、映射账号，并执行自己的登录认证与权限控制。

完整参数：`tag-jwt-verify --help`。

## 验证与构建

测试使用 Node.js 内置 `node:test`，运行时生成测试密钥，不包含真实 JWT 或密钥：

```sh
npm test
npm pack --ignore-scripts
```

发布流水线必须先通过测试，再打包发布。
格式及校验依据：[RFC 7519](https://www.rfc-editor.org/rfc/rfc7519)、
[RFC 8725](https://www.rfc-editor.org/rfc/rfc8725)、
[Node.js crypto](https://nodejs.org/api/crypto.html)。
