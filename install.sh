#!/usr/bin/env bash

# Define the complete installer before running it when downloaded through a pipe.
install_tag_jwt() (
  set -euo pipefail
  unset TAG_IDENTITY

  for tool in node npm curl; do
    command -v "$tool" >/dev/null 2>&1 || {
      printf '安装失败：缺少 %s。请先安装 Node.js 20+、npm 和 curl。\n' "$tool" >&2
      exit 1
    }
  done
  node -e 'if (Number(process.versions.node.split(".")[0]) < 20) { console.error("安装失败：需要 Node.js 20 或更高版本。"); process.exit(1); }'

  install_tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/tag-jwt-install.XXXXXXXX")"
  trap 'rm -rf -- "$install_tmpdir"' EXIT
  archive="$install_tmpdir/tag-jwt-verify-0.1.2.tgz"
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --connect-timeout 10 --max-time 60 \
    'https://github.com/Rudo-erek/tag-jwt-verify/releases/download/v0.1.2/tag-jwt-verify-0.1.2.tgz' -o "$archive"

  node -e '
    const fs = require("node:fs");
    const crypto = require("node:crypto");
    const digest = crypto.createHash("sha256").update(fs.readFileSync(process.argv[1])).digest("hex");
    if (digest !== "64f87a23837cf095f1f36af1dfe17f44f40fb7a3577e48d8162a921831a0b216") {
      console.error("安装失败：安装包 SHA-256 不匹配，已停止安装。");
      process.exit(1);
    }
  ' "$archive"

  npm install --global --ignore-scripts --no-audit --no-fund --cache "$install_tmpdir/npm-cache" "$archive"
  if ! command -v tag-jwt-verify >/dev/null 2>&1; then
    printf '安装完成，但 npm 全局 bin 目录未加入 PATH；请将 npm prefix -g 对应的 bin 目录加入 PATH。\n' >&2
    exit 1
  fi
  printf '安装完成：tag-jwt-verify '
  tag-jwt-verify --version
)

install_tag_jwt "$@"
