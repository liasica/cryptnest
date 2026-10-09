# CryptNest

浏览器端的文件与文本加密应用。

[在线使用](https://liasica.github.io/cryptnest/) · [下载离线版](https://liasica.github.io/cryptnest/cryptnest-offline.html) · [MIT 许可证](LICENSE)

## 功能

- 文件和文件夹支持选择或拖入，多个文件自动打包为 ZIP
- 文件名、目录结构和内容一起加密，输出 `.cryptnest` 加密包
- 使用原密码解密，文件归档还原为 ZIP，文本可复制或下载
- 文本加密结果以 `cryptnest:v1:` 开头，支持复制、粘贴和文件导出
- 支持自定义密码、密码显示、随机密码生成、处理进度和取消
- 提供「跟随系统」「浅色」「深色」三个主题按钮，默认跟随系统并记住手动选择
- 桌面与手机均可使用，提供包含全部代码的独立 HTML 离线版

## 使用

加密文件时，选择或拖入文件，设置并确认密码，点击「加密并生成文件」，下载结果。解密时切换到「解密」，选择 `.cryptnest` 加密包并输入原密码，下载 ZIP 后解压。

文本处理使用「文本」选项。加密结果可复制为密文，也可下载为 `.cryptnest` 文件。文本解密支持粘贴完整密文或选择加密文件。

点击「下载离线版」，保存 HTML 文件并直接用浏览器打开。离线版支持相同的加密与解密操作。

## 数据处理

文件、文本、密码与密钥在当前浏览器中处理，不发送到服务器。应用不使用分析统计、第三方运行时资源、外部字体或网络接口，不将输入内容写入浏览器持久存储。

生产构建将代码和样式内联到 HTML，内容安全策略的 `connect-src 'none'` 禁用应用联网请求。打包与加密在 Web Worker 内完成。

## 密码与格式

应用使用浏览器原生 Web Crypto API：

| 参数 | 值 |
| --- | --- |
| 加密算法 | AES-256-GCM |
| 密钥派生 | PBKDF2-HMAC-SHA-256 |
| 迭代次数 | 600,000 |
| 随机盐 | 32 字节，每次独立生成 |
| 随机 IV | 12 字节，每次独立生成 |
| 认证标签 | 128 位 |
| 认证附加数据 | 完整的 56 字节文件头 |

`.cryptnest` 是 CryptNest 的加密容器，需要使用 CryptNest 解密。ZIP 归档在加密容器内部，解密得到的 ZIP 可用常规压缩软件打开。密码按原样参与派生，区分大小写、空格和 Unicode 字符，不进行自动修剪或规范化。密码无法找回。

格式版本为 `CNEST001`，整数使用大端序。

| 偏移 | 长度 | 内容 |
| --- | --- | --- |
| 0 | 8 字节 | UTF-8 标识 `CNEST001` |
| 8 | 4 字节 | PBKDF2 迭代次数 |
| 12 | 32 字节 | 随机盐 |
| 44 | 12 字节 | 随机 IV |
| 56 | 可变 | AES-GCM 密文，末尾包含 16 字节认证标签 |

解密后的首字节标识内容类型：`1` 表示 ZIP，`2` 表示 UTF-8 文本。后续字节为原始内容。文本密文格式为 `cryptnest:v1:` 加完整二进制容器的标准 Base64 编码。

## 处理范围

- 一次最多加密 1,000 个文件，原始文件总大小不超过 100 MiB
- 文本原始内容不超过 1 MiB，密码长度不超过 1,024 个字符
- 一次解密一个加密包，输入加密包不超过 110 MiB
- 拖入目录的层级不超过 32 层，空目录不写入归档
- 重名文件自动添加序号，ZIP 内保留文件相对路径和修改时间
- 支持带 Web Crypto API 与 Web Worker 的现代浏览器，在线版使用 HTTPS

## 本地开发

使用 `.nvmrc` 指定的 Node.js 版本。

```sh
nvm use
npm ci
npm run dev
```

```sh
npm run check
npm run build
npm run preview
```

构建结果为 `dist/index.html` 和 `dist/cryptnest-offline.html`。新增依赖和发布工具使用核对后的最新稳定版本，准确版本保存在 `package.json` 和 `package-lock.json`。

## 发布

`master` 分支推送触发 GitHub Actions，构建并发布到 GitHub Pages。工作流使用 `.nvmrc` 中的 Node.js 版本，官方 Actions 固定到最新稳定版本对应的提交。

仓库设置中的 Pages 发布来源为 GitHub Actions。

## 许可证

采用 [MIT](LICENSE) 许可证，版权所有 © 2026 liasica。
