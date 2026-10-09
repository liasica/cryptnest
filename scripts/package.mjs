import { createHash } from 'node:crypto';
import { readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { resolve, sep } from 'node:path';

const directory = resolve('dist');
let html = await readFile(resolve(directory, 'index.html'), 'utf8');

async function readAsset(url) {
  const path = resolve(directory, url.replace(/^\.\//, ''));
  if (!path.startsWith(directory + sep)) throw new Error('构建资源路径无效');
  return readFile(path, 'utf8');
}

for (const match of html.matchAll(/<script\b[^>]*\bsrc="([^"]+)"[^>]*><\/script>/g)) {
  const script = (await readAsset(match[1])).replace(/<\/script/gi, '<\\/script');
  html = html.replace(match[0], `<script type="module">${script}</script>`);
}

for (const match of html.matchAll(/<link\b[^>]*rel="stylesheet"[^>]*href="([^"]+)"[^>]*>/g)) {
  const style = await readAsset(match[1]);
  html = html.replace(match[0], `<style>${style}</style>`);
}

const scriptHashes = [...html.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/g)].map(
  (match) => `'sha256-${createHash('sha256').update(match[1]).digest('base64')}'`,
);
const styleHashes = [...html.matchAll(/<style\b[^>]*>([\s\S]*?)<\/style>/g)].map(
  (match) => `'sha256-${createHash('sha256').update(match[1]).digest('base64')}'`,
);
if (scriptHashes.length === 0 || styleHashes.length === 0) throw new Error('独立 HTML 构建不完整');
if (/<(?:script|link)\b[^>]*(?:src|href)="(?:\.\/)?assets\//.test(html)) throw new Error('构建仍包含外部资源');

const policy = [
  "default-src 'none'",
  `script-src ${scriptHashes.join(' ')}`,
  `style-src ${styleHashes.join(' ')}`,
  'img-src data: blob:',
  'worker-src blob: data:',
  "connect-src 'none'",
  "object-src 'none'",
  "base-uri 'none'",
  "form-action 'none'",
].join('; ');
html = html.replace(/<meta charset="UTF-8"\s*\/>/, (tag) => `${tag}\n    <meta http-equiv="Content-Security-Policy" content="${policy}" />`);
await writeFile(resolve(directory, 'index.html'), html);
await writeFile(resolve(directory, 'cryptnest-offline.html'), html);
for (const entry of await readdir(directory)) {
  if (entry === 'assets') await rm(resolve(directory, entry), { recursive: true });
}
await writeFile(resolve(directory, '.nojekyll'), '');
console.log('独立 HTML 与离线版已生成，应用联网请求已禁用');
