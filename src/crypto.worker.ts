import { zipSync } from 'fflate';
import type { Zippable } from 'fflate';
import { decryptContent, encryptContent, MAX_FILE_BYTES, MAX_FILES, MAX_TEXT_BYTES, normalizePath } from './crypto';
import type { JobRequest, JobResponse } from './crypto';

const scope = globalThis as unknown as {
  onmessage: ((event: MessageEvent<JobRequest>) => void) | null;
  postMessage: (message: JobResponse, transfer?: Transferable[]) => void;
};

function progress(label: string, value: number): void {
  scope.postMessage({ type: 'progress', label, value });
}

scope.onmessage = async (event) => {
  const request = event.data;
  let sensitive: Uint8Array<ArrayBuffer> | undefined;
  try {
    if (!crypto.subtle) throw new Error('浏览器不支持加密功能，请使用最新版浏览器并通过 HTTPS 或离线版打开。');
    if (request.action === 'decrypt') {
      const result = await decryptContent(request.data, request.password, progress);
      scope.postMessage({ type: 'result', ...result, encrypted: false }, [result.data]);
      return;
    }
    let kind: 'zip' | 'text';
    if ('files' in request) {
      if (request.files.length === 0 || request.files.length > MAX_FILES) throw new Error('请选择 1 至 1,000 个文件。');
      if (request.files.reduce((total, file) => total + file.data.byteLength, 0) > MAX_FILE_BYTES) {
        throw new Error('文件总大小不能超过 100 MiB。');
      }
      progress('正在打包 ZIP 归档……', 35);
      const archive: Zippable = Object.create(null) as Zippable;
      for (const file of request.files) {
        const path = normalizePath(file.path);
        if (Object.hasOwn(archive, path)) throw new Error('存在重复文件路径，请重新选择文件。');
        const modified = new Date(file.modified);
        const mtime = Number.isFinite(modified.getTime()) && modified.getFullYear() >= 1980 && modified.getFullYear() <= 2099 ? modified : new Date();
        archive[path] = [new Uint8Array(file.data), { mtime }];
      }
      sensitive = new Uint8Array(zipSync(archive, { level: 6 }));
      kind = 'zip';
    } else {
      sensitive = new TextEncoder().encode(request.text);
      if (sensitive.byteLength === 0 || sensitive.byteLength > MAX_TEXT_BYTES) throw new Error('请输入内容不超过 1 MiB 的文本。');
      kind = 'text';
    }
    const data = await encryptContent(sensitive, kind, request.password, progress);
    scope.postMessage({ type: 'result', kind, data, encrypted: true }, [data]);
  } catch (error) {
    scope.postMessage({ type: 'error', message: error instanceof Error ? error.message : '处理失败，请重新选择内容后重试。' });
  } finally {
    sensitive?.fill(0);
    if (request.action === 'encrypt' && 'files' in request) {
      for (const file of request.files) new Uint8Array(file.data).fill(0);
    }
    request.password = '';
  }
};
