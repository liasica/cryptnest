import './style.css';
import brandLogo from './assets/cryptnest-logo.svg?raw';
import {
  Archive, Box, Check, CircleAlert, CodeXml, Copy, Download, Eye, EyeOff,
  File, FileCheck2, Files, FileText, FolderLock, FolderUp, Info, KeyRound, LockKeyhole,
  Monitor, Moon, Plus, ShieldCheck, Sun, TextCursorInput, UnlockKeyhole, X,
  createElement, createIcons,
} from 'lucide';
import CryptoWorker from './crypto.worker?worker&inline';
import { decodeCiphertext, encodeCiphertext, identifyCiphertext, MAX_CIPHER_BYTES, MAX_FILE_BYTES, MAX_FILES, MAX_TEXT_BYTES, parseCopiedCiphertext, uniquePath, validatePassword } from './crypto';
import type { ArchiveInput, JobRequest, JobResponse } from './crypto';

const initialHTML = '<!doctype html>\n' + document.documentElement.outerHTML;
const icons = { Archive, Box, Check, CircleAlert, CodeXml, Copy, Download, Eye, EyeOff, File, FileCheck2, Files, FileText, FolderLock, FolderUp, Info, KeyRound, LockKeyhole, Monitor, Moon, Plus, ShieldCheck, Sun, TextCursorInput, UnlockKeyhole, X };
createIcons({ icons });

function element<T extends HTMLElement = HTMLElement>(id: string): T {
  const result = document.getElementById(id);
  if (!result) throw new Error(`缺少界面元素：${id}`);
  return result as T;
}

element('brand-logo').innerHTML = brandLogo;

type ThemePreference = 'system' | 'light' | 'dark';
const systemTheme = window.matchMedia('(prefers-color-scheme: light)');
const themeButtons = document.querySelectorAll<HTMLButtonElement>('button[data-theme-preference]');

function applyTheme(preference: ThemePreference): void {
  const theme = preference === 'system' ? (systemTheme.matches ? 'light' : 'dark') : preference;
  document.documentElement.dataset.themePreference = preference;
  document.documentElement.dataset.theme = theme;
  for (const button of themeButtons) {
    const active = button.dataset.themePreference === preference;
    button.classList.toggle('is-active', active);
    button.setAttribute('aria-pressed', String(active));
  }
  for (const meta of document.querySelectorAll<HTMLMetaElement>('meta[name="theme-color"]')) {
    meta.media = meta.content === (theme === 'light' ? '#f5f6fc' : '#0b1020') ? 'all' : 'not all';
  }
}

for (const button of themeButtons) {
  button.addEventListener('click', () => {
    const preference = button.dataset.themePreference as ThemePreference;
    applyTheme(preference);
    try { localStorage.setItem('cryptnest-theme', preference); } catch {}
  });
}
systemTheme.addEventListener('change', () => {
  if (document.documentElement.dataset.themePreference === 'system') applyTheme('system');
});
applyTheme(document.documentElement.dataset.themePreference as ThemePreference);

const form = element<HTMLFormElement>('crypto-form');
const fileInput = element<HTMLInputElement>('file-input');
const folderInput = element<HTMLInputElement>('folder-input');
const dropzone = element('dropzone');
const sourceText = element<HTMLTextAreaElement>('source-text');
const password = element<HTMLInputElement>('password');
const copyPassword = element<HTMLInputElement>('copy-password');
const resultText = element<HTMLTextAreaElement>('result-text');
const resultPanel = element('result-panel');
const helpDialog = element<HTMLDialogElement>('help-dialog');

interface SelectedFile {
  id: number;
  file: File;
  path: string;
}

let mode: 'encrypt' | 'decrypt' = 'encrypt';
let source: 'files' | 'text' = 'files';
let selected: SelectedFile[] = [];
let nextFileId = 1;
let selectionVersion = 0;
let busy = false;
let worker: Worker | null = null;
let operation = 0;
let resultBlob: Blob | null = null;
let resultFilename = '';
let resultCopyText = '';
let resultPassword: string | null = null;
let needsPassword = false;
let toastTimer: ReturnType<typeof setTimeout>;

function replaceIcon(id: string, icon: typeof LockKeyhole): void {
  const previous = element(id);
  previous.replaceWith(createElement(icon, { id, 'aria-hidden': 'true' }));
}

function showToast(message: string): void {
  clearTimeout(toastTimer);
  const toast = element('toast');
  toast.textContent = message;
  toast.hidden = false;
  toastTimer = setTimeout(() => { toast.hidden = true; }, 3500);
}

function showError(message: string, field?: HTMLElement): void {
  element('error-text').textContent = message;
  element('error-message').hidden = false;
  field?.focus();
}

function invalidateResult(): void {
  resultBlob = null;
  resultFilename = '';
  resultCopyText = '';
  resultPassword = null;
  copyPassword.checked = false;
  element('copy-options').hidden = true;
  element('copy-password-note').hidden = true;
  resultText.value = '';
  resultPanel.hidden = true;
  element('error-message').hidden = true;
}

function formatBytes(size: number): string {
  if (size < 1024) return `${size} B`;
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KiB`;
  return `${(size / (1024 * 1024)).toFixed(1)} MiB`;
}

function renderFiles(): void {
  const list = element<HTMLUListElement>('file-list');
  list.replaceChildren();
  element('selection').hidden = selected.length === 0;
  element('selection-summary').textContent = `${selected.length} 个文件，共 ${formatBytes(selected.reduce((total, item) => total + item.file.size, 0))}`;
  for (const item of selected) {
    const row = document.createElement('li');
    const name = document.createElement('span');
    name.className = 'file-name';
    name.textContent = item.path;
    name.title = item.path;
    const size = document.createElement('span');
    size.className = 'file-size';
    size.textContent = formatBytes(item.file.size);
    const remove = document.createElement('button');
    remove.type = 'button';
    remove.className = 'remove-file';
    remove.setAttribute('aria-label', `移除 ${item.path}`);
    remove.append(createElement(X, { 'aria-hidden': 'true' }));
    remove.addEventListener('click', () => {
      if (busy) return;
      selected = selected.filter((file) => file.id !== item.id);
      selectionVersion++;
      invalidateResult();
      renderFiles();
      void refreshPasswordRequirement();
    });
    row.append(createElement(File, { 'aria-hidden': 'true' }), name, size, remove);
    list.append(row);
  }
}

function clearFiles(): void {
  selected = [];
  fileInput.value = '';
  folderInput.value = '';
  selectionVersion++;
  renderFiles();
  void refreshPasswordRequirement();
}

function setPasswordVisibility(visible: boolean): void {
  password.type = visible ? 'text' : 'password';
  const toggle = element<HTMLButtonElement>('toggle-password');
  toggle.setAttribute('aria-label', visible ? '隐藏密码' : '显示密码');
  toggle.setAttribute('aria-pressed', String(visible));
  toggle.replaceChildren(createElement(visible ? EyeOff : Eye, { 'aria-hidden': 'true' }));
}

function renderFlow(): void {
  const encrypting = mode === 'encrypt';
  const files = source === 'files';
  const stages = encrypting
    ? files
      ? [{ icon: Files, title: '选择文件', detail: '保留文件名与目录' }, { icon: Archive, title: '自动打包', detail: '生成 ZIP 归档' }, { icon: LockKeyhole, title: '随机密钥加密', detail: '下载 .cryptnest 文件' }]
      : [{ icon: FileText, title: '输入文本', detail: '保留文本与换行' }, { icon: LockKeyhole, title: '随机密钥加密', detail: '生成无前缀密文' }, { icon: Copy, title: '保存结果', detail: '复制密文或下载文件' }]
    : [{ icon: files ? FolderLock : FileText, title: files ? '选择加密包' : '粘贴密文', detail: files ? 'CryptNest 加密文件' : '完整的编码字符串' }, { icon: KeyRound, title: needsPassword ? '输入原密码' : '还原解密密钥', detail: needsPassword ? '验证密码与内容完整性' : '读取结果中封装的密钥' }, { icon: UnlockKeyhole, title: '还原内容', detail: '下载归档或复制文本' }];
  element('flow-title').textContent = encrypting ? (files ? '文件的加密流程' : '文本的加密流程') : '内容的解密流程';
  element('flow-description').textContent = encrypting
    ? (files ? '文件与目录结构一起打包，整个归档使用随机密钥加密。' : '文本使用随机密钥加密，生成可复制、可下载的密文。')
    : '应用还原封装后的密钥，再解密文件归档或原始文本。';
  const list = element<HTMLOListElement>('flow-list');
  list.replaceChildren();
  for (const [index, stage] of stages.entries()) {
    const row = document.createElement('li');
    const icon = document.createElement('span');
    icon.className = 'flow-icon';
    icon.append(createElement(stage.icon, { 'aria-hidden': 'true' }));
    const content = document.createElement('span');
    content.textContent = stage.title;
    const detail = document.createElement('strong');
    detail.textContent = stage.detail;
    content.append(detail);
    const order = document.createElement('span');
    order.className = 'flow-order';
    order.textContent = `0${index + 1}`;
    row.append(icon, content, order);
    list.append(row);
  }
  element('format-note').textContent = '持有完整加密结果，即可使用本应用解密。';
}

async function refreshPasswordRequirement(): Promise<void> {
  const version = selectionVersion;
  let required = false;
  try {
    if (mode === 'decrypt' && source === 'text') {
      required = identifyCiphertext(decodeCiphertext(sourceText.value)) === 'password';
    } else if (mode === 'decrypt' && selected.length === 1) {
      const data = await selected[0].file.slice(0, 8).arrayBuffer();
      if (version !== selectionVersion || mode !== 'decrypt' || source !== 'files') return;
      required = identifyCiphertext(data) === 'password';
    }
  } catch {
    required = false;
  }
  needsPassword = required;
  element('password-section').hidden = !required;
  if (!required) password.value = '';
  renderFlow();
}

function renderMode(): void {
  const encrypting = mode === 'encrypt';
  document.body.dataset.mode = mode;
  document.querySelectorAll<HTMLButtonElement>('button[data-mode]').forEach((button) => {
    const active = button.dataset.mode === mode;
    button.classList.toggle('is-active', active);
    button.setAttribute('aria-pressed', String(active));
  });
  document.querySelectorAll<HTMLButtonElement>('button[data-source]').forEach((button) => {
    const active = button.dataset.source === source;
    button.classList.toggle('is-active', active);
    button.setAttribute('aria-pressed', String(active));
  });
  element('files-pane').hidden = source !== 'files';
  element('text-pane').hidden = source !== 'text';
  element('mode-caption').textContent = encrypting ? '创建加密包' : '还原加密内容';
  element('source-heading').textContent = encrypting ? '选择加密内容' : '选择解密内容';
  element('drop-title').textContent = encrypting ? '将文件拖到这里' : '拖入 CryptNest 加密包';
  element('drop-description').textContent = encrypting ? '支持多文件与文件夹，总大小不超过 100 MiB' : '选择加密时下载的 .cryptnest 文件';
  element('select-files').lastChild!.textContent = encrypting ? '选择文件' : '选择加密包';
  element('select-folder').hidden = !encrypting;
  element('drop-footnote').lastChild!.textContent = encrypting ? '加密前自动打包为 ZIP' : '每次解密一个加密包';
  dropzone.setAttribute('aria-label', encrypting ? '选择或拖入文件' : '选择或拖入 CryptNest 加密包');
  replaceIcon('drop-icon', encrypting ? FolderUp : FolderLock);
  element('text-label').textContent = encrypting ? '需要加密的文本' : '需要解密的密文';
  sourceText.placeholder = encrypting ? '在这里输入需要加密的文本……' : '粘贴完整密文，或包含密码的复制内容……';
  element('text-hint').textContent = encrypting ? '保留原始文本与换行' : '支持分行密文与附带密码的内容';
  element('key-info').hidden = !encrypting;
  element('submit-label').textContent = encrypting ? (source === 'files' ? '加密并生成文件' : '加密文本') : (source === 'files' ? '解密并还原内容' : '解密文本');
  replaceIcon('submit-icon', encrypting ? LockKeyhole : UnlockKeyhole);
  element('output-hint').textContent = encrypting
    ? (source === 'files' ? '输出 .cryptnest 加密包，解密后得到 ZIP 文件' : '输出可复制的密文，也可下载为 .cryptnest 文件')
    : '文件归档还原为 ZIP，文本内容可复制或下载';
  fileInput.multiple = encrypting;
  fileInput.accept = encrypting ? '' : '.cryptnest';
  renderFlow();
  void refreshPasswordRequirement();
}

function addFiles(incoming: { file: File; path: string }[]): void {
  if (busy) return;
  if (incoming.length === 0) throw new Error('没有读取到文件，请选择包含文件的文件夹。');
  if (mode === 'decrypt') {
    if (incoming.length !== 1) throw new Error('每次只能解密一个加密包。');
    if (incoming[0].file.size > MAX_CIPHER_BYTES) throw new Error('加密包不能超过 110 MiB。');
    selected = [{ ...incoming[0], id: nextFileId++ }];
  } else {
    if (incoming.length + selected.length > MAX_FILES) throw new Error('一次最多加密 1,000 个文件。');
    const total = [...selected, ...incoming].reduce((size, item) => size + item.file.size, 0);
    if (total > MAX_FILE_BYTES) throw new Error('文件总大小不能超过 100 MiB，请分批处理。');
    const paths = new Set(selected.map((file) => file.path));
    const prepared = incoming.map((item) => ({ ...item, path: uniquePath(item.path, paths), id: nextFileId++ }));
    selected.push(...prepared);
  }
  selectionVersion++;
  invalidateResult();
  renderFiles();
  void refreshPasswordRequirement();
}

fileInput.addEventListener('change', () => {
  try {
    addFiles(Array.from(fileInput.files ?? []).map((file) => ({ file, path: file.name })));
  } catch (error) { showError(error instanceof Error ? error.message : '读取文件失败。'); }
  fileInput.value = '';
});
folderInput.addEventListener('change', () => {
  try {
    addFiles(Array.from(folderInput.files ?? []).map((file) => ({ file, path: file.webkitRelativePath || file.name })));
  } catch (error) { showError(error instanceof Error ? error.message : '读取文件夹失败。'); }
  folderInput.value = '';
});

element('select-files').addEventListener('click', (event) => { event.stopPropagation(); fileInput.click(); });
element('select-folder').addEventListener('click', (event) => { event.stopPropagation(); folderInput.click(); });
dropzone.addEventListener('click', () => { if (!busy) fileInput.click(); });
dropzone.addEventListener('keydown', (event) => {
  if (event.target !== dropzone) return;
  if ((event.key === 'Enter' || event.key === ' ') && !busy) { event.preventDefault(); fileInput.click(); }
});
element('clear-files').addEventListener('click', () => { clearFiles(); invalidateResult(); });

async function collectEntry(entry: FileSystemEntry, output: { file: File; path: string }[], depth = 0): Promise<void> {
  if (depth > 32) throw new Error('文件夹层级不能超过 32 层。');
  if (entry.isFile) {
    if (output.length >= MAX_FILES) throw new Error('一次最多加密 1,000 个文件。');
    const file = await new Promise<File>((resolve, reject) => (entry as FileSystemFileEntry).file(resolve, reject));
    output.push({ file, path: entry.fullPath.replace(/^\//, '') || file.name });
  } else if (entry.isDirectory) {
    const reader = (entry as FileSystemDirectoryEntry).createReader();
    while (true) {
      const entries = await new Promise<FileSystemEntry[]>((resolve, reject) => reader.readEntries(resolve, reject));
      if (entries.length === 0) break;
      for (const child of entries) await collectEntry(child, output, depth + 1);
    }
  }
}

let dragDepth = 0;
dropzone.addEventListener('dragenter', (event) => {
  event.preventDefault();
  if (!busy) { dragDepth++; dropzone.classList.add('drag-over'); }
});
dropzone.addEventListener('dragover', (event) => { event.preventDefault(); if (event.dataTransfer) event.dataTransfer.dropEffect = busy ? 'none' : 'copy'; });
dropzone.addEventListener('dragleave', (event) => {
  event.preventDefault();
  dragDepth = Math.max(0, dragDepth - 1);
  if (dragDepth === 0) dropzone.classList.remove('drag-over');
});
dropzone.addEventListener('drop', async (event) => {
  event.preventDefault();
  dragDepth = 0;
  dropzone.classList.remove('drag-over');
  if (busy || !event.dataTransfer) return;
  const version = selectionVersion;
  const fallback = Array.from(event.dataTransfer.files);
  const entries = Array.from(event.dataTransfer.items).filter((item) => item.kind === 'file').map((item) => item.webkitGetAsEntry?.());
  try {
    const incoming: { file: File; path: string }[] = [];
    if (entries.length > 0 && entries.every((entry) => entry != null)) {
      if (mode === 'decrypt' && entries.some((entry) => entry?.isDirectory)) throw new Error('请拖入单个 .cryptnest 加密文件。');
      for (const entry of entries) if (entry) await collectEntry(entry, incoming);
    } else {
      incoming.push(...fallback.map((file) => ({ file, path: file.name })));
    }
    if (selectionVersion === version) addFiles(incoming);
  } catch (error) { showError(error instanceof Error ? error.message : '读取拖入的文件失败。'); }
});
window.addEventListener('dragover', (event) => { event.preventDefault(); });
window.addEventListener('drop', (event) => { event.preventDefault(); });

document.querySelectorAll<HTMLButtonElement>('button[data-mode]').forEach((button) => {
  button.addEventListener('click', () => {
    if (busy || button.dataset.mode === mode) return;
    mode = button.dataset.mode === 'decrypt' ? 'decrypt' : 'encrypt';
    clearFiles();
    sourceText.value = '';
    password.value = '';
    setPasswordVisibility(false);
    invalidateResult();
    element('text-count').textContent = '0 个字符';
    renderMode();
  });
});
document.querySelectorAll<HTMLButtonElement>('button[data-source]').forEach((button) => {
  button.addEventListener('click', () => {
    if (busy || button.dataset.source === source) return;
    source = button.dataset.source === 'text' ? 'text' : 'files';
    invalidateResult();
    renderMode();
  });
});
sourceText.addEventListener('input', () => {
  invalidateResult();
  if (mode === 'decrypt') {
    const copied = parseCopiedCiphertext(sourceText.value);
    if (copied.password !== undefined) {
      try {
        const format = identifyCiphertext(decodeCiphertext(copied.ciphertext));
        sourceText.value = copied.ciphertext;
        if (format === 'password') { password.value = copied.password; setPasswordVisibility(false); }
      } catch {}
    }
  }
  element('text-count').textContent = `${sourceText.value.length.toLocaleString('zh-CN')} 个字符`;
  void refreshPasswordRequirement();
});
password.addEventListener('input', invalidateResult);
element('toggle-password').addEventListener('click', () => { setPasswordVisibility(password.type === 'password'); });

function updateCopyContent(): void {
  const includePassword = copyPassword.checked && resultPassword !== null;
  resultText.value = includePassword ? `${resultCopyText}\n密码：${resultPassword}` : resultCopyText;
  element('copy-password-note').hidden = !includePassword;
}
copyPassword.addEventListener('change', updateCopyContent);

function setBusy(value: boolean): void {
  busy = value;
  for (const control of form.querySelectorAll<HTMLInputElement | HTMLButtonElement | HTMLTextAreaElement>('button, input, textarea')) {
    if (control.id !== 'cancel-button') control.disabled = value;
  }
  document.querySelectorAll<HTMLButtonElement>('button[data-mode], button[data-source]').forEach((button) => { button.disabled = value; });
  dropzone.classList.toggle('is-busy', value);
  dropzone.setAttribute('aria-disabled', String(value));
  element('progress-section').hidden = !value;
  if (!value) renderMode();
  else element('submit-label').textContent = '正在处理……';
}

function updateProgress(label: string, value: number): void {
  element('progress-label').textContent = label;
  element<HTMLProgressElement>('progress-bar').value = value;
}

function cancelOperation(): void {
  operation++;
  worker?.terminate();
  worker = null;
  setBusy(false);
}
element('cancel-button').addEventListener('click', () => { cancelOperation(); showToast('已取消处理。'); });

function displayResult(message: Extract<JobResponse, { type: 'result' }>): void {
  const timestamp = new Date().toISOString().replace(/[-:]/g, '').slice(0, 15).replace('T', '-');
  const text = message.kind === 'text';
  const encrypted = message.encrypted;
  resultFilename = `cryptnest-${timestamp}.${encrypted ? 'cryptnest' : text ? 'txt' : 'zip'}`;
  resultBlob = new Blob([message.data], { type: encrypted ? 'application/octet-stream' : text ? 'text/plain;charset=utf-8' : 'application/zip' });
  element('result-title').textContent = encrypted ? '加密完成' : '解密完成';
  element('result-description').textContent = `${resultFilename} · ${formatBytes(message.data.byteLength)}`;
  resultText.hidden = !text;
  element('copy-result').hidden = !text;
  resultCopyText = text ? (encrypted ? encodeCiphertext(message.data) : new TextDecoder('utf-8', { fatal: true }).decode(message.data)) : '';
  resultPassword = text && encrypted ? message.password ?? null : null;
  copyPassword.checked = false;
  element('copy-options').hidden = resultPassword === null;
  updateCopyContent();
  element('download-label').textContent = encrypted ? '下载加密包' : text ? '下载文本' : '下载 ZIP 文件';
  element('copy-label').textContent = encrypted ? '复制密文' : '复制文本';
  resultPanel.hidden = false;
  password.value = '';
  setPasswordVisibility(false);
}

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  if (busy) return;
  invalidateResult();
  try {
    if (!crypto.subtle || !window.Worker) throw new Error('浏览器不支持加密功能，请使用最新版浏览器并通过 HTTPS 或离线版打开。');
    if (source === 'files' && selected.length === 0) { showError('请先选择文件。', dropzone); return; }
    if (source === 'text' && sourceText.value.length === 0) { showError('请先输入需要处理的文本。', sourceText); return; }
    if (mode === 'encrypt' && source === 'text' && new TextEncoder().encode(sourceText.value).byteLength > MAX_TEXT_BYTES) {
      showError('文本不能超过 1 MiB。', sourceText); return;
    }
    const id = ++operation;
    const secret = password.value;
    const text = sourceText.value;
    const files = [...selected];
    setBusy(true);
    updateProgress('正在读取内容……', 5);
    let request: JobRequest;
    let transfer: ArrayBuffer[];
    if (mode === 'decrypt') {
      const data = source === 'text' ? decodeCiphertext(text) : await files[0].file.arrayBuffer();
      if (id !== operation) return;
      if (identifyCiphertext(data) === 'password') {
        try { validatePassword(secret); } catch (error) {
          needsPassword = true;
          setBusy(false);
          element('password-section').hidden = false;
          showError((error as Error).message, password);
          return;
        }
      }
      request = { action: 'decrypt', password: secret, data };
      transfer = [data];
    } else if (source === 'text') {
      request = { action: 'encrypt', text };
      transfer = [];
    } else {
      const archive: ArchiveInput[] = [];
      for (const [index, item] of files.entries()) {
        const data = await item.file.arrayBuffer();
        if (id !== operation) { new Uint8Array(data).fill(0); for (const file of archive) new Uint8Array(file.data).fill(0); return; }
        archive.push({ path: item.path, data, modified: item.file.lastModified });
        updateProgress(`正在读取文件（${index + 1}/${files.length}）……`, 5 + Math.round(20 * (index + 1) / files.length));
      }
      request = { action: 'encrypt', files: archive };
      transfer = archive.map((file) => file.data);
    }
    if (id !== operation) return;
    const current = new CryptoWorker();
    worker = current;
    const finish = () => { current.terminate(); if (worker === current) worker = null; setBusy(false); };
    current.onmessage = (workerEvent: MessageEvent<JobResponse>) => {
      if (id !== operation) return;
      const message = workerEvent.data;
      if (message.type === 'progress') { updateProgress(message.label, message.value); return; }
      finish();
      if (message.type === 'error') { showError(message.message); return; }
      try { displayResult(message); } catch { invalidateResult(); showError('内容无法读取，请检查加密包是否完整。'); }
    };
    current.onerror = (workerError) => {
      workerError.preventDefault();
      if (id !== operation) return;
      finish();
      showError('处理失败，请刷新页面或减小文件大小后重试。');
    };
    current.postMessage(request, transfer);
    if (request.action === 'decrypt') request.password = '';
  } catch (error) {
    cancelOperation();
    showError(error instanceof Error ? error.message : '处理失败，请重试。');
  }
});

function download(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => { URL.revokeObjectURL(url); }, 60_000);
}
element('download-result').addEventListener('click', () => { if (resultBlob) download(resultBlob, resultFilename); });
element('copy-result').addEventListener('click', async () => {
  try {
    await navigator.clipboard.writeText(resultText.value);
    showToast(copyPassword.checked && resultPassword !== null ? '密文和密码已复制。' : '已复制。');
  } catch {
    resultText.focus();
    resultText.select();
    showToast('请在结果框中复制已选中的文本。');
  }
});
element('offline-button').addEventListener('click', () => {
  if (import.meta.env.DEV) { showToast('请在发布页面下载离线版。'); return; }
  download(new Blob([initialHTML], { type: 'text/html;charset=utf-8' }), 'cryptnest-offline.html');
});
element('help-button').addEventListener('click', () => { helpDialog.showModal(); });
element('close-help').addEventListener('click', () => { helpDialog.close(); });
helpDialog.addEventListener('click', (event) => {
  const bounds = helpDialog.getBoundingClientRect();
  if (event.target === helpDialog && (event.clientX < bounds.left || event.clientX > bounds.right || event.clientY < bounds.top || event.clientY > bounds.bottom)) helpDialog.close();
});
window.addEventListener('pagehide', () => {
  cancelOperation();
  password.value = '';
  sourceText.value = '';
  clearFiles();
  invalidateResult();
  element('text-count').textContent = '0 个字符';
});

renderMode();
if (!crypto.subtle || !window.Worker) showError('当前浏览器无法运行加密功能，请使用最新版浏览器并通过 HTTPS 或离线版打开。');
