export const MAX_FILE_BYTES = 100 * 1024 * 1024;
export const MAX_CIPHER_BYTES = 110 * 1024 * 1024;
export const MAX_TEXT_BYTES = 1024 * 1024;
export const MAX_FILES = 1000;
export const TEXT_PREFIX = 'cryptnest:v1:';

const MAGIC = new TextEncoder().encode('CNEST001');
const ITERATIONS = 600_000;
const SALT_BYTES = 32;
const IV_BYTES = 12;
const HEADER_BYTES = MAGIC.length + 4 + SALT_BYTES + IV_BYTES;
const TAG_BYTES = 16;

export type ContentKind = 'zip' | 'text';

export interface ArchiveInput {
  path: string;
  data: ArrayBuffer;
  modified: number;
}

export type JobRequest =
  | { action: 'encrypt'; password: string; files: ArchiveInput[] }
  | { action: 'encrypt'; password: string; text: string }
  | { action: 'decrypt'; password: string; data: ArrayBuffer };

export type JobResponse =
  | { type: 'progress'; label: string; value: number }
  | { type: 'error'; message: string }
  | { type: 'result'; kind: ContentKind; data: ArrayBuffer; encrypted: boolean };

export function validatePassword(password: string): void {
  if (password.length === 0) throw new Error('请输入密码。');
  if (password.length > 1024) throw new Error('密码不能超过 1,024 个字符。');
}

async function deriveKey(password: string, salt: Uint8Array<ArrayBuffer>): Promise<CryptoKey> {
  validatePassword(password);
  const passwordBytes = new TextEncoder().encode(password);
  try {
    const material = await crypto.subtle.importKey('raw', passwordBytes, 'PBKDF2', false, ['deriveKey']);
    return await crypto.subtle.deriveKey(
      { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: ITERATIONS },
      material,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt'],
    );
  } finally {
    passwordBytes.fill(0);
  }
}

export async function encryptContent(
  data: Uint8Array<ArrayBuffer>,
  kind: ContentKind,
  password: string,
  progress: (label: string, value: number) => void = () => {},
): Promise<ArrayBuffer> {
  const header = new Uint8Array(HEADER_BYTES);
  header.set(MAGIC);
  new DataView(header.buffer).setUint32(MAGIC.length, ITERATIONS);
  const salt = crypto.getRandomValues(new Uint8Array(SALT_BYTES));
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  header.set(salt, MAGIC.length + 4);
  header.set(iv, MAGIC.length + 4 + SALT_BYTES);
  const payload = new Uint8Array(data.byteLength + 1);
  payload[0] = kind === 'zip' ? 1 : 2;
  payload.set(data, 1);
  try {
    progress('正在生成密码密钥……', 60);
    const key = await deriveKey(password, salt);
    progress('正在加密内容……', 85);
    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv, additionalData: header, tagLength: 128 },
      key,
      payload,
    );
    const output = new Uint8Array(HEADER_BYTES + ciphertext.byteLength);
    output.set(header);
    output.set(new Uint8Array(ciphertext), HEADER_BYTES);
    return output.buffer;
  } finally {
    payload.fill(0);
  }
}

export async function decryptContent(
  data: ArrayBuffer,
  password: string,
  progress: (label: string, value: number) => void = () => {},
): Promise<{ kind: ContentKind; data: ArrayBuffer }> {
  if (data.byteLength < HEADER_BYTES + TAG_BYTES + 1 || data.byteLength > MAX_CIPHER_BYTES) {
    throw new Error('加密包大小无效，请选择完整的 CryptNest 加密文件。');
  }
  const bytes = new Uint8Array(data);
  if (!MAGIC.every((value, index) => bytes[index] === value)) {
    throw new Error('无法识别此文件，请选择 .cryptnest 加密包。');
  }
  if (new DataView(data).getUint32(MAGIC.length) !== ITERATIONS) {
    throw new Error('此加密包的参数不受支持。');
  }
  const header = bytes.slice(0, HEADER_BYTES);
  const salt = header.slice(MAGIC.length + 4, MAGIC.length + 4 + SALT_BYTES);
  const iv = header.slice(MAGIC.length + 4 + SALT_BYTES);
  progress('正在验证密码……', 45);
  const key = await deriveKey(password, salt);
  progress('正在解密内容……', 80);
  let plaintext: ArrayBuffer;
  try {
    plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv, additionalData: header, tagLength: 128 },
      key,
      bytes.subarray(HEADER_BYTES),
    );
  } catch (error) {
    if (error instanceof DOMException && error.name === 'OperationError') {
      throw new Error('密码错误或加密包已损坏，请检查密码与文件。');
    }
    throw error;
  }
  const payload = new Uint8Array(plaintext);
  try {
    if (payload[0] !== 1 && payload[0] !== 2) throw new Error('加密包中的内容类型不受支持。');
    const kind: ContentKind = payload[0] === 1 ? 'zip' : 'text';
    if (kind === 'text' && payload.byteLength - 1 > MAX_TEXT_BYTES) {
      throw new Error('加密包中的文本超过 1 MiB。');
    }
    return { kind, data: payload.slice(1).buffer };
  } finally {
    payload.fill(0);
  }
}

export function encodeCiphertext(data: ArrayBuffer): string {
  const bytes = new Uint8Array(data);
  const pieces: string[] = [];
  for (let offset = 0; offset < bytes.length; offset += 0x8000) {
    pieces.push(String.fromCharCode(...bytes.subarray(offset, offset + 0x8000)));
  }
  return TEXT_PREFIX + btoa(pieces.join(''));
}

export function decodeCiphertext(text: string): ArrayBuffer {
  const value = text.replace(/\s/g, '');
  if (!value.startsWith(TEXT_PREFIX)) throw new Error('请粘贴以 cryptnest:v1: 开头的完整密文。');
  const base64 = value.slice(TEXT_PREFIX.length);
  if (base64.length > 2 * 1024 * 1024) throw new Error('文本密文过长，请改用文件解密。');
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(base64) || base64.length % 4 !== 0) {
    throw new Error('密文格式不完整，请重新复制完整密文。');
  }
  try {
    return Uint8Array.from(atob(base64), (character) => character.charCodeAt(0)).buffer;
  } catch {
    throw new Error('密文格式无效，请重新复制完整密文。');
  }
}

export function normalizePath(path: string): string {
  const parts = path.replace(/\\/g, '/').split('/').filter((part) => part !== '' && part !== '.');
  if (parts.length === 0 || parts.some((part) => part === '..' || /[\u0000-\u001f\u007f]/.test(part))) {
    throw new Error('文件路径包含无效字符，请修改文件名后重试。');
  }
  const normalized = parts.join('/');
  if (new TextEncoder().encode(normalized).length > 4096) throw new Error('文件路径过长，请缩短目录或文件名。');
  return normalized;
}

export function uniquePath(path: string, used: Set<string>): string {
  const normalized = normalizePath(path);
  let candidate = normalized;
  let suffix = 2;
  const slash = normalized.lastIndexOf('/');
  const dot = normalized.lastIndexOf('.');
  const extensionIndex = dot > slash + 1 ? dot : normalized.length;
  while (used.has(candidate)) {
    candidate = `${normalized.slice(0, extensionIndex)} (${suffix++})${normalized.slice(extensionIndex)}`;
  }
  used.add(candidate);
  return candidate;
}
