import { gcmsiv } from '@noble/ciphers/aes.js';
import { chacha20poly1305, xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import type { Cipher } from '@noble/ciphers/utils.js';

export const MAX_FILE_BYTES = 100 * 1024 * 1024;
export const MAX_CIPHER_BYTES = 110 * 1024 * 1024;
export const MAX_TEXT_BYTES = 1024 * 1024;
export const MAX_FILES = 1000;
const LEGACY_TEXT_PREFIX = 'cryptnest:v1:';
const MAGIC = Uint8Array.of(0x8d, 0x4c, 0xe9, 0x71, 0x2f, 0xb6, 0xa3, 0x03);
const PASSWORD_MAGIC = new TextEncoder().encode('CNEST001');
const ITERATIONS = 600_000;
const SALT_BYTES = 32;
const KEY_BYTES = 32;
const NONCE_BYTES = 24;
const PASSWORD_IV_BYTES = 12;
const TAG_BYTES = 16;
const WRAPPED_KEY_BYTES = 1 + KEY_BYTES + TAG_BYTES;
const MIN_HEADER_BYTES = 129;
const MAX_HEADER_BYTES = 381;
const FOOTER_BYTES = MAGIC.length + 8;
const PASSWORD_HEADER_BYTES = PASSWORD_MAGIC.length + 4 + SALT_BYTES + PASSWORD_IV_BYTES;

interface ContentAlgorithm {
  id: number;
  name: string;
  nonceBytes: number;
  cipher: (key: Uint8Array, nonce: Uint8Array, aad: Uint8Array) => Cipher;
}

const CONTENT_ALGORITHMS: readonly ContentAlgorithm[] = [
  { id: 1, name: 'XChaCha20-Poly1305', nonceBytes: 24, cipher: xchacha20poly1305 },
  { id: 2, name: 'ChaCha20-Poly1305', nonceBytes: 12, cipher: chacha20poly1305 },
  { id: 3, name: 'AES-256-GCM-SIV', nonceBytes: 12, cipher: gcmsiv },
];
let availableAlgorithms: readonly ContentAlgorithm[] | undefined;

class UnsupportedAlgorithmError extends Error {}

function getAvailableAlgorithms(): readonly ContentAlgorithm[] {
  if (availableAlgorithms) return availableAlgorithms;
  const sample = Uint8Array.of(0x27, 0xa6);
  availableAlgorithms = CONTENT_ALGORITHMS.filter((algorithm) => {
    const key = crypto.getRandomValues(new Uint8Array(KEY_BYTES));
    const nonce = crypto.getRandomValues(new Uint8Array(algorithm.nonceBytes));
    try {
      const encrypted = algorithm.cipher(key, nonce, MAGIC).encrypt(sample);
      const decrypted = algorithm.cipher(key, nonce, MAGIC).decrypt(encrypted);
      return decrypted.length === sample.length && decrypted.every((value, index) => value === sample[index]);
    } catch {
      return false;
    } finally {
      key.fill(0);
    }
  });
  return availableAlgorithms;
}

function randomIndex(length: number): number {
  const limit = 256 - 256 % length;
  let value: number;
  do { value = crypto.getRandomValues(new Uint8Array(1))[0]; } while (value >= limit);
  return value % length;
}

function automaticVersion(bytes: Uint8Array): 2 | 3 | null {
  if (bytes.length < FOOTER_BYTES) return null;
  const offset = bytes.length - FOOTER_BYTES;
  if (!MAGIC.subarray(0, MAGIC.length - 1).every((value, index) => bytes[offset + index] === value)) return null;
  const version = bytes[offset + MAGIC.length - 1];
  return version === 2 || version === 3 ? version : null;
}

export type ContentKind = 'zip' | 'text';

export interface ArchiveInput {
  path: string;
  data: ArrayBuffer;
  modified: number;
}

export type JobRequest =
  | { action: 'encrypt'; files: ArchiveInput[] }
  | { action: 'encrypt'; text: string }
  | { action: 'decrypt'; password: string; data: ArrayBuffer };

export type JobResponse =
  | { type: 'progress'; label: string; value: number }
  | { type: 'error'; message: string }
  | { type: 'result'; kind: ContentKind; data: ArrayBuffer; encrypted: boolean; algorithm: string; password?: string };

export function identifyCiphertext(data: ArrayBuffer): 'automatic' | 'password' | null {
  const bytes = new Uint8Array(data);
  if (bytes.length < MAGIC.length) return null;
  if (automaticVersion(bytes)) return 'automatic';
  if (PASSWORD_MAGIC.every((value, index) => bytes[index] === value)) return 'password';
  return null;
}

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

async function wrappingKey(version: 2 | 3): Promise<Uint8Array<ArrayBuffer>> {
  const bytes = new TextEncoder().encode(version === 2 ? 'CryptNest/v2/XChaCha20-Poly1305/key-envelope' : 'CryptNest/v3/algorithm-key-envelope');
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return new Uint8Array(digest);
}

function authenticatedEnvelope(header: Uint8Array, footer: Uint8Array): Uint8Array<ArrayBuffer> {
  const data = new Uint8Array(header.length + footer.length);
  data.set(header);
  data.set(footer, header.length);
  return data;
}

function readEnvelope(bytes: Uint8Array<ArrayBuffer>): {
  version: 2 | 3;
  header: Uint8Array<ArrayBuffer>;
  footer: Uint8Array<ArrayBuffer>;
  keyNonce: Uint8Array<ArrayBuffer>;
  wrappedKey: Uint8Array<ArrayBuffer>;
  nonce: Uint8Array<ArrayBuffer>;
  ciphertext: Uint8Array<ArrayBuffer>;
} {
  const version = automaticVersion(bytes);
  if (!version) throw new Error('加密包的格式版本不受支持。');
  const footer = bytes.subarray(bytes.length - FOOTER_BYTES);
  const parameters = new DataView(footer.buffer, footer.byteOffset, footer.byteLength);
  const headerSize = parameters.getUint16(MAGIC.length);
  const offsets = [2, 4, 6].map((offset) => parameters.getUint16(MAGIC.length + offset));
  const wrappedSize = version === 2 ? KEY_BYTES + TAG_BYTES : WRAPPED_KEY_BYTES;
  const lengths = [NONCE_BYTES, wrappedSize, NONCE_BYTES];
  const spans = offsets.map((start, index) => ({ start, end: start + lengths[index] })).sort((a, b) => a.start - b.start);
  const adjustment = version === 2 ? 1 : 0;
  if (headerSize < MIN_HEADER_BYTES - adjustment || headerSize > MAX_HEADER_BYTES - adjustment || bytes.length < headerSize + FOOTER_BYTES + TAG_BYTES + 1
    || spans.some((span, index) => span.start < 8 || span.end > headerSize - 8 || (index > 0 && span.start < spans[index - 1].end))) {
    throw new Error('加密包的封装参数无效。');
  }
  const header = bytes.subarray(0, headerSize);
  return {
    version,
    header,
    footer,
    keyNonce: header.subarray(offsets[0], offsets[0] + NONCE_BYTES),
    wrappedKey: header.subarray(offsets[1], offsets[1] + wrappedSize),
    nonce: header.subarray(offsets[2], offsets[2] + NONCE_BYTES),
    ciphertext: bytes.subarray(headerSize, bytes.length - FOOTER_BYTES),
  };
}

export async function encryptContent(
  data: Uint8Array<ArrayBuffer>,
  kind: ContentKind,
  progress: (label: string, value: number) => void = () => {},
): Promise<{ data: ArrayBuffer; password: string; algorithm: string }> {
  const candidates = getAvailableAlgorithms();
  if (!candidates.some((algorithm) => algorithm.id === 1)) {
    throw new UnsupportedAlgorithmError('当前浏览器不支持密钥封装，请使用最新版浏览器。');
  }
  const algorithm = candidates[randomIndex(candidates.length)];
  const lengths = [NONCE_BYTES, WRAPPED_KEY_BYTES, NONCE_BYTES];
  const gaps = Array.from(crypto.getRandomValues(new Uint8Array(4)), (value) => 8 + (value & 63));
  const order = [0, 1, 2];
  for (let index = order.length - 1; index > 0; index--) {
    const chosen = randomIndex(index + 1);
    [order[index], order[chosen]] = [order[chosen], order[index]];
  }
  const headerSize = lengths.reduce((total, length) => total + length, 0) + gaps.reduce((total, gap) => total + gap, 0);
  const header = crypto.getRandomValues(new Uint8Array(headerSize));
  const offsets = [0, 0, 0];
  let cursor = gaps[0];
  for (const [index, part] of order.entries()) {
    offsets[part] = cursor;
    cursor += lengths[part] + gaps[index + 1];
  }
  const footer = new Uint8Array(FOOTER_BYTES);
  footer.set(MAGIC);
  const parameters = new DataView(footer.buffer);
  parameters.setUint16(MAGIC.length, header.length);
  offsets.forEach((offset, index) => parameters.setUint16(MAGIC.length + 2 + index * 2, offset));
  const rawKey = crypto.getRandomValues(new Uint8Array(KEY_BYTES));
  const metadata = new Uint8Array(1 + KEY_BYTES);
  metadata[0] = algorithm.id;
  metadata.set(rawKey, 1);
  let envelopeKey: Uint8Array<ArrayBuffer> | undefined;
  const payload = new Uint8Array(data.byteLength + 1);
  payload[0] = kind === 'zip' ? 1 : 2;
  payload.set(data, 1);
  try {
    progress('正在封装随机密钥……', 60);
    envelopeKey = await wrappingKey(3);
    const keyNonce = header.subarray(offsets[0], offsets[0] + NONCE_BYTES);
    const wrapped = xchacha20poly1305(envelopeKey, keyNonce, footer).encrypt(metadata);
    header.set(wrapped, offsets[1]);
    progress('正在加密内容……', 85);
    const nonce = header.subarray(offsets[2], offsets[2] + algorithm.nonceBytes);
    const ciphertext = algorithm.cipher(rawKey, nonce, authenticatedEnvelope(header, footer)).encrypt(payload);
    const output = new Uint8Array(header.length + ciphertext.byteLength + footer.length);
    output.set(header);
    output.set(ciphertext, header.length);
    output.set(footer, header.length + ciphertext.length);
    const password = btoa(String.fromCharCode(...rawKey)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    return { data: output.buffer, password, algorithm: algorithm.name };
  } finally {
    rawKey.fill(0);
    metadata.fill(0);
    envelopeKey?.fill(0);
    payload.fill(0);
  }
}

export async function decryptContent(
  data: ArrayBuffer,
  password = '',
  progress: (label: string, value: number) => void = () => {},
): Promise<{ kind: ContentKind; data: ArrayBuffer; algorithm: string }> {
  if (data.byteLength < PASSWORD_HEADER_BYTES + TAG_BYTES + 1 || data.byteLength > MAX_CIPHER_BYTES) {
    throw new Error('加密包大小无效，请选择完整的 CryptNest 加密文件。');
  }
  const bytes = new Uint8Array(data);
  const format = identifyCiphertext(data);
  if (!format) {
    throw new Error('无法识别此文件，请选择 .cryptnest 加密包。');
  }
  let payload: Uint8Array;
  let algorithmName: string;
  try {
    if (format === 'automatic') {
      progress('正在还原解密密钥……', 45);
      const envelope = readEnvelope(bytes);
      const envelopeKey = await wrappingKey(envelope.version);
      let metadata: Uint8Array | undefined;
      try {
        metadata = xchacha20poly1305(envelopeKey, envelope.keyNonce, envelope.footer).decrypt(envelope.wrappedKey);
        const id = envelope.version === 2 ? 1 : metadata[0];
        const algorithm = CONTENT_ALGORITHMS.find((candidate) => candidate.id === id);
        if (!algorithm) throw new UnsupportedAlgorithmError('加密包使用了不支持的算法，请更新应用后重试。');
        if (!getAvailableAlgorithms().some((candidate) => candidate.id === id)) {
          throw new UnsupportedAlgorithmError('当前浏览器不支持此加密包使用的算法，请更换浏览器。');
        }
        const rawKey = envelope.version === 2 ? metadata : metadata.subarray(1);
        progress('正在解密内容……', 80);
        payload = algorithm.cipher(rawKey, envelope.nonce.subarray(0, algorithm.nonceBytes), authenticatedEnvelope(envelope.header, envelope.footer)).decrypt(envelope.ciphertext);
        algorithmName = algorithm.name;
      } finally {
        metadata?.fill(0);
        envelopeKey.fill(0);
      }
    } else {
      if (new DataView(data).getUint32(PASSWORD_MAGIC.length) !== ITERATIONS) {
        throw new Error('此加密包的参数不受支持。');
      }
      progress('正在验证密码……', 45);
      const header = bytes.slice(0, PASSWORD_HEADER_BYTES);
      const iv = header.slice(PASSWORD_HEADER_BYTES - PASSWORD_IV_BYTES);
      const salt = header.slice(PASSWORD_MAGIC.length + 4, PASSWORD_MAGIC.length + 4 + SALT_BYTES);
      const key = await deriveKey(password, salt);
      progress('正在解密内容……', 80);
      payload = new Uint8Array(await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv, additionalData: header, tagLength: 128 },
        key,
        bytes.subarray(PASSWORD_HEADER_BYTES),
      ));
      algorithmName = 'AES-256-GCM';
    }
  } catch (error) {
    if (error instanceof UnsupportedAlgorithmError) throw error;
    if (format === 'automatic') throw new Error('加密内容已损坏，请重新选择文件或复制完整密文。');
    if (error instanceof DOMException && error.name === 'OperationError') {
      throw new Error('密码错误或加密包已损坏，请检查密码与文件。');
    }
    throw error;
  }
  try {
    if (payload[0] !== 1 && payload[0] !== 2) throw new Error('加密包中的内容类型不受支持。');
    const kind: ContentKind = payload[0] === 1 ? 'zip' : 'text';
    if (kind === 'text' && payload.byteLength - 1 > MAX_TEXT_BYTES) {
      throw new Error('加密包中的文本超过 1 MiB。');
    }
    return { kind, data: payload.slice(1).buffer, algorithm: algorithmName };
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
  return btoa(pieces.join(''));
}

export function decodeCiphertext(text: string): ArrayBuffer {
  const copied = parseCopiedCiphertext(text);
  const value = copied.ciphertext.replace(/\s/g, '');
  const base64 = value.startsWith(LEGACY_TEXT_PREFIX) ? value.slice(LEGACY_TEXT_PREFIX.length) : value;
  if (base64.length > 2 * 1024 * 1024) throw new Error('文本密文过长，请改用文件解密。');
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(base64) || base64.length % 4 !== 0) {
    throw new Error('密文格式不完整，请重新复制完整密文。');
  }
  try {
    const data = Uint8Array.from(atob(base64), (character) => character.charCodeAt(0)).buffer;
    if (!identifyCiphertext(data)) throw new Error('无法识别密文');
    return data;
  } catch {
    throw new Error('密文格式无效，请重新复制完整密文。');
  }
}

export function parseCopiedCiphertext(text: string): { ciphertext: string; password?: string } {
  const separator = text.lastIndexOf('\n密码：');
  if (separator < 0) return { ciphertext: text };
  const password = text.slice(separator + '\n密码：'.length).replace(/(?:\r?\n)+$/, '');
  if (password.length === 0 || password.length > 1024 || /[\r\n]/.test(password)) return { ciphertext: text };
  return { ciphertext: text.slice(0, separator).replace(/\r$/, ''), password };
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
