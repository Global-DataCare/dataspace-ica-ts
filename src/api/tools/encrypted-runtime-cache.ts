import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';

type CachedSecret = {
  ivB64: string;
  tagB64: string;
  ciphertextB64: string;
  expiresAtMs: number;
  staleUntilMs: number;
};

export class EncryptedRuntimeCache {
  private readonly sessionKey: Buffer<ArrayBuffer>;

  private readonly entries = new Map<string, CachedSecret>();

  constructor() {
    this.sessionKey = randomBytes(32);
  }

  set(key: string, value: string, ttlSeconds: number, staleIfErrorSeconds: number): void {
    const now = Date.now();
    const ttlMs = Math.max(0, Math.floor(ttlSeconds * 1000));
    const staleMs = Math.max(0, Math.floor(staleIfErrorSeconds * 1000));
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', this.sessionKey, iv);
    const ciphertext = Buffer.concat([cipher.update(value, 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();
    this.entries.set(key, {
      ivB64: iv.toString('base64'),
      tagB64: tag.toString('base64'),
      ciphertextB64: ciphertext.toString('base64'),
      expiresAtMs: now + ttlMs,
      staleUntilMs: now + ttlMs + staleMs,
    });
  }

  getFresh(key: string): string | undefined {
    const entry = this.entries.get(key);
    if (!entry) return undefined;
    if (Date.now() > entry.expiresAtMs) return undefined;
    return this.decrypt(entry);
  }

  getStaleIfAllowed(key: string): string | undefined {
    const entry = this.entries.get(key);
    if (!entry) return undefined;
    if (Date.now() > entry.staleUntilMs) return undefined;
    return this.decrypt(entry);
  }

  clear(): void {
    this.entries.clear();
  }

  private decrypt(entry: CachedSecret): string {
    const decipher = createDecipheriv(
      'aes-256-gcm',
      this.sessionKey,
      Buffer.from(entry.ivB64, 'base64'),
    );
    decipher.setAuthTag(Buffer.from(entry.tagB64, 'base64'));
    const plaintext = Buffer.concat([
      decipher.update(Buffer.from(entry.ciphertextB64, 'base64')),
      decipher.final(),
    ]);
    return plaintext.toString('utf8');
  }
}

