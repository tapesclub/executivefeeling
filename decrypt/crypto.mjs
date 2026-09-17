// Pure crypto module: no DOM, no storage. Shared verbatim by the decoder page and the
// private authoring tool so the two can never drift.
//
// Contract:
//   key        -> normalized to exactly 24 hex characters (see normalizeKey)
//   passphrase -> normalized to A-Z only (see normalizePassphrase)
//   PBKDF2-SHA-256, 600 000 iterations,
//     password = UTF-8 bytes of the normalized passphrase,
//     salt     = UTF-8 bytes of the normalized 24-character key string (NOT hex-decoded)
//   -> AES-256-GCM key; each blob = { iv: base64(12 random bytes), ct: base64(ciphertext||tag) }

export const KEY_HEX_LENGTH = 24;
export const PBKDF2_ITERATIONS = 600000;
export const IV_BYTES = 12;

const subtle = globalThis.crypto.subtle;
const enc = new TextEncoder();
const dec = new TextDecoder();

export function normalizeKey(input) {
  let s = String(input ?? "").trim().toUpperCase();
  s = s.replace(/^KEY\s*:?\s*/, "");
  s = s.replace(/[\s\-–—_]/g, "");
  s = s.replace(/O/g, "0");
  if (s.length === 0) return { ok: false, error: "enter the key" };
  if (/[^0-9A-F]/.test(s)) return { ok: false, error: "keys contain only 0–9 and A–F" };
  if (s.length !== KEY_HEX_LENGTH) return { ok: false, error: `the key is ${KEY_HEX_LENGTH} characters` };
  return { ok: true, value: s };
}

export function normalizePassphrase(input) {
  let s = String(input ?? "").trim().toUpperCase();
  s = s.replace(/[\s\-–—_]/g, "");
  if (s.length === 0) return { ok: false, error: "enter a passphrase" };
  if (/[^A-Z]/.test(s)) return { ok: false, error: "passphrases contain only letters" };
  return { ok: true, value: s };
}

export async function deriveKey(normalizedPassphrase, normalizedKey) {
  const material = await subtle.importKey("raw", enc.encode(normalizedPassphrase), "PBKDF2", false, ["deriveKey"]);
  return subtle.deriveKey(
    { name: "PBKDF2", hash: "SHA-256", salt: enc.encode(normalizedKey), iterations: PBKDF2_ITERATIONS },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

export function toBase64(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

export function fromBase64(str) {
  const s = atob(str);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

// Returns a blob {iv, ct}. A fresh random IV is generated on every call.
export async function encrypt(passphrase, key, plaintext) {
  const p = normalizePassphrase(passphrase);
  const k = normalizeKey(key);
  if (!p.ok) throw new Error(p.error);
  if (!k.ok) throw new Error(k.error);
  const aesKey = await deriveKey(p.value, k.value);
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const ct = new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv, tagLength: 128 }, aesKey, enc.encode(plaintext)));
  return { iv: toBase64(iv), ct: toBase64(ct) };
}

// Returns the plaintext string, or null if this key does not open this blob.
export async function decryptBlob(aesKey, blob) {
  try {
    const pt = await subtle.decrypt(
      { name: "AES-GCM", iv: fromBase64(blob.iv), tagLength: 128 },
      aesKey,
      fromBase64(blob.ct)
    );
    return dec.decode(pt);
  } catch {
    return null;
  }
}

// Derives once, tries every blob. Returns { ok, plaintext } or { ok:false, error }.
export async function tryDecryptAll(passphrase, key, blobs) {
  const p = normalizePassphrase(passphrase);
  if (!p.ok) return { ok: false, error: p.error };
  const k = normalizeKey(key);
  if (!k.ok) return { ok: false, error: k.error };
  const aesKey = await deriveKey(p.value, k.value);
  for (const blob of blobs) {
    const pt = await decryptBlob(aesKey, blob);
    if (pt !== null) return { ok: true, plaintext: pt };
  }
  return { ok: false, error: "nothing decrypted" };
}
