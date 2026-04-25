/* ============================================================
   angou_crypto_core.js
   innerKey が無くてもパスフレーズだけで動く完全版
============================================================ */

const enc2 = new TextEncoder();

function concatU8(...arrays) {
  let len = 0;
  for (const a of arrays) len += a.length;
  const out = new Uint8Array(len);
  let off = 0;
  for (const a of arrays) {
    out.set(a, off);
    off += a.length;
  }
  return out;
}

/* ============================================================
   innerKey + passphrase → PBKDF2 → HKDF
   innerKey が無い場合は passphrase のみで動作
============================================================ */
async function deriveComplexKeys(passphrase, salt1, salt2, domain) {
  const passBytes = enc2.encode(passphrase);

  // ★ innerKey が無い場合 → passphrase のみで動作
  let baseMaterial;
  if (window.innerKey instanceof Uint8Array && window.innerKey.length > 0) {
    baseMaterial = concatU8(window.innerKey, passBytes);
  } else {
    baseMaterial = passBytes;
  }

  // PBKDF2
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    baseMaterial,
    { name: "PBKDF2" },
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: concatU8(salt1, salt2, enc2.encode(domain)),
      iterations: 200000,
      hash: "SHA-256"
    },
    keyMaterial,
    256 * 3
  );

  const all = new Uint8Array(bits);

  const encKeyBytes  = all.slice(0, 32);
  const macKey1Bytes = all.slice(32, 64);
  const macKey2Bytes = all.slice(64, 96);

  const encKey = await crypto.subtle.importKey(
    "raw",
    encKeyBytes,
    { name: "AES-CTR" },
    false,
    ["encrypt", "decrypt"]
  );

  const macKey1 = await crypto.subtle.importKey(
    "raw",
    macKey1Bytes,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );

  const macKey2 = await crypto.subtle.importKey(
    "raw",
    macKey2Bytes,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );

  return { encKey, macKey1, macKey2 };
}
