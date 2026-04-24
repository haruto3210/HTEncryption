/* ============================================================
   angou_crypto_core.js
   複雑キー生成コア（PBKDF2 + HKDF + innerKey 混合）
   出力: encKey(32) / macKey1(32) / macKey2(32)
============================================================ */

const enc2 = new TextEncoder();
const strToU82 = s => enc2.encode(s);

/* -----------------------------
   HKDF（SHA-256）
----------------------------- */
async function hkdfExpand(master, info, length) {
  const macKey = await crypto.subtle.importKey(
    "raw", master,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const blocks = Math.ceil(length / 32);
  let okm = new Uint8Array(0);
  let prev = new Uint8Array(0);

  for (let i = 1; i <= blocks; i++) {
    const input = new Uint8Array(prev.length + info.length + 1);
    input.set(prev, 0);
    input.set(info, prev.length);
    input[input.length - 1] = i;

    const t = new Uint8Array(await crypto.subtle.sign("HMAC", macKey, input));
    okm = concatU8(okm, t);
    prev = t;
  }

  return okm.slice(0, length);
}

/* -----------------------------
   PBKDF2 + innerKey → masterKey
   masterKey → HKDF → encKey / macKey1 / macKey2
----------------------------- */
async function deriveComplexKeys(passphrase, salt1, salt2, domainTag) {
  let passBytes = strToU82(passphrase);

  // innerKey を混ぜる（軍用強化）
  if (window.innerKey) {
    passBytes = concatU8(passBytes, window.innerKey);
  }

  // PBKDF2（300,000回）
  const baseKey = await crypto.subtle.importKey(
    "raw", passBytes,
    { name: "PBKDF2" },
    false,
    ["deriveBits"]
  );

  const masterBits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: salt1,
      iterations: 300000,
      hash: "SHA-256"
    },
    baseKey,
    256
  );

  const masterKey = new Uint8Array(masterBits);

  // HKDF info
  const info = concatU8(
    strToU82("ANGOU-CTR-HMAC-CORE"),
    salt2,
    strToU82(domainTag)
  );

  // HKDF で 96byte 生成（32*3）
  const okm = await hkdfExpand(masterKey, info, 96);

  const encKeyBytes = okm.slice(0, 32);
  const macKey1Bytes = okm.slice(32, 64);
  const macKey2Bytes = okm.slice(64, 96);

  // AES-CTR 鍵
  const encKey = await crypto.subtle.importKey(
    "raw", encKeyBytes,
    { name: "AES-CTR" },
    false,
    ["encrypt", "decrypt"]
  );

  // HMAC 鍵1
  const macKey1 = await crypto.subtle.importKey(
    "raw", macKey1Bytes,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );

  // HMAC 鍵2
  const macKey2 = await crypto.subtle.importKey(
    "raw", macKey2Bytes,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );

  logHud("KEYGEN", "複雑キー生成完了（encKey + macKey1 + macKey2）");

  return { encKey, macKey1, macKey2 };
}

/* -----------------------------
   バイト配列結合
----------------------------- */
function concatU8(...arrays) {
  let len = 0;
  for (const a of arrays) len += a.length;

  const out = new Uint8Array(len);
  let offset = 0;

  for (const a of arrays) {
    out.set(a, offset);
    offset += a.length;
  }

  return out;
}
