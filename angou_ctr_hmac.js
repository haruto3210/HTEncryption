/* ============================================================
   angou_ctr_hmac.js
   AES‑CTR + HMAC2段 暗号化/復号（テキスト & ファイル）
   innerKey + PBKDF2 + HKDF（複雑キー）
============================================================ */

const enc3 = new TextEncoder();
const dec3 = new TextDecoder();

const strToU83 = s => enc3.encode(s);
const u8ToStr3 = u => dec3.decode(u);
const u8ToB64 = u => btoa(String.fromCharCode(...u));
const b64ToU8 = b64 => new Uint8Array([...atob(b64)].map(c => c.charCodeAt(0)));

function concatU83(...arrays) {
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
   LZ圧縮（Base64）
============================================================ */
const LZ = {
  compress(str) {
    if (!str) return "";
    const utf8 = strToU83(str);
    let bin = "";
    utf8.forEach(b => bin += String.fromCharCode(b));
    return btoa(bin);
  },
  decompress(b64) {
    if (!b64) return "";
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return u8ToStr3(bytes);
  }
};

/* ============================================================
   作戦モード（痕跡ゼロ）
============================================================ */
function clearSensitive() {
  const op = document.getElementById("opMode");
  if (!op || !op.checked) return;

  ["plain", "cipher", "fileInput", "encFileInput", "passphrase"].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.value = "";
  });

  logHud("OPS", "作戦モード：痕跡ゼロ実行");
}

window.addEventListener("beforeunload", clearSensitive);

/* ============================================================
   テキスト暗号化
============================================================ */
async function encryptCtrHmacText(plainText, passphrase) {
  logHud("ENC", "テキスト暗号化開始");

  const compressed = LZ.compress(plainText);
  const data = strToU83(compressed);

  const salt1 = crypto.getRandomValues(new Uint8Array(16));
  const salt2 = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(16));

  const { encKey, macKey1, macKey2 } =
    await deriveComplexKeys(passphrase, salt1, salt2, "TEXT");

  const cipher = new Uint8Array(await crypto.subtle.encrypt(
    { name: "AES-CTR", counter: iv, length: 64 },
    encKey,
    data
  ));

  const header = concatU83(salt1, salt2, iv, cipher);

  const tag1 = new Uint8Array(await crypto.subtle.sign("HMAC", macKey1, header));
  const tag2 = new Uint8Array(await crypto.subtle.sign("HMAC", macKey2, concatU83(header, tag1)));

  const out = concatU83(header, tag1, tag2);

  logHud("ENC", "テキスト暗号化完了");
  return u8ToB64(out);
}

/* ============================================================
   テキスト復号
============================================================ */
async function decryptCtrHmacText(b64, passphrase) {
  logHud("DEC", "テキスト復号開始");

  const all = b64ToU8(b64);

  const salt1 = all.slice(0, 16);
  const salt2 = all.slice(16, 32);
  const iv = all.slice(32, 48);
  const tag2 = all.slice(all.length - 32);
  const tag1 = all.slice(all.length - 64, all.length - 32);
  const cipher = all.slice(48, all.length - 64);

  const { encKey, macKey1, macKey2 } =
    await deriveComplexKeys(passphrase, salt1, salt2, "TEXT");

  const header = concatU83(salt1, salt2, iv, cipher);

  const ok1 = await crypto.subtle.verify("HMAC", macKey1, tag1, header);
  if (!ok1) throw new Error("HMAC1 検証失敗");

  const ok2 = await crypto.subtle.verify("HMAC", macKey2, tag2, concatU83(header, tag1));
  if (!ok2) throw new Error("HMAC2 検証失敗");

  const plain = new Uint8Array(await crypto.subtle.decrypt(
    { name: "AES-CTR", counter: iv, length: 64 },
    encKey,
    cipher
  ));

  logHud("DEC", "テキスト復号完了");

  return LZ.decompress(u8ToStr3(plain));
}

/* ============================================================
   ファイル暗号化
============================================================ */
function randomPadding(size) {
  const out = new Uint8Array(size);
  crypto.getRandomValues(out);
  return out;
}

async function encryptCtrHmacFiles(passphrase) {
  const files = document.getElementById("fileInput")?.files;
  if (!files || !files.length) {
    alert("暗号化するファイルを選択してください");
    return;
  }

  for (const file of files) {
    logHud("ENC", `ファイル暗号化: ${file.name}`);

    const fileBytes = new Uint8Array(await file.arrayBuffer());

    const meta = strToU83(JSON.stringify({
      name: file.name,
      type: file.type || "application/octet-stream",
      size: file.size
    }));

    const metaLen = meta.length;
    const padLen = 1024 * 1024;

    const headerMeta = new Uint8Array([
      (metaLen >>> 24) & 0xff,
      (metaLen >>> 16) & 0xff,
      (metaLen >>> 8) & 0xff,
      metaLen & 0xff
    ]);

    const headerPad = new Uint8Array([
      (padLen >>> 24) & 0xff,
      (padLen >>> 16) & 0xff,
      (padLen >>> 8) & 0xff,
      padLen & 0xff
    ]);

    const padBytes = randomPadding(padLen);

    const plain = concatU83(headerMeta, meta, headerPad, fileBytes, padBytes);

    const salt1 = crypto.getRandomValues(new Uint8Array(16));
    const salt2 = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(16));

    const { encKey, macKey1, macKey2 } =
      await deriveComplexKeys(passphrase, salt1, salt2, "FILE");

    const cipher = new Uint8Array(await crypto.subtle.encrypt(
      { name: "AES-CTR", counter: iv, length: 64 },
      encKey,
      plain
    ));

    const header = concatU83(salt1, salt2, iv, cipher);

    const tag1 = new Uint8Array(await crypto.subtle.sign("HMAC", macKey1, header));
    const tag2 = new Uint8Array(await crypto.subtle.sign("HMAC", macKey2, concatU83(header, tag1)));

    const out = concatU83(header, tag1, tag2);

    const blob = new Blob([out], { type: "application/octet-stream" });
    const url = URL.createObjectURL(blob);

    const a = document.createElement("a");
    a.href = url;
    a.download = file.name + ".enc";
    a.click();

    URL.revokeObjectURL(url);

    logHud("ENC", `ファイル暗号化完了: ${file.name}`);
  }
}

/* ============================================================
   ファイル復号
============================================================ */
async function decryptCtrHmacFiles(passphrase) {
  const encFiles = document.getElementById("encFileInput")?.files;
  if (!encFiles || !encFiles.length) {
    alert("復号するファイルを選択してください");
    return;
  }

  for (const encFile of encFiles) {
    logHud("DEC", `ファイル復号: ${encFile.name}`);

    const all = new Uint8Array(await encFile.arrayBuffer());

    const salt1 = all.slice(0, 16);
    const salt2 = all.slice(16, 32);
    const iv = all.slice(32, 48);
    const tag2 = all.slice(all.length - 32);
    const tag1 = all.slice(all.length - 64, all.length - 32);
    const cipher = all.slice(48, all.length - 64);

    const { encKey, macKey1, macKey2 } =
      await deriveComplexKeys(passphrase, salt1, salt2, "FILE");

    const header = concatU83(salt1, salt2, iv, cipher);

    const ok1 = await crypto.subtle.verify("HMAC", macKey1, tag1, header);
    if (!ok1) {
      alert(encFile.name + ": HMAC1 検証失敗");
      continue;
    }

    const ok2 = await crypto.subtle.verify(
      "HMAC",
      macKey2,
      tag2,
      concatU83(header, tag1)
    );
    if (!ok2) {
      alert(encFile.name + ": HMAC2 検証失敗");
      continue;
    }

    let plain;
    try {
      plain = new Uint8Array(await crypto.subtle.decrypt(
        { name: "AES-CTR", counter: iv, length: 64 },
        encKey,
        cipher
      ));
    } catch {
      alert(encFile.name + ": 復号失敗");
      continue;
    }

    const metaLen =
      (plain[0] << 24) |
      (plain[1] << 16) |
      (plain[2] << 8) |
      (plain[3]);

    const metaBytes = plain.slice(4, 4 + metaLen);
    const meta = JSON.parse(u8ToStr3(metaBytes));

    const padLen =
      (plain[4 + metaLen] << 24) |
      (plain[5 + metaLen] << 16) |
      (plain[6 + metaLen] << 8) |
      (plain[7 + metaLen]);

    const fileBytes = plain.slice(8 + metaLen, plain.length - padLen);

    const blob = new Blob([fileBytes], { type: meta.type });
    const url = URL.createObjectURL(blob);

    const a = document.createElement("a");
    a.href = url;
    a.download = meta.name;
    a.click();

    URL.revokeObjectURL(url);

    logHud("DEC", `ファイル復号完了: ${meta.name}`);
  }
}

/* ============================================================
   UI エントリポイント
============================================================ */
async function encryptCtrHmac() {
  const pass = document.getElementById("passphrase").value;
  if (!pass) {
    alert("パスフレーズを入力してください");
    return;
  }

  const mode = document.getElementById("mode").value;

  try {
    if (mode === "text") {
      const plain = document.getElementById("plain").value;
      const out = await encryptCtrHmacText(plain, pass);
      document.getElementById("cipher").value = out;
    } else {
      await encryptCtrHmacFiles(pass);
    }
  } catch (e) {
    console.error(e);
    alert("暗号化に失敗しました");
    logHud("ERR", "暗号化エラー");
  }

  clearSensitive();
}

async function decryptCtrHmac() {
  const pass = document.getElementById("passphrase").value;
  if (!pass) {
    alert("パスフレーズを入力してください");
    return;
  }

  const mode = document.getElementById("mode").value;

  try {
    if (mode === "text") {
      const b64 = document.getElementById("cipher").value.trim();
      const plain = await decryptCtrHmacText(b64, pass);
      document.getElementById("plain").value = plain;
    } else {
      await decryptCtrHmacFiles(pass);
    }
  } catch (e) {
    console.error(e);
    alert("復号に失敗しました");
    logHud("ERR", "復号エラー");
  }

  clearSensitive();
}
