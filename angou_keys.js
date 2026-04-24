/* ============================================================
   angou_keys.js
   鍵管理（1〜4鍵）+ 鍵生成 + QRポップアップ
   + 分割QR生成 + QR読み取り（カメラ）+ 署名検証 + innerKey生成
============================================================ */

window.innerKey = null;

const enc = new TextEncoder();
const strToU8 = s => enc.encode(s);

/* -----------------------------
   HUDログ
----------------------------- */
function logHud(tag, msg) {
  const body = document.getElementById("hudLogBody");
  if (!body) return;

  const line = document.createElement("div");
  line.className = "hud-log-line";

  const now = new Date();
  const t = now.toTimeString().slice(0, 8);

  line.innerHTML =
    `<span class="time">[${t}]</span>` +
    `<span class="tag">${tag}</span>` +
    `<span>${msg}</span>`;

  body.prepend(line);

  while (body.children.length > 60) body.removeChild(body.lastChild);
}

/* -----------------------------
   鍵モード UI 切り替え
----------------------------- */
function updateKeyModeUI() {
  const mode = parseInt(document.getElementById("keyMode").value, 10);

  const show = (id, cond) => {
    const el = document.getElementById(id);
    if (el) el.style.display = cond ? "block" : "none";
  };

  show("keyLoadA", true);
  show("genA", true);

  show("keyLoadB", mode >= 2);
  show("genB", mode >= 2);

  show("keyLoadC", mode >= 3);
  show("genC", mode >= 3);

  show("keyLoadD", mode >= 4);
  show("genD", mode >= 4);

  updateInnerKey();
  logHud("KEY", `鍵モード変更: ${mode}本`);
}

/* -----------------------------
   innerKey = XOR → SHA-256
----------------------------- */
async function updateInnerKey() {
  const mode = parseInt(document.getElementById("keyMode").value, 10);
  const status = document.getElementById("keyStatus");

  const fA = document.getElementById("keyFileA")?.files[0];
  const fB = document.getElementById("keyFileB")?.files[0];
  const fC = document.getElementById("keyFileC")?.files[0];
  const fD = document.getElementById("keyFileD")?.files[0];

  const files = [];
  if (mode >= 1) files.push(fA);
  if (mode >= 2) files.push(fB);
  if (mode >= 3) files.push(fC);
  if (mode >= 4) files.push(fD);

  if (files.some(f => !f)) {
    window.innerKey = null;
    status.textContent = "鍵未読み込み";
    status.className = "warn";
    logHud("KEY", "鍵が揃っていません");
    return;
  }

  const buffers = [];
  for (const f of files) {
    buffers.push(new Uint8Array(await f.arrayBuffer()));
  }

  let minLen = buffers[0].length;
  for (const b of buffers) if (b.length < minLen) minLen = b.length;

  const xored = new Uint8Array(minLen);
  for (let i = 0; i < minLen; i++) {
    let v = 0;
    for (const b of buffers) v ^= b[i];
    xored[i] = v;
  }

  const hash = await crypto.subtle.digest("SHA-256", xored);
  window.innerKey = new Uint8Array(hash);

  status.textContent = `鍵${mode}本 読み込み済み`;
  status.className = "ok";
  logHud("KEY", "innerKey 更新完了");
}

/* -----------------------------
   鍵生成（バイナリ）
----------------------------- */
function generateKey(which) {
  const name = document.getElementById("genKeyName" + which).value || `key${which}.bin`;
  const size = parseInt(document.getElementById("genKeySize" + which).value, 10);

  const keyBytes = new Uint8Array(size);
  crypto.getRandomValues(keyBytes);

  const blob = new Blob([keyBytes], { type: "application/octet-stream" });
  const url = URL.createObjectURL(blob);

  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();

  URL.revokeObjectURL(url);

  logHud("GEN", `鍵${which} 生成: ${name} (${size}B)`);
}

/* -----------------------------
   単発：鍵QRポップアップ（ハッシュのみ）
----------------------------- */
async function generateKeyQR(which) {
  const name = document.getElementById("genKeyName" + which).value || `key${which}.bin`;
  const size = parseInt(document.getElementById("genKeySize" + which).value, 10);

  const keyBytes = new Uint8Array(size);
  crypto.getRandomValues(keyBytes);

  const hashBuf = await crypto.subtle.digest("SHA-256", keyBytes);
  const hashHex = [...new Uint8Array(hashBuf)]
    .map(x => x.toString(16).padStart(2, "0"))
    .join("");

  const payload = JSON.stringify({
    name,
    size,
    type: "ANGOU-KEY",
    hash: hashHex
  });

  const backdrop = document.getElementById("qrBackdrop");
  const container = document.getElementById("qrContainer");
  const title = document.getElementById("qrTitle");

  container.innerHTML = "";
  title.textContent = `鍵${which} QR`;

  new QRCode(container, {
    text: payload,
    width: 240,
    height: 240,
    correctLevel: QRCode.CorrectLevel.H
  });

  backdrop.style.display = "flex";

  logHud("QR", `鍵${which} QR生成（ハッシュ）`);
}

/* ============================================================
   分割QR生成（鍵そのものを分割して運ぶ）
============================================================ */

const QR_SIGN_SECRET = "HTEncryption-QR-Secret-ChangeMe";

/* SHA-256 → hex */
async function sha256Hex(str) {
  const data = enc.encode(str);
  const buf = await crypto.subtle.digest("SHA-256", data);
  return [...new Uint8Array(buf)]
    .map(x => x.toString(16).padStart(2, "0"))
    .join("");
}

/* 署名生成 */
async function makeQRSignature(obj) {
  const base = `${obj.name}|${obj.size}|${obj.type}|${obj.index}|${obj.total}|${obj.data}|${QR_SIGN_SECRET}`;
  return await sha256Hex(base);
}

/* 署名検証 */
async function verifyQRSignature(obj) {
  if (!obj.sig) return false;
  const { sig, ...baseObj } = obj;
  const base = `${baseObj.name}|${baseObj.size}|${baseObj.type}|${baseObj.index}|${baseObj.total}|${baseObj.data}|${QR_SIGN_SECRET}`;
  const expected = await sha256Hex(base);
  return expected === sig;
}

/* 分割QR生成 */
async function generateKeyQR_Multi(which) {
  const name = document.getElementById("genKeyName" + which).value || `key${which}.bin`;
  const size = parseInt(document.getElementById("genKeySize" + which).value, 10);

  const keyBytes = new Uint8Array(size);
  crypto.getRandomValues(keyBytes);

  let bin = "";
  for (let i = 0; i < keyBytes.length; i++) bin += String.fromCharCode(keyBytes[i]);
  const b64 = btoa(bin);

  const CHUNK_SIZE = 1000;
  const chunks = [];
  for (let i = 0; i < b64.length; i += CHUNK_SIZE) {
    chunks.push(b64.slice(i, i + CHUNK_SIZE));
  }

  const total = chunks.length;

  const backdrop = document.getElementById("qrBackdrop");
  const container = document.getElementById("qrContainer");
  const title = document.getElementById("qrTitle");

  container.innerHTML = "";
  title.textContent = `鍵${which} QR（${total}分割）`;

  let index = 0;

  async function showQR() {
    container.innerHTML = "";

    const baseObj = {
      name,
      size,
      type: "ANGOU-KEY-PART",
      index: index + 1,
      total,
      data: chunks[index]
    };

    const sig = await makeQRSignature(baseObj);
    const payload = JSON.stringify({ ...baseObj, sig });

    new QRCode(container, {
      text: payload,
      width: 240,
      height: 240,
      correctLevel: QRCode.CorrectLevel.H
    });

    const nav = document.createElement("div");
    nav.style.marginTop = "10px";
    nav.style.textAlign = "center";
    nav.innerHTML = `
      <button id="prevQR" ${index === 0 ? "disabled" : ""}>前へ</button>
      <span style="margin: 0 10px;">${index + 1} / ${total}</span>
      <button id="nextQR" ${index === total - 1 ? "disabled" : ""}>次へ</button>
      <button id="saveQRBtn">PNG保存</button>
    `;
    container.appendChild(nav);

    document.getElementById("prevQR").onclick = () => {
      if (index > 0) {
        index--;
        showQR();
      }
    };
    document.getElementById("nextQR").onclick = () => {
      if (index < total - 1) {
        index++;
        showQR();
      }
    };
    document.getElementById("saveQRBtn").onclick = saveQR;
  }

  await showQR();
  backdrop.style.display = "flex";

  logHud("QR", `鍵${which} 分割QR生成（${total}枚）`);
}

/* -----------------------------
   QRモーダル閉じる
----------------------------- */
function closeQRModal() {
  document.getElementById("qrBackdrop").style.display = "none";
}

/* -----------------------------
   QR PNG保存
----------------------------- */
function saveQR() {
  const container = document.getElementById("qrContainer");

  const img = container.querySelector("img");
  const canvas = container.querySelector("canvas");

  let dataUrl = null;

  if (img) {
    dataUrl = img.src;
  } else if (canvas) {
    dataUrl = canvas.toDataURL("image/png");
  } else {
    alert("QRコードが見つかりません。");
    return;
  }

  const a = document.createElement("a");
  a.href = dataUrl;
  a.download = "key_qr.png";
  a.click();
}

/* ============================================================
   分割QR復元ロジック
============================================================ */

let qrParts = [];

/* 分割QR → 元の鍵を復元 */
async function restoreKeyFromQR(parts) {
  if (!Array.isArray(parts) || parts.length === 0) {
    throw new Error("QRデータがありません");
  }

  const total = parts[0].total;

  if (parts.length !== total) {
    throw new Error(`QRが不足しています (${parts.length}/${total})`);
  }

  parts.sort((a, b) => a.index - b.index);

  let b64 = "";
  for (const p of parts) b64 += p.data;

  const bin = atob(b64);
  const keyBytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) keyBytes[i] = bin.charCodeAt(i);

  if (keyBytes.length !== parts[0].size) {
    throw new Error("鍵サイズが一致しません（破損の可能性）");
  }

  return {
    name: parts[0].name,
    size: parts[0].size,
    key: keyBytes
  };
}

/* QRパーツ追加 → 全部揃ったら復元 */
async function addQRPart(json) {
  if (json.type !== "ANGOU-KEY-PART") {
    alert("QR形式が不正です");
    return null;
  }

  qrParts.push(json);
  logHud("QR", `受信 ${json.index}/${json.total}`);

  if (qrParts.length === json.total) {
    const result = await restoreKeyFromQR(qrParts);
    qrParts = [];

    window.innerKey = result.key;
    const status = document.getElementById("keyStatus");
    if (status) {
      status.textContent = "QR鍵復元済み";
      status.className = "ok";
    }

    logHud("QR", "鍵復元完了 → innerKey にセット");
    return result;
  }

  return null;
}

/* ============================================================
   カメラQR読み取りUI（jsQR利用前提）
============================================================ */

let qrScanStream = null;
let qrScanTimer = null;

async function startQRScan() {
  const video = document.getElementById("qrVideo");
  const status = document.getElementById("qrScanStatus");

  try {
    qrScanStream = await navigator.mediaDevices.getUserMedia({
      video: { facingMode: "environment" }
    });
    video.srcObject = qrScanStream;

    document.getElementById("qrScanBackdrop").style.display = "flex";
    status.textContent = "読み取り中...";

    const canvas = document.createElement("canvas");
    const ctx = canvas.getContext("2d");

    qrScanTimer = setInterval(async () => {
      if (video.readyState !== video.HAVE_ENOUGH_DATA) return;

      canvas.width = video.videoWidth;
      canvas.height = video.videoHeight;
      ctx.drawImage(video, 0, 0, canvas.width, canvas.height);

      const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
      const code = jsQR(imageData.data, canvas.width, canvas.height);

      if (code) {
        status.textContent = "QR検出";
        stopQRScan();
        await handleScannedQR(code.data);
      }
    }, 300);
  } catch (e) {
    status.textContent = "カメラにアクセスできません";
    logHud("QR", "カメラ起動失敗");
  }
}

function stopQRScan() {
  if (qrScanTimer) {
    clearInterval(qrScanTimer);
    qrScanTimer = null;
  }
  if (qrScanStream) {
    qrScanStream.getTracks().forEach(t => t.stop());
    qrScanStream = null;
  }
}

function closeQRScanModal() {
  stopQRScan();
  document.getElementById("qrScanBackdrop").style.display = "none";
}

/* 読み取ったQRテキストを処理 */
async function handleScannedQR(text) {
  try {
    const json = JSON.parse(text);

    if (!(await verifyQRSignature(json))) {
      logHud("QR", "署名検証失敗（改ざんの可能性）");
      alert("QRが改ざんされている可能性があります。");
      return;
    }

    const result = await addQRPart(json);

    if (result) {
      alert("鍵復元完了: " + result.name);
      closeQRScanModal();
    } else {
      const status = document.getElementById("qrScanStatus");
      status.textContent = `受信 ${json.index}/${json.total}`;
    }
  } catch (e) {
    logHud("QR", "QR解析エラー");
  }
}

/* -----------------------------
   初期化
----------------------------- */
window.addEventListener("DOMContentLoaded", () => {
  const keyMode = document.getElementById("keyMode");
  if (keyMode) keyMode.addEventListener("change", updateKeyModeUI);

  ["A", "B", "C", "D"].forEach(ch => {
    const el = document.getElementById("keyFile" + ch);
    if (el) el.addEventListener("change", updateInnerKey);
  });

  updateKeyModeUI();
  logHud("INIT", "鍵管理モジュール起動");
});
