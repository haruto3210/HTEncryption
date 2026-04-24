/* ============================================================
   angou_keys.js
   鍵管理（1〜4鍵）+ 鍵生成 + QRポップアップ + innerKey生成 + HUDログ
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
   鍵QRポップアップ（安全版）
----------------------------- */
async function generateKeyQR(which) {
  const name = document.getElementById("genKeyName" + which).value || `key${which}.bin`;
  const size = parseInt(document.getElementById("genKeySize" + which).value, 10);

  const keyBytes = new Uint8Array(size);
  crypto.getRandomValues(keyBytes);

  // QR に入れるのは鍵のハッシュのみ（安全 & QRエラー防止）
  const hash = await crypto.subtle.digest("SHA-256", keyBytes);
  const hex = [...new Uint8Array(hash)]
    .map(x => x.toString(16).padStart(2, "0"))
    .join("");

  const payload = JSON.stringify({
    name,
    size,
    type: "ANGOU-KEY",
    hash: hex
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

  logHud("QR", `鍵${which} QR生成`);
}

function closeQRModal() {
  document.getElementById("qrBackdrop").style.display = "none";
}

/* -----------------------------
   初期化
----------------------------- */
window.addEventListener("DOMContentLoaded", () => {
  document.getElementById("keyMode").addEventListener("change", updateKeyModeUI);

  ["A","B","C","D"].forEach(ch => {
    const el = document.getElementById("keyFile" + ch);
    if (el) el.addEventListener("change", updateInnerKey);
  });

  updateKeyModeUI();
  logHud("INIT", "鍵管理モジュール起動");
});
