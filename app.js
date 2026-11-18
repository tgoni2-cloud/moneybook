'use strict';
/* 우리집 가계부 — 모든 금융 데이터는 이 기기 안(IndexedDB)에만 AES-GCM으로 암호화되어 저장됩니다. */

// ---------- small helpers ----------
const $ = (s, el = document) => el.querySelector(s);
const enc = new TextEncoder(), dec = new TextDecoder();
const rand = n => crypto.getRandomValues(new Uint8Array(n));
const b64 = u8 => btoa(String.fromCharCode(...new Uint8Array(u8)));
const ub64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const pad2 = n => String(n).padStart(2, '0');
const ymd = d => `${d.getFullYear()}-${pad2(d.getMonth() + 1)}-${pad2(d.getDate())}`;
const won = n => (n < 0 ? '-' : '') + Math.abs(Math.round(n)).toLocaleString('ko-KR') + '원';
const man = n => {
  const a = Math.abs(n), s = n < 0 ? '-' : '';
  if (a >= 1e8) return s + (a / 1e8).toFixed(a >= 1e9 ? 1 : 2).replace(/\.?0+$/, '') + '억';
  if (a >= 1e6) return s + Math.round(a / 1e4).toLocaleString('ko-KR') + '만';
  if (a >= 1e4) return s + (a / 1e4).toFixed(1).replace(/\.0$/, '') + '만';
  return s + Math.round(a).toLocaleString('ko-KR');
};
const WD = ['일', '월', '화', '수', '목', '금', '토'];
const dayLabel = d => { const x = new Date(d + 'T00:00:00'); return `${x.getMonth() + 1}월 ${x.getDate()}일 (${WD[x.getDay()]})`; };

// ---------- IndexedDB ----------
const idb = (() => {
  let dbp;
  const open = () => dbp || (dbp = new Promise((res, rej) => {
    const r = indexedDB.open('gagyebu', 1);
    r.onupgradeneeded = () => r.result.createObjectStore('kv');
    r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error);
  }));
  const tx = async (mode, fn) => { const db = await open(); return new Promise((res, rej) => { const t = db.transaction('kv', mode); const st = t.objectStore('kv'); const r = fn(st); t.oncomplete = () => res(r && r.result); t.onerror = () => rej(t.error); }); };
  return { get: k => tx('readonly', s => s.get(k)), set: (k, v) => tx('readwrite', s => s.put(v, k)), del: k => tx('readwrite', s => s.delete(k)), clear: () => tx('readwrite', s => s.clear()) };
})();

// ---------- crypto ----------
const PBKDF2_ITER = 600000;
async function pinKek(pin, salt) {
  const base = await crypto.subtle.importKey('raw', enc.encode(pin), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: PBKDF2_ITER, hash: 'SHA-256' }, base, { name: 'AES-KW', length: 256 }, false, ['wrapKey', 'unwrapKey']);
}
async function prfKek(prfOut) {
  const base = await crypto.subtle.importKey('raw', prfOut, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: enc.encode('gagyebu-faceid') }, base, { name: 'AES-KW', length: 256 }, false, ['wrapKey', 'unwrapKey']);
}
const wrap = async (dek, kek) => b64(await crypto.subtle.wrapKey('raw', dek, kek, 'AES-KW'));
const unwrap = (w, kek) => crypto.subtle.unwrapKey('raw', ub64(w), kek, 'AES-KW', { name: 'AES-GCM' }, true, ['encrypt', 'decrypt']);
async function seal(obj, dek) {
  const iv = rand(12);
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, dek, enc.encode(JSON.stringify(obj)));
  return { iv: b64(iv), ct: new Uint8Array(ct) };
}
async function open_(box, dek) {
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: ub64(box.iv) }, dek, box.ct);
  return JSON.parse(dec.decode(pt));
}

// ---------- state ----------
const DEFAULT_SETTINGS = {
  startDate: '2025-12-01',
  cards: [
    { pay: 'KB국민 코웨이II 카드', label: '국민카드', target: 400000, note: '코웨이 정수기·비데 할인' },
    { pay: '카드의 정석 WOWRI', label: '우리카드', target: 300000, note: '마이너스통장 우대금리' },
  ],
  rules: { salary: '한국쌔스소프트', reimb: 'SAS Softwa', wife: '김보민', wifeName: '아내' },
  gmail: { clientId: '', query: 'banksalad has:attachment' },
  fixed: { overrides: {}, manual: [] },
};
let DEK = null, META = null;
let DATA = null; // {txs, assets, settings, importedAt, fileName, assetHistory}
const today = ymd(new Date());
const UI = { tab: 'today', day: today, month: today.slice(0, 7), year: today.slice(0, 4), todayMode: 'pay', monthMode: 'time', filter: 'exp' };

async function persist() { await idb.set('data', await seal(DATA, DEK)); }

// ---------- lock screen ----------
let pinBuf = '', pinStage = 'unlock', firstPin = '';
function setupPad() {
  const keys = ['1', '2', '3', '4', '5', '6', '7', '8', '9', '', '0', '⌫'];
  $('#pad').innerHTML = keys.map(k => k === '' ? '<span></span>' : `<button data-k="${k}" class="${k === '⌫' ? 'ghost' : ''}" aria-label="${k === '⌫' ? '지우기' : k}">${k}</button>`).join('');
  $('#pad').onclick = e => { const b = e.target.closest('button'); if (b) pressKey(b.dataset.k); };
  document.addEventListener('keydown', e => {
    if ($('#lock').classList.contains('hidden')) return;
    if (/^[0-9]$/.test(e.key)) pressKey(e.key); else if (e.key === 'Backspace') pressKey('⌫');
  });
}
function drawDots() { [...$('#dots').children].forEach((d, i) => d.classList.toggle('on', i < pinBuf.length)); }
function lockMsg(t) { $('#lockSub').textContent = t; }
function shake() { const d = $('#dots'); d.classList.remove('shake'); void d.offsetWidth; d.classList.add('shake'); }
let busy = false;
async function pressKey(k) {
  if (busy) return;
  if (k === '⌫') { pinBuf = pinBuf.slice(0, -1); return drawDots(); }
  if (pinBuf.length >= 6) return;
  pinBuf += k; drawDots();
  if (pinBuf.length < 6) return;
  const pin = pinBuf; busy = true;
  try {
    if (pinStage === 'new') { firstPin = pin; pinStage = 'confirm'; lockMsg('한 번 더 입력하세요'); }
    else if (pinStage === 'confirm') {
      if (pin !== firstPin) { pinStage = 'new'; shake(); lockMsg('일치하지 않아요. 새 비밀번호 6자리를 다시 입력하세요'); }
      else { lockMsg('설정 중…'); await createVault(pin); unlocked(); }
    } else if (pinStage === 'change-new') { firstPin = pin; pinStage = 'change-confirm'; lockMsg('새 비밀번호를 한 번 더 입력하세요'); }
    else if (pinStage === 'change-confirm') {
      if (pin !== firstPin) { pinStage = 'change-new'; shake(); lockMsg('일치하지 않아요. 새 비밀번호를 다시 입력하세요'); }
      else { await changePin(pin); toast('비밀번호를 바꿨어요'); unlocked(); }
    } else { await tryUnlock(pin); }
  } finally { pinBuf = ''; drawDots(); busy = false; }
}
async function createVault(pin) {
  const salt = rand(16);
  DEK = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
  META = { v: 1, salt: b64(salt), wPin: await wrap(DEK, await pinKek(pin, salt)), fails: 0, until: 0 };
  await idb.set('meta', META);
  DATA = { txs: [], assets: null, settings: structuredClone(DEFAULT_SETTINGS), importedAt: null, fileName: null, assetHistory: [] };
  await persist();
}
async function tryUnlock(pin) {
  const now = Date.now();
  if (META.until > now) { shake(); return lockMsg(`잠시 후 다시 시도하세요 (${Math.ceil((META.until - now) / 1000)}초)`); }
  lockMsg('확인 중…');
  try {
    DEK = await unwrap(META.wPin, await pinKek(pin, ub64(META.salt)));
  } catch {
    META.fails = (META.fails || 0) + 1;
    if (META.fails >= 5) META.until = Date.now() + 30000 * 2 ** (META.fails - 5);
    await idb.set('meta', META); shake();
    return lockMsg(META.fails >= 5 ? `${META.fails}회 틀렸어요. ${Math.round(30 * 2 ** (META.fails - 5))}초 뒤에 다시 시도하세요` : `비밀번호가 달라요 (${META.fails}회)`);
  }
  META.fails = 0; META.until = 0; await idb.set('meta', META);
  await loadData(); unlocked();
}
async function loadData() {
  const box = await idb.get('data');
  DATA = box ? await open_(box, DEK) : null;
  if (!DATA) DATA = { txs: [], assets: null, settings: structuredClone(DEFAULT_SETTINGS), importedAt: null, fileName: null, assetHistory: [] };
  DATA.settings = Object.assign(structuredClone(DEFAULT_SETTINGS), DATA.settings || {});
  DATA.settings.rules = Object.assign(structuredClone(DEFAULT_SETTINGS.rules), DATA.settings.rules || {});
  DATA.settings.gmail = Object.assign(structuredClone(DEFAULT_SETTINGS.gmail), DATA.settings.gmail || {});
  DATA.settings.fixed = Object.assign(structuredClone(DEFAULT_SETTINGS.fixed), DATA.settings.fixed || {});
  reclassify();
  // Default views to latest data if today has nothing yet
  if (DATA.txs.length) { const last = DATA.txs[0].d; if (last < UI.month + '-01') { UI.month = last.slice(0, 7); UI.year = last.slice(0, 4); } }
}
async function changePin(pin) {
  const salt = rand(16);
  META.salt = b64(salt); META.wPin = await wrap(DEK, await pinKek(pin, salt)); META.fails = 0; META.until = 0;
  await idb.set('meta', META);
}
function lock() {
  DEK = null; DATA = null; pinStage = 'unlock'; pinBuf = ''; drawDots();
  $('#app').innerHTML = ''; $('#app').classList.add('hidden'); $('#tabbar').classList.add('hidden');
  $('#lock').classList.remove('hidden'); lockMsg('비밀번호 6자리를 입력하세요');
  $('#bioBtn').classList.toggle('hidden', !META?.bio);
}
function unlocked() {
  $('#lock').classList.add('hidden'); $('#app').classList.remove('hidden'); $('#tabbar').classList.remove('hidden');
  if (!DATA.txs.length) UI.tab = 'setting';
  render();
  if (GTOKEN) { const t = GTOKEN; GTOKEN = null; gmailImport(t); }
}
// Auto-lock after 60s in background
let hiddenAt = 0;
document.addEventListener('visibilitychange', () => {
  if (document.hidden) hiddenAt = Date.now();
  else if (DEK && hiddenAt && Date.now() - hiddenAt > 60000) lock();
});

// ---------- Face ID (WebAuthn PRF) ----------
const bioSupported = () => !!(window.PublicKeyCredential && navigator.credentials && window.isSecureContext);
async function enrollBio() {
  if (!bioSupported()) throw new Error('이 브라우저에서는 Face ID를 쓸 수 없어요 (https 주소에서 열어야 해요)');
  const prfSalt = rand(32);
  const cred = await navigator.credentials.create({ publicKey: {
    rp: { name: '우리집 가계부' },
    user: { id: rand(16), name: '가계부 ' + new Date().toLocaleDateString('ko-KR'), displayName: '우리집 가계부' },
    challenge: rand(32),
    pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
    authenticatorSelection: { authenticatorAttachment: 'platform', userVerification: 'required', residentKey: 'preferred' },
    extensions: { prf: { eval: { first: prfSalt } } },
  } });
  const ext = cred.getClientExtensionResults();
  if (!ext.prf || ext.prf.enabled === false) throw new Error('이 기기는 Face ID 잠금 해제(PRF)를 지원하지 않아요. iOS 18 / macOS 15 이상 Safari에서 다시 시도해 주세요');
  let out = ext.prf.results && ext.prf.results.first;
  if (!out) out = await bioAssert(new Uint8Array(cred.rawId), prfSalt);
  META.bio = { id: b64(cred.rawId), salt: b64(prfSalt), w: await wrap(DEK, await prfKek(out)) };
  await idb.set('meta', META);
}
async function bioAssert(id, salt) {
  const a = await navigator.credentials.get({ publicKey: {
    challenge: rand(32), allowCredentials: [{ type: 'public-key', id }], userVerification: 'required',
    extensions: { prf: { eval: { first: salt } } },
  } });
  const out = a.getClientExtensionResults().prf?.results?.first;
  if (!out) throw new Error('Face ID 키를 받지 못했어요');
  return out;
}
async function unlockBio() {
  try {
    lockMsg('Face ID 확인 중…');
    const out = await bioAssert(ub64(META.bio.id), ub64(META.bio.salt));
    DEK = await unwrap(META.bio.w, await prfKek(out));
    await loadData(); unlocked();
  } catch (e) { lockMsg(e.name === 'NotAllowedError' ? '취소됐어요. 비밀번호로 열어 주세요' : 'Face ID로 열지 못했어요. 비밀번호로 열어 주세요'); }
}

// ---------- Banksalad parsing ----------
function xlDate(v) { // excel serial → YYYY-MM-DD
  if (v instanceof Date) return ymd(v);
  if (typeof v === 'number') { const d = new Date(Math.round((v - 25569) * 86400000)); return `${d.getUTCFullYear()}-${pad2(d.getUTCMonth() + 1)}-${pad2(d.getUTCDate())}`; }
  const m = String(v).match(/(\d{4})[-./](\d{1,2})[-./](\d{1,2})/); return m ? `${m[1]}-${pad2(m[2])}-${pad2(m[3])}` : null;
}
function xlTime(v) {
  if (typeof v === 'number') { let s = Math.round((v % 1) * 86400); return `${pad2(Math.floor(s / 3600))}:${pad2(Math.floor(s / 60) % 60)}`; }
  const m = String(v ?? '').match(/(\d{1,2}):(\d{2})/); return m ? `${pad2(m[1])}:${m[2]}` : '';
}
function parseBanksalad(buf) {
  let wb;
  try { wb = XLSX.read(buf, { type: 'array' }); }
  catch (e) { throw new Error(/password|encrypt/i.test(e.message) ? '암호가 걸린 파일이에요. 엑셀이나 Numbers에서 열어 암호 없이 저장한 뒤 다시 올려 주세요' : '엑셀 파일을 읽지 못했어요: ' + e.message); }
  const txSheet = wb.Sheets['가계부 내역'] || wb.Sheets[wb.SheetNames.find(n => /가계부/.test(n))];
  if (!txSheet) throw new Error("'가계부 내역' 시트를 찾지 못했어요. 뱅크샐러드에서 내보낸 파일이 맞는지 확인해 주세요");
  const rows = XLSX.utils.sheet_to_json(txSheet, { header: 1, raw: true });
  const h = rows[0].map(x => String(x || '').trim());
  const ix = n => h.indexOf(n);
  const I = { d: ix('날짜'), t: ix('시간'), type: ix('타입'), cat: ix('대분류'), sub: ix('소분류'), memo: ix('내용'), amt: ix('금액'), pay: ix('결제수단'), note: ix('메모') };
  if (I.d < 0 || I.amt < 0) throw new Error('가계부 내역의 열 이름이 예상과 달라요');
  const txs = [];
  for (const r of rows.slice(1)) {
    if (r[I.d] == null || r[I.amt] == null) continue;
    const d = xlDate(r[I.d]); if (!d) continue;
    txs.push({ d, t: xlTime(r[I.t]), type: String(r[I.type] || ''), cat: String(r[I.cat] || ''), sub: String(r[I.sub] || ''),
      memo: String(r[I.memo] ?? ''), amt: Number(r[I.amt]) || 0, pay: String(r[I.pay] || ''), note: r[I.note] ? String(r[I.note]) : '' });
  }
  return { txs, assets: parseAssets(wb.Sheets['뱅샐현황']) };
}
function parseAssets(ws) {
  if (!ws) return null;
  // 시트가 B열부터 시작해도 열 번호가 A열 기준이 되도록 맞춤
  const off = XLSX.utils.decode_range(ws['!ref'] || 'A1').s.c;
  const rows = XLSX.utils.sheet_to_json(ws, { header: 1, raw: true, defval: null }).map(r => Array(off).fill(null).concat(r));
  const out = { assets: [], debts: [], invest: [], loans: [], insurance: [] };
  const find = (pred, from = 0) => { for (let i = from; i < rows.length; i++) if (pred(rows[i] || [])) return i; return -1; };
  const s3 = find(r => /^3\./.test(String(r[1] || '')));
  if (s3 >= 0) {
    const hdr = find(r => r[1] === '항목' && r[5] === '항목', s3);
    let ga = '', gd = '';
    for (let i = hdr + 1; i < rows.length; i++) {
      const r = rows[i] || [];
      if (r[1] === '총자산' || /^4\./.test(String(r[1] || ''))) break;
      if (r[1]) ga = String(r[1]); if (r[5]) gd = String(r[5]);
      if (r[2] != null && typeof r[4] === 'number') out.assets.push({ group: ga, name: String(r[2]), amount: r[4] });
      if (r[6] != null && typeof r[8] === 'number') out.debts.push({ group: gd, name: String(r[6]), amount: r[8] });
    }
  }
  const s5 = find(r => /^5\./.test(String(r[1] || '')));
  if (s5 >= 0) for (let i = s5 + 3; i < rows.length; i++) {
    const r = rows[i] || []; if (r[1] === '총계' || /^6\./.test(String(r[1] || ''))) break;
    if (r[3]) out.invest.push({ type: r[1], company: r[2], name: String(r[3]), principal: +r[5] || 0, value: +r[6] || 0, rate: +r[7] || 0 });
  }
  const s6 = find(r => /^6\./.test(String(r[1] || '')));
  if (s6 >= 0) for (let i = s6 + 3; i < rows.length; i++) {
    const r = rows[i] || []; if (r[1] === '총계' || /^7\./.test(String(r[1] || ''))) break;
    if (r[3]) out.loans.push({ type: r[1], company: r[2], name: String(r[3]), principal: +r[5] || 0, balance: +r[6] || 0, rate: +r[7] || 0, end: r[9] ? xlDate(r[9]) : '' });
  }
  const s4 = find(r => /^4\./.test(String(r[1] || '')));
  if (s4 >= 0) for (let i = s4 + 3; i < rows.length; i++) {
    const r = rows[i] || []; if (r[1] === '총계' || /^5\./.test(String(r[1] || ''))) break;
    if (r[2]) out.insurance.push({ company: r[1], name: String(r[2]), status: r[4] });
  }
  return out;
}
function assetTotals(a) {
  if (!a) return { assets: 0, debts: 0, net: 0 };
  const debtAmts = new Set(a.debts.map(d => Math.round(d.amount)));
  // 마이너스통장은 자산 쪽에 음수 잔액으로도 잡혀 이중 계산되므로 제외
  const assets = a.assets.filter(x => !(x.amount < 0 && debtAmts.has(Math.round(-x.amount)))).reduce((s, x) => s + x.amount, 0);
  const debts = a.debts.reduce((s, x) => s + x.amount, 0);
  return { assets, debts, net: assets - debts };
}

// ---------- 비밀번호 걸린 zip (뱅크샐러드 내보내기) ----------
const isZipName = n => /\.zip$/i.test(n || '');
async function xlsxFromZip(buf) {
  if (!window.zip) throw new Error('압축 해제 모듈을 불러오지 못했어요');
  zip.configure({ useWebWorkers: false });
  const reader = new zip.ZipReader(new zip.Uint8ArrayReader(new Uint8Array(buf)));
  try {
    const entries = await reader.getEntries();
    const entry = entries.find(e => !e.directory && /\.xlsx?$/i.test(e.filename)) || entries.find(e => !e.directory);
    if (!entry) throw new Error('압축파일 안에 엑셀 파일이 없어요');
    for (let attempt = 0; attempt < 3; attempt++) {
      const password = entry.encrypted ? await askPassword(attempt ? '비밀번호가 달라요. 다시 입력해 주세요' : '뱅크샐러드에서 정한 압축파일 비밀번호를 입력하세요') : undefined;
      try { return await entry.getData(new zip.Uint8ArrayWriter(), { password }); }
      catch (err) { if (!entry.encrypted || !/password/i.test(err.message)) throw err; }
    }
    throw new Error('비밀번호가 3번 틀렸어요');
  } finally { await reader.close(); }
}
// 비밀번호는 화면에서 입력만 받고 어디에도 저장하지 않음
function askPassword(msg) {
  return new Promise((resolve, reject) => {
    const w = document.createElement('div'); w.className = 'modal';
    w.innerHTML = `<form class="sheet"><b>압축파일 비밀번호</b><div class="note" style="margin:6px 0 12px">${esc(msg)}</div>
      <input type="password" inputmode="numeric" autocomplete="off" maxlength="16" class="pw" aria-label="압축파일 비밀번호">
      <div class="row" style="margin-top:14px"><button type="button" class="btn sec" data-x>취소</button><button class="btn">확인</button></div></form>`;
    document.body.appendChild(w);
    const inp = w.querySelector('input'); setTimeout(() => inp.focus(), 50);
    w.querySelector('form').onsubmit = e => { e.preventDefault(); const v = inp.value; w.remove(); resolve(v); };
    w.querySelector('[data-x]').onclick = () => { w.remove(); reject(new Error('취소했어요')); };
  });
}
async function importFile(file) { return importBuffer(await file.arrayBuffer(), file.name); }
async function importBuffer(buf, name) {
  if (isZipName(name)) buf = await xlsxFromZip(buf);
  const { txs, assets } = parseBanksalad(buf);
  if (!txs.length) throw new Error('거래 내역이 비어 있어요');
  const start = DATA.settings.startDate || '0000-00-00';
  const fresh = txs.filter(t => t.d >= start);
  const minD = fresh.reduce((m, t) => t.d < m ? t.d : m, '9999-99-99');
  const kept = DATA.txs.filter(t => t.d < minD && t.d >= start);
  DATA.txs = kept.concat(fresh).sort((a, b) => (b.d + b.t).localeCompare(a.d + a.t));
  if (assets) {
    DATA.assets = assets;
    const tot = assetTotals(assets), dt = ymd(new Date());
    DATA.assetHistory = (DATA.assetHistory || []).filter(h => h.d !== dt).concat([{ d: dt, ...tot }]).slice(-60);
  }
  DATA.importedAt = new Date().toISOString(); DATA.fileName = name;
  reclassify();
  await persist();
  const lastD = DATA.txs[0]?.d; if (lastD) { UI.month = lastD.slice(0, 7); UI.year = lastD.slice(0, 4); }
  return { added: fresh.length, kept: kept.length, from: minD, to: lastD };
}

// ---------- classification ----------
const splitRule = s => String(s || '').split(',').map(x => x.trim()).filter(Boolean);
function reclassify() {
  const R = DATA.settings.rules, sal = splitRule(R.salary), rei = splitRule(R.reimb), wife = splitRule(R.wife);
  const has = (m, list) => list.some(k => m.includes(k));
  for (const t of DATA.txs) {
    const m = t.memo;
    if (has(m, wife)) t.k = t.amt > 0 ? 'wife_in' : 'wife_out';
    else if (has(m, sal) && t.amt > 0) t.k = 'salary';
    else if (has(m, rei) && t.amt > 0) t.k = 'reimb';
    else if (t.type === '수입') t.k = 'income';
    else if (t.type === '지출') {
      if (t.cat === '금융' && (t.sub === '증권/투자' || t.sub === '이자/대출')) t.k = 'fin';
      else t.k = /카드|간편결제/.test(t.pay) ? 'card' : 'account';
    } else t.k = 'transfer';
  }
}
const isInc = t => t.k === 'salary' || t.k === 'reimb' || t.k === 'income';
const isExp = t => t.k === 'card' || t.k === 'account';
function summarize(list) {
  const s = { income: 0, salary: 0, reimb: 0, otherInc: 0, expense: 0, card: 0, account: 0, wifeIn: 0, wifeOut: 0, fin: 0, byCat: {}, byPay: {} };
  for (const t of list) {
    if (isInc(t)) { s.income += t.amt; if (t.k === 'salary') s.salary += t.amt; else if (t.k === 'reimb') s.reimb += t.amt; else s.otherInc += t.amt; }
    else if (isExp(t)) {
      const v = -t.amt; s.expense += v; s[t.k] += v;
      s.byCat[t.cat || '미분류'] = (s.byCat[t.cat || '미분류'] || 0) + v;
      s.byPay[t.pay] = (s.byPay[t.pay] || 0) + v;
    } else if (t.k === 'wife_in') s.wifeIn += t.amt;
    else if (t.k === 'wife_out') s.wifeOut += -t.amt;
    else if (t.k === 'fin') s.fin += -t.amt;
  }
  return s;
}
function cardProgress(ym) {
  const [y, m] = ym.split('-').map(Number), last = new Date(y, m, 0).getDate();
  const isCur = ym === today.slice(0, 7), daysLeft = isCur ? last - Number(today.slice(8)) + 1 : 0;
  return DATA.settings.cards.map(c => {
    const spent = -DATA.txs.filter(t => t.pay === c.pay && t.type === '지출' && t.d.startsWith(ym)).reduce((s, t) => s + t.amt, 0);
    return { ...c, spent, pct: c.target ? spent / c.target * 100 : 0, left: Math.max(0, c.target - spent), isCur, daysLeft, isFuture: ym > today.slice(0, 7) };
  });
}

// ---------- rendering ----------
const ICONS = {
  today: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3.5" y="5" width="17" height="15" rx="3"/><path d="M8 3v4M16 3v4M3.5 10h17"/><circle cx="12" cy="15" r="1.6" fill="currentColor"/></svg>',
  month: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><rect x="3.5" y="5" width="17" height="15" rx="3"/><path d="M8 3v4M16 3v4M3.5 10h17M8 14h2M14 14h2M8 17h2M14 17h2"/></svg>',
  year: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><path d="M5 20V11M10 20V6M15 20v-7M20 20V4"/></svg>',
  asset: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"><path d="M12 3 3.5 8v1.5h17V8L12 3Z"/><path d="M5.5 10v7M10 10v7M14 10v7M18.5 10v7M3.5 20h17" stroke-linecap="round"/></svg>',
  fixed: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M4 12a8 8 0 0 1 13.7-5.6L20 8.5"/><path d="M20 4v4.5h-4.5"/><path d="M20 12a8 8 0 0 1-13.7 5.6L4 15.5"/><path d="M4 20v-4.5h4.5"/><path d="M12 8.5v7M14 10h-2.8a1.2 1.2 0 0 0 0 2.4h1.6a1.2 1.2 0 0 1 0 2.4H10"/></svg>',
  setting: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1Z"/></svg>',
};
const TABS = [['asset', 'Asset'], ['fixed', '고정비'], ['today', 'Today'], ['month', 'Month'], ['year', 'Year']];
function renderTabs() {
  $('#tabs').innerHTML = TABS.map(([k, l]) => `<button data-tab="${k}" class="${UI.tab === k ? 'on' : ''} ${k === 'today' ? 'center' : ''}">${k === 'today' ? `<span class="pill">${ICONS[k]}</span>` : ICONS[k]}<span>${l}</span></button>`).join('');
}
$('#tabs')?.addEventListener('click', () => {});
function render() {
  renderTabs();
  const v = { today: vToday, month: vMonth, year: vYear, asset: vAsset, fixed: vFixed, setting: vSetting }[UI.tab];
  $('#app').innerHTML = v();
  // 설정은 탭 대신 각 화면 오른쪽 위 톱니바퀴로 이동
  const tb = $('#app .topbar');
  if (tb && UI.tab !== 'setting') tb.insertAdjacentHTML('beforeend', `<button class="gear" data-tab="setting" aria-label="설정">${ICONS.setting}</button>`);
  if (tb && UI.tab === 'setting') tb.insertAdjacentHTML('afterbegin', `<button class="gear" data-tab="${UI.prevTab || 'today'}" aria-label="뒤로">‹</button>`);
  window.scrollTo(0, 0);
}

const CAT_ICON = { '카페/간식': '☕', '생활': '🛒', '의료/건강': '🏥', '교통': '🚇', '자동차': '🚗', '주거/통신': '📱', '문화/여가': '🎬', '경조/선물': '🎁', '쇼핑': '🛍️', '금융': '🏦', '미분류': '💳', '식비': '🍚', '여행/숙박': '✈️', '교육': '📚', '뷰티/미용': '💄' };
const KIND_LABEL = { salary: '월급', reimb: '비용청구 환급', income: '기타 수입', wife_in: '부부 이체(입금)', wife_out: '부부 이체(송금)', fin: '금융·자산이동', transfer: '이체' };
function txRow(t, showDate) {
  const inc = isInc(t) || (t.amt > 0 && !isExp(t));
  const icon = isInc(t) ? '💰' : t.k === 'wife_in' || t.k === 'wife_out' ? '💑' : t.k === 'fin' || t.k === 'transfer' ? '🔁' : (CAT_ICON[t.cat] || '💳');
  const label = isExp(t) ? (t.sub && t.sub !== '미분류' ? t.sub : t.cat) : KIND_LABEL[t.k];
  const second = [showDate ? dayLabel(t.d).replace(/ \(.\)/, '') : null, t.t, label, t.pay].filter(Boolean).join(' · ');
  return `<div class="tx"><div class="ic">${icon}</div><div class="mid"><div class="t1">${esc(t.memo || t.cat)}</div><div class="t2">${esc(second)}</div></div>
    <div class="amt num ${t.amt < 0 ? '' : 'inc'}">${t.amt > 0 ? '+' : ''}${won(t.amt)}</div></div>`;
}
function filterList(list) {
  if (UI.filter === 'exp') return list.filter(isExp);
  if (UI.filter === 'inc') return list.filter(isInc);
  return list;
}
function listBlock(list, mode, opts = {}) {
  list = filterList(list);
  if (!list.length) return `<div class="group"><div class="empty">${UI.filter === 'inc' ? '수입 내역이 없어요' : UI.filter === 'exp' ? '사용 내역이 없어요' : '내역이 없어요'}</div></div>`;
  const val = t => isExp(t) ? -t.amt : t.amt;
  if (mode === 'pay') {
    const g = {};
    for (const t of list) (g[t.pay || '기타'] ||= []).push(t);
    const cardSet = new Map(DATA.settings.cards.map(c => [c.pay, c]));
    return Object.entries(g).sort((a, b) => b[1].reduce((s, t) => s + Math.abs(t.amt), 0) - a[1].reduce((s, t) => s + Math.abs(t.amt), 0)).map(([p, ts]) => {
      const sum = ts.reduce((s, t) => s + val(t), 0), c = cardSet.get(p);
      return `<div class="group"><div class="ghead"><span>${esc(p)}${c ? ` <span class="muted">· ${esc(c.label)} 실적</span>` : ''}</span><span class="num">${won(sum)} <span class="muted">${ts.length}건</span></span></div>${ts.map(t => txRow(t, opts.showDate)).join('')}</div>`;
    }).join('');
  }
  if (opts.byDay) {
    const g = {};
    for (const t of list) (g[t.d] ||= []).push(t);
    return Object.keys(g).sort().reverse().map(d => {
      const ts = g[d], sum = ts.reduce((s, t) => s + val(t), 0);
      return `<div class="group"><div class="ghead"><span>${dayLabel(d)}</span><span class="num">${won(sum)}</span></div>${ts.map(t => txRow(t)).join('')}</div>`;
    }).join('');
  }
  return `<div class="group">${list.map(t => txRow(t)).join('')}</div>`;
}
function goalsBlock(ym, compact) {
  const ps = cardProgress(ym);
  if (!ps.length) return '';
  return `<div class="card">${compact ? '' : '<div class="row" style="margin-bottom:10px"><b>카드 실적 달성률</b><span class="label">매월 1일 ~ 말일</span></div>'}${ps.map(p => {
    const done = p.spent >= p.target, w = Math.min(100, p.pct);
    const tail = done ? `달성 · ${man(p.spent - p.target)}원 초과` : p.isCur ? `${man(p.left)}원 남음 · D-${p.daysLeft}` : p.isFuture ? '' : `${man(p.left)}원 부족`;
    return `<div class="goal"><div class="row"><span><b>${esc(p.label)}</b> <span class="muted" style="font-size:12px">${esc(p.note || '')}</span></span><span class="pct num ${done ? 'inc' : ''}">${Math.round(p.pct)}%</span></div>
      <div class="bar"><span class="${done ? 'done' : ''}" style="width:${w}%"></span></div>
      <div class="row"><small class="num">${won(p.spent)} / ${won(p.target)}</small><small>${tail}</small></div></div>`;
  }).join('')}</div>`;
}
const seg = (name, cur, opts) => `<div class="seg" data-seg="${name}">${opts.map(([v, l]) => `<button data-v="${v}" class="${cur === v ? 'on' : ''}">${l}</button>`).join('')}</div>`;
function noData() {
  return `<div class="card empty">아직 불러온 내역이 없어요.<br><br><button class="btn" data-go="setting">뱅크샐러드 파일 올리기</button></div>`;
}
function updatedLine() {
  if (!DATA.importedAt) return '';
  const d = new Date(DATA.importedAt);
  return `<div class="label" style="text-align:center;margin:18px 0 0">최근 업데이트 ${d.getMonth() + 1}/${d.getDate()} ${pad2(d.getHours())}:${pad2(d.getMinutes())} · 내역은 ${dayLabel(DATA.txs[0]?.d || today).replace(/ \(.\)/, '')}까지</div>`;
}

function vToday() {
  if (!DATA.txs.length) return `<div class="topbar"><h2>Today</h2></div>` + noData();
  const list = DATA.txs.filter(t => t.d === UI.day);
  const s = summarize(list);
  const isToday = UI.day === today;
  return `<div class="topbar"><h2>${isToday ? '오늘' : 'Today'}</h2><div class="nav-arrows"><button data-day="-1" aria-label="이전 날">‹</button>${isToday ? '' : '<button data-day="0" style="font-size:13px;width:auto;padding:0 8px">오늘</button>'}<button data-day="1" aria-label="다음 날">›</button></div></div>
  <div class="card"><div class="label">${dayLabel(UI.day)} 전체 사용금액</div><div class="big num">${won(s.expense)}</div>
    <div class="kpis"><div class="kpi"><span class="label">카드·간편결제</span><b class="num">${won(s.card)}</b></div><div class="kpi"><span class="label">계좌 출금</span><b class="num">${won(s.account)}</b></div><div class="kpi"><span class="label">수입</span><b class="num inc">${won(s.income)}</b></div></div></div>
  ${goalsBlock(UI.day.slice(0, 7), false)}
  <div class="tools">${seg('todayMode', UI.todayMode, [['pay', '결제수단별'], ['time', '시간별']])}${seg('filter', UI.filter, [['exp', '지출'], ['inc', '수입'], ['all', '전체']])}</div>
  ${listBlock(list, UI.todayMode)}${updatedLine()}`;
}
function monthName(ym) { const [y, m] = ym.split('-'); return `${y}년 ${Number(m)}월`; }
function catBars(byCat, total) {
  const ent = Object.entries(byCat).sort((a, b) => b[1] - a[1]);
  if (!ent.length) return '';
  const top = ent.slice(0, 5), rest = ent.slice(5).reduce((s, [, v]) => s + v, 0);
  if (rest > 0) top.push(['기타', rest]);
  const cols = ['var(--c1)', 'var(--c2)', 'var(--c3)', 'var(--c4)', 'var(--c5)', 'var(--c6)'];
  return `<div class="card"><b>분류별 지출</b><div class="stack">${top.map(([, v], i) => `<span style="width:${v / total * 100}%;background:${cols[i]}"></span>`).join('')}</div>
    ${top.map(([k, v], i) => `<div class="hb"><div class="row"><span><i style="display:inline-block;width:9px;height:9px;border-radius:3px;background:${cols[i]};margin-right:7px"></i>${esc(k)}</span><span class="num">${won(v)} <span class="muted">${Math.round(v / total * 100)}%</span></span></div></div>`).join('')}</div>`;
}
function vMonth() {
  if (!DATA.txs.length) return `<div class="topbar"><h2>Month</h2></div>` + noData();
  const list = DATA.txs.filter(t => t.d.startsWith(UI.month));
  const s = summarize(list), bal = s.income - s.expense;
  const extra = [s.wifeIn || s.wifeOut ? `부부 이체 받음 ${man(s.wifeIn)} · 보냄 ${man(s.wifeOut)}` : '', s.fin ? `금융·자산이동 ${man(s.fin)}` : ''].filter(Boolean).join('<br>');
  return `<div class="topbar"><h2>${monthName(UI.month)}</h2><div class="nav-arrows"><button data-month="-1" aria-label="이전 달">‹</button><button data-month="1" aria-label="다음 달">›</button></div></div>
  <div class="card"><div class="label">이번 달 잔액 (수입 − 지출)</div><div class="big num ${bal < 0 ? 'exp' : ''}">${won(bal)}</div>
    <div class="kpis"><div class="kpi"><span class="label">수입</span><b class="num inc">${won(s.income)}</b></div><div class="kpi"><span class="label">지출</span><b class="num exp">${won(s.expense)}</b></div><div class="kpi"><span class="label">카드 비중</span><b class="num">${s.expense ? Math.round(s.card / s.expense * 100) : 0}%</b></div></div>
    <div class="note" style="margin-top:12px">수입: 월급 ${won(s.salary)} · 비용환급 ${won(s.reimb)} · 기타 ${won(s.otherInc)}${extra ? '<br>' + extra : ''}</div></div>
  ${goalsBlock(UI.month)}
  ${catBars(s.byCat, s.expense)}
  <div class="tools">${seg('monthMode', UI.monthMode, [['pay', '결제수단별'], ['time', '일자별']])}${seg('filter', UI.filter, [['exp', '지출'], ['inc', '수입'], ['all', '전체']])}</div>
  ${listBlock(list, UI.monthMode, { byDay: true, showDate: true })}${updatedLine()}`;
}
function vYear() {
  if (!DATA.txs.length) return `<div class="topbar"><h2>Year</h2></div>` + noData();
  const y = UI.year, months = Array.from({ length: 12 }, (_, i) => `${y}-${pad2(i + 1)}`);
  const per = months.map(m => summarize(DATA.txs.filter(t => t.d.startsWith(m))));
  const all = summarize(DATA.txs.filter(t => t.d.startsWith(y)));
  const max = Math.max(1, ...per.map(p => Math.max(p.income, p.expense)));
  const cards = DATA.settings.cards;
  const prog = months.map(m => cardProgress(m));
  const active = months.filter((m, i) => per[i].expense || per[i].income).length || 1;
  return `<div class="topbar"><h2>${y}년</h2><div class="nav-arrows"><button data-year="-1" aria-label="이전 해">‹</button><button data-year="1" aria-label="다음 해">›</button></div></div>
  <div class="card"><div class="label">올해 잔액 (수입 − 지출)</div><div class="big num">${won(all.income - all.expense)}</div>
    <div class="kpis"><div class="kpi"><span class="label">수입</span><b class="num inc">${man(all.income)}</b></div><div class="kpi"><span class="label">지출</span><b class="num exp">${man(all.expense)}</b></div><div class="kpi"><span class="label">월평균 지출</span><b class="num">${man(all.expense / active)}</b></div></div></div>
  <div class="card"><b>월별 수입·지출</b>
    <div class="cols">${per.map((p, i) => `<div class="colg ${months[i] === UI.month ? 'sel' : ''}" data-gomonth="${months[i]}" title="${i + 1}월 수입 ${won(p.income)} / 지출 ${won(p.expense)}"><i class="ci" style="height:${p.income / max * 100}%"></i><i class="ce" style="height:${p.expense / max * 100}%"></i></div>`).join('')}</div>
    <div class="xlab">${months.map((m, i) => `<span>${i + 1}</span>`).join('')}</div>
    <div class="legend"><span><i style="background:var(--inc)"></i>수입</span><span><i style="background:var(--exp)"></i>지출</span><span>막대를 누르면 그 달로 이동</span></div></div>
  ${cards.length ? `<div class="card"><b>카드 실적 달성 현황</b><div class="grid12"><span></span>${months.map((m, i) => `<span class="h">${i + 1}</span>`).join('')}
    ${cards.map((c, ci) => `<span class="n">${esc(c.label)}</span>${prog.map((p, mi) => { const x = p[ci]; if (x.isFuture) return '<span class="cell"></span>'; const cls = x.pct >= 100 ? 'ok' : x.pct >= 70 ? 'mid' : x.spent > 0 ? 'low' : ''; return `<span class="cell ${cls}" title="${mi + 1}월 ${won(x.spent)}">${x.pct >= 100 ? '✓' : Math.round(x.pct) + ''}</span>`; }).join('')}`).join('')}
    </div><div class="legend"><span><i style="background:var(--inc)"></i>달성</span><span><i style="background:var(--warn)"></i>70% 이상</span><span>숫자는 달성률(%)</span></div>
    <div class="note" style="margin-top:8px">${cards.map((c, ci) => `${esc(c.label)}: 12개월 중 ${prog.filter(p => p[ci].pct >= 100).length}번 달성`).join(' · ')}</div></div>` : ''}
  ${catBars(all.byCat, all.expense)}
  <div class="card"><b>결제수단별 지출</b>${Object.entries(all.byPay).sort((a, b) => b[1] - a[1]).slice(0, 8).map(([k, v]) => `<div class="hb"><div class="row"><span>${esc(k)}</span><span class="num">${won(v)}</span></div><div class="bar"><span style="width:${v / all.expense * 100}%"></span></div></div>`).join('')}</div>
  ${updatedLine()}`;
}
function vAsset() {
  const a = DATA.assets;
  if (!a) return `<div class="topbar"><h2>Asset</h2></div>` + noData();
  const tot = assetTotals(a);
  const groups = {};
  for (const x of a.assets) if (x.amount > 0) groups[x.group] = (groups[x.group] || 0) + x.amount;
  const ent = Object.entries(groups).sort((p, q) => q[1] - p[1]);
  const cols = ['var(--c1)', 'var(--c2)', 'var(--c3)', 'var(--c4)', 'var(--c5)', 'var(--c6)'];
  const hist = DATA.assetHistory || [];
  return `<div class="topbar"><h2>자산</h2></div>
  <div class="card"><div class="label">순자산</div><div class="big num">${won(tot.net)}</div>
    <div class="kpis" style="grid-template-columns:1fr 1fr"><div class="kpi"><span class="label">총자산</span><b class="num">${man(tot.assets)}</b></div><div class="kpi"><span class="label">총부채</span><b class="num exp">${man(tot.debts)}</b></div></div>
    <div class="stack">${ent.map(([, v], i) => `<span style="width:${v / tot.assets * 100}%;background:${cols[i % 6]}"></span>`).join('')}</div>
    ${ent.map(([k, v], i) => `<div class="hb"><div class="row"><span><i style="display:inline-block;width:9px;height:9px;border-radius:3px;background:${cols[i % 6]};margin-right:7px"></i>${esc(k)}</span><span class="num">${won(v)} <span class="muted">${(v / tot.assets * 100).toFixed(1)}%</span></span></div></div>`).join('')}
    ${hist.length > 1 ? `<div class="note" style="margin-top:12px">지난 업데이트(${hist[hist.length - 2].d}) 대비 ${tot.net - hist[hist.length - 2].net >= 0 ? '+' : ''}${won(tot.net - hist[hist.length - 2].net)}</div>` : ''}</div>
  ${a.invest.length ? `<div class="section-title">투자</div><div class="group">${a.invest.map(x => `<div class="tx"><div class="ic">📈</div><div class="mid"><div class="t1">${esc(x.name)}</div><div class="t2">${esc(x.company || '')} · 원금 ${won(x.principal)}</div></div><div style="text-align:right"><div class="amt num">${won(x.value)}</div><div class="t2 num ${x.rate < 0 ? 'exp' : 'inc'}" style="font-size:12px">${x.rate > 0 ? '+' : ''}${x.rate.toFixed(1)}%</div></div></div>`).join('')}</div>` : ''}
  ${a.loans.length ? `<div class="section-title">대출</div><div class="group">${a.loans.map(x => `<div class="tx"><div class="ic">🏦</div><div class="mid"><div class="t1">${esc(x.name)}</div><div class="t2">한도 ${man(x.principal)} · 금리 ${x.rate}%${x.end ? ' · 만기 ' + x.end : ''}</div></div><div class="amt num exp">${won(x.balance)}</div></div>`).join('')}</div>` : ''}
  <div class="section-title">자산 상세</div>
  ${Object.entries(a.assets.reduce((g, x) => ((g[x.group] ||= []).push(x), g), {})).map(([g, xs]) => {
    const shown = xs.filter(x => x.amount > 0);
    if (!shown.length) return '';
    return `<div class="group"><div class="ghead"><span>${esc(g)}</span><span class="num">${won(shown.reduce((s, x) => s + x.amount, 0))}</span></div>${shown.sort((p, q) => q.amount - p.amount).map(x => `<div class="tx"><div class="mid"><div class="t1">${esc(x.name)}</div></div><div class="amt num">${won(x.amount)}</div></div>`).join('')}</div>`;
  }).join('')}
  <div class="note" style="text-align:center;margin-top:10px">잔액 0원 계좌는 숨겼어요. 마이너스통장 음수 잔액은 부채에서 한 번만 계산해요.</div>
  ${updatedLine()}`;
}
function vSetting() {
  const S = DATA.settings;
  const n = DATA.txs.length;
  return `<div class="topbar"><h2>Setting</h2></div>
  <div class="card"><b>뱅크샐러드 파일 업로드</b>
    <label class="upload" style="display:block;margin-top:12px"><input type="file" id="file" accept=".zip,.xlsx,.xls,application/zip,application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" hidden>
      <div style="font-size:28px">📄</div><div style="font-weight:600;margin-top:4px">파일 선택해서 업데이트</div><div class="note">뱅크샐러드에서 받은 .zip(비밀번호) 또는 .xlsx</div></label>
    <button class="btn block" id="gmailImport" style="margin-top:10px">✉️ Gmail에서 최신 파일 불러오기</button>
    <div id="importMsg" class="note" style="margin-top:10px">${n ? `저장된 내역 ${n.toLocaleString()}건 · ${esc(DATA.fileName || '')}<br>${DATA.txs[n - 1].d} ~ ${DATA.txs[0].d}` : '아직 저장된 내역이 없어요'}</div>
    <div class="note" style="margin-top:8px">파일은 이 기기 안에서만 읽고 암호화해 저장해요. 어떤 서버로도 보내지 않아요. 새 파일을 올리면 그 파일 기간의 내역은 새 내용으로 바뀌고, 그 이전 내역은 남아요.</div></div>

  <div class="card"><b>Gmail 연결</b><div class="note">버튼을 누를 때만 Google 로그인 창이 열리고, 메일은 읽기만 해요. 받은 권한은 불러오기가 끝나면 바로 취소해요.</div>
    <label class="field"><span class="label">Google OAuth 클라이언트 ID</span><input id="gClient" placeholder="xxxx.apps.googleusercontent.com" value="${esc(S.gmail.clientId)}"></label>
    <label class="field"><span class="label">메일 검색어</span><input id="gQuery" value="${esc(S.gmail.query)}"></label>
    <button class="btn" id="saveGmail" style="margin-top:6px">저장</button></div>

  <div class="card"><b>카드 실적 목표</b><div id="cards">${S.cards.map((c, i) => `<div class="cardrow" data-i="${i}">
      <label class="field"><span class="label">이름</span><input data-f="label" value="${esc(c.label)}"></label>
      <label class="field"><span class="label">월 목표(원)</span><input data-f="target" inputmode="numeric" value="${c.target}"></label>
      <label class="field full"><span class="label">결제수단 (뱅크샐러드 표기)</span><select data-f="pay">${payOptions(c.pay)}</select></label>
      <label class="field full"><span class="label">메모</span><input data-f="note" value="${esc(c.note || '')}"></label>
      <button class="btn danger" data-delcard="${i}" style="text-align:left">이 카드 삭제</button></div>`).join('')}</div>
    <div class="row" style="margin-top:12px"><button class="btn sec" id="addCard">카드 추가</button><button class="btn" id="saveCards">저장</button></div></div>

  <div class="card"><b>자동 분류 규칙</b><div class="note">내용에 아래 단어가 들어가면 분류해요. 여러 개는 쉼표로 구분해요.</div>
    <label class="field"><span class="label">월급</span><input id="rSalary" value="${esc(S.rules.salary)}"></label>
    <label class="field"><span class="label">회사 비용청구 환급</span><input id="rReimb" value="${esc(S.rules.reimb)}"></label>
    <label class="field"><span class="label">배우자 이름 (부부 이체로 분리)</span><input id="rWife" value="${esc(S.rules.wife)}"></label>
    <label class="field"><span class="label">이 날짜 이후 내역만 사용</span><input id="rStart" type="date" value="${esc(S.startDate)}"></label>
    <button class="btn" id="saveRules" style="margin-top:6px">저장</button></div>

  <div class="card"><b>보안</b>
    <div class="set-item"><div>Face ID / Touch ID<div class="muted">${META.bio ? '사용 중' : '켜면 비밀번호 대신 얼굴로 열어요'}</div></div><button class="btn sec" id="bioToggle">${META.bio ? '끄기' : '켜기'}</button></div>
    <div class="set-item"><div>비밀번호 변경</div><button class="btn sec" id="chPin">변경</button></div>
    <div class="set-item"><div>지금 잠그기<div class="muted">앱을 1분 이상 벗어나면 자동으로 잠겨요</div></div><button class="btn sec" id="lockNow">잠금</button></div>
    <div class="set-item"><div>화면 모드</div>${seg('theme', document.documentElement.dataset.theme || 'auto', [['auto', '자동'], ['light', '라이트'], ['dark', '다크']])}</div>
    <div class="set-item"><div class="exp">이 기기의 모든 데이터 삭제</div><button class="btn danger" id="wipe">삭제</button></div></div>
  <div class="note" style="text-align:center">우리집 가계부 · 데이터는 이 기기에만 저장돼요</div>`;
}
function payOptions(cur) {
  const pays = [...new Set(DATA.txs.filter(t => t.type === '지출').map(t => t.pay))].filter(p => /카드|간편결제/.test(p)).sort();
  if (cur && !pays.includes(cur)) pays.unshift(cur);
  return '<option value="">선택하세요</option>' + pays.map(p => `<option ${p === cur ? 'selected' : ''}>${esc(p)}</option>`).join('');
}

// ---------- 고정비 (매달 반복 결제·할부 자동 감지 + 사용자 수정) ----------
const FIX_TYPES = ['구독', '통신', '주거', '보험', '렌탈', '할부', '대출', '기타'];
const FIX_ICON = { 구독: '🔁', 통신: '📱', 주거: '🏠', 보험: '🛡️', 렌탈: '💧', 할부: '🧾', 대출: '🏦', 기타: '📌' };
const normMemo = m => String(m || '').replace(/[0-9]+/g, '').replace(/\s+/g, ' ').trim();
const FIX_KW = /관리비|자동납부|자동이체|보험|텔레콤|통신|가스|전기|수도|렌탈|코웨이|생명|손해|DB손|삼성생|SKT|KT|U\+|이자/;
function guessType(memo, amt, cat) {
  const a = String(Math.abs(Math.round(amt)));
  if (/(\d)\1{3,}$/.test(a) && Math.abs(amt) >= 100000) return '할부';
  if (/보험|생명|손해|DB손|삼성생/.test(memo)) return '보험';
  if (/텔레콤|SKT|KT|U\+|통신|피에스앤마케팅/.test(memo)) return '통신';
  if (/관리비|가스|전기|수도|에너지/.test(memo) || cat === '주거/통신') return '주거';
  if (/코웨이|렌탈/.test(memo)) return '렌탈';
  if (/이자|대출/.test(memo)) return '대출';
  if (/SUBSCR|Netflix|멤버십|Apple|플러스|구독|YouTube|Google|와우|시리즈|CLAUDE|OPENAI/i.test(memo)) return '구독';
  // 같은 금액이 매달 반복되는 10만원 이상 결제는 대부분 카드 할부
  if (Math.abs(amt) >= 100000 && cat !== '주거/통신') return '할부';
  return '기타';
}
const ymAdd = (ym, n) => { const [y, m] = ym.split('-').map(Number); const d = new Date(y, m - 1 + n, 1); return `${d.getFullYear()}-${pad2(d.getMonth() + 1)}`; };
const median = a => { const s = [...a].sort((x, y) => x - y); return s.length ? s[Math.floor(s.length / 2)] : 0; };
function detectFixed() {
  if (!DATA.txs.length) return [];
  const end = DATA.txs[0].d.slice(0, 7), from = ymAdd(end, -11);
  const pool = DATA.txs.filter(t => t.amt < 0 && t.d.slice(0, 7) >= from && (isExp(t) || (t.k === 'fin' && FIX_KW.test(t.memo))) && Math.abs(t.amt) < 5e6);
  const out = [], used = new Set();
  const build = (key, ts, variable) => {
    const months = [...new Set(ts.map(t => t.d.slice(0, 7)))].sort();
    const last = ts.reduce((a, b) => (a.d + a.t > b.d + b.t ? a : b));
    const perMonth = months.map(m => -ts.filter(t => t.d.startsWith(m)).reduce((s, t) => s + t.amt, 0));
    const amount = variable ? perMonth[perMonth.length - 1] : -last.amt;
    return { key, name: last.memo, pay: last.pay, cat: last.cat, amount, day: Math.round(median(ts.map(t => +t.d.slice(8)))),
      months, lastMonth: months[months.length - 1], variable, type: guessType(last.memo, amount, last.cat), auto: true, txKeys: ts };
  };
  // A: 같은 가맹점·같은 금액이 3개월 이상 (구독, 할부, 정액 이체)
  const ga = {}, freq = {};
  for (const t of pool) {
    (ga[normMemo(t.memo) + '|' + t.pay + '|' + Math.round(t.amt)] ||= []).push(t);
    const f = (freq[normMemo(t.memo) + '|' + t.pay] ||= { n: 0, m: new Set() }); f.n++; f.m.add(t.d.slice(0, 7));
  }
  for (const [k, ts] of Object.entries(ga)) {
    const months = new Set(ts.map(t => t.d.slice(0, 7)));
    if (months.size < 3 || ts.length / months.size > 1.2) continue;
    // 편의점·배달처럼 자주 가는 곳에서 우연히 같은 금액이 반복된 경우는 제외
    const f = freq[normMemo(ts[0].memo) + '|' + ts[0].pay];
    if (f.n / f.m.size > 2 && guessType(ts[0].memo, ts[0].amt, ts[0].cat) === '기타') continue;
    out.push(build('A|' + k, ts, false)); ts.forEach(t => used.add(t));
  }
  // B: 금액이 달라지는 공과금·통신·보험·관리비
  const gb = {};
  for (const t of pool) if (!used.has(t) && FIX_KW.test(t.memo)) (gb[normMemo(t.memo) + '|' + t.pay] ||= []).push(t);
  for (const [k, ts] of Object.entries(gb)) {
    const months = new Set(ts.map(t => t.d.slice(0, 7)));
    if (months.size >= 3 && ts.length / months.size <= 2.2) out.push(build('B|' + k, ts, true));
  }
  return out;
}
function fixedItems() {
  const F = DATA.settings.fixed, end = DATA.txs[0]?.d.slice(0, 7) || today.slice(0, 7), cur = today.slice(0, 7);
  const items = detectFixed().map(it => Object.assign(it, F.overrides[it.key] || {}));
  for (const m of F.manual) items.push({ ...m, auto: false, months: [], lastMonth: '', txKeys: [] });
  for (const it of items) {
    it.active = !it.auto || it.lastMonth >= ymAdd(end, -1);
    const paidTx = it.txKeys.filter(t => t.d.startsWith(cur));
    it.paidThisMonth = paidTx.length ? paidTx[0].d : null;
    if (it.type === '할부') {
      const startYm = it.start || it.months[0] || cur;
      it.paidCount = it.auto ? it.months.length : Math.max(0, monthsBetween(startYm, cur) + 1);
      if (it.total) { it.remain = Math.max(0, it.total - it.paidCount); it.endYm = ymAdd(startYm, it.total - 1); if (it.remain === 0 && it.paidCount >= it.total && !it.paidThisMonth) it.active = false; }
    }
  }
  return items.filter(it => !it.hidden).sort((a, b) => a.day - b.day || b.amount - a.amount);
}
const monthsBetween = (a, b) => { const [y1, m1] = a.split('-').map(Number), [y2, m2] = b.split('-').map(Number); return (y2 - y1) * 12 + (m2 - m1); };
function fixedRow(it) {
  const sub = [it.pay, it.type, it.variable ? '금액 변동' : null].filter(Boolean).join(' · ');
  let status = '';
  if (it.type === '할부') status = it.total ? `${Math.min(it.paidCount, it.total)}/${it.total}회 · ${it.remain ? `남은 ${it.remain}회 ${man(it.remain * it.amount)}원 · ${it.endYm} 끝` : '완납'}` : `${it.paidCount}회째 결제 · 총 회차를 입력하면 남은 금액이 보여요`;
  const badge = it.active ? (it.paidThisMonth ? `<span class="inc" style="font-size:12px">✓ ${+it.paidThisMonth.slice(8)}일 결제</span>` : `<span class="muted" style="font-size:12px">${it.day}일 예정</span>`) : '<span class="muted" style="font-size:12px">최근 결제 없음</span>';
  return `<button class="tx fx" data-fixed="${esc(it.key)}" style="width:100%;text-align:left"><div class="ic daybadge"><b>${it.day}</b><small>일</small></div>
    <div class="mid"><div class="t1">${FIX_ICON[it.type] || ''} ${esc(it.name)}</div><div class="t2">${esc(sub)}</div>${status ? `<div class="t2" style="color:var(--accent)">${esc(status)}</div>` : ''}</div>
    <div style="text-align:right"><div class="amt num">${won(it.amount)}</div>${badge}</div></button>`;
}
function vFixed() {
  if (!DATA.txs.length && !DATA.settings.fixed.manual.length) return `<div class="topbar"><h2>고정비</h2></div>` + noData();
  const items = fixedItems(), act = items.filter(i => i.active), old = items.filter(i => !i.active);
  const total = act.reduce((s, i) => s + i.amount, 0), paid = act.filter(i => i.paidThisMonth).reduce((s, i) => s + i.amount, 0);
  const byType = {}; for (const i of act) byType[i.type] = (byType[i.type] || 0) + i.amount;
  const inst = act.filter(i => i.type === '할부');
  return `<div class="topbar"><h2>고정비</h2><button class="btn sec" data-fixadd style="padding:8px 12px;font-size:14px">+ 추가</button></div>
  <div class="card"><div class="label">매달 나가는 고정비</div><div class="big num">${won(total)}</div>
    <div class="kpis"><div class="kpi"><span class="label">이번 달 결제</span><b class="num inc">${man(paid)}</b></div><div class="kpi"><span class="label">남은 예정</span><b class="num">${man(total - paid)}</b></div><div class="kpi"><span class="label">할부</span><b class="num">${inst.length}건 ${man(inst.reduce((s, i) => s + i.amount, 0))}</b></div></div>
    <div class="note" style="margin-top:12px">${Object.entries(byType).sort((a, b) => b[1] - a[1]).map(([k, v]) => `${FIX_ICON[k]} ${k} ${man(v)}`).join(' · ')}</div></div>
  <div class="section-title">결제일 순 <span class="label">눌러서 이름·금액·할부 회차 수정</span></div>
  <div class="group">${act.map(fixedRow).join('') || '<div class="empty">찾은 고정비가 없어요</div>'}</div>
  ${old.length ? `<div class="section-title">최근 결제가 없는 항목 <span class="label">끝났거나 해지된 것 같아요</span></div><div class="group" style="opacity:.7">${old.map(fixedRow).join('')}</div>` : ''}
  <div class="note" style="text-align:center;margin-top:10px">최근 12개월 내역에서 3개월 이상 반복된 결제를 자동으로 찾았어요. 할부는 카드사가 회차별 금액을 보내준 경우에만 잡혀요. 안 잡힌 할부는 + 추가로 넣어 주세요.</div>`;
}
function editFixed(key) {
  const F = DATA.settings.fixed;
  const it = key ? fixedItems().concat(detectFixed().filter(x => F.overrides[x.key]?.hidden).map(x => Object.assign(x, F.overrides[x.key]))).find(i => i.key === key) : { key: 'M|' + Date.now(), name: '', amount: 0, day: 1, pay: '', type: '할부', auto: false, isNew: true };
  if (!it) return;
  const w = document.createElement('div'); w.className = 'modal';
  w.innerHTML = `<form class="sheet" style="max-width:420px;max-height:90vh;overflow:auto"><b>${it.isNew ? '고정비 추가' : '고정비 수정'}</b>
    <label class="field"><span class="label">이름</span><input name="name" value="${esc(it.name)}" required></label>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px"><label class="field"><span class="label">월 금액(원)</span><input name="amount" inputmode="numeric" value="${Math.round(it.amount) || ''}"></label>
    <label class="field"><span class="label">결제일</span><input name="day" inputmode="numeric" value="${it.day}"></label></div>
    <label class="field"><span class="label">종류</span><select name="type">${FIX_TYPES.map(t => `<option ${t === it.type ? 'selected' : ''}>${t}</option>`).join('')}</select></label>
    ${it.auto ? '' : `<label class="field"><span class="label">결제수단</span><input name="pay" value="${esc(it.pay || '')}"></label>`}
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px"><label class="field"><span class="label">할부 총 회차</span><input name="total" inputmode="numeric" placeholder="예: 12" value="${it.total || ''}"></label>
    <label class="field"><span class="label">첫 결제 월</span><input name="start" type="month" value="${esc(it.start || it.months?.[0] || '')}"></label></div>
    <div class="row" style="margin-top:14px">${it.isNew ? '<span></span>' : `<button type="button" class="btn danger" data-del>${it.auto ? '목록에서 숨기기' : '삭제'}</button>`}<span style="display:flex;gap:8px"><button type="button" class="btn sec" data-x>취소</button><button class="btn">저장</button></span></div></form>`;
  document.body.appendChild(w);
  const close = () => w.remove();
  w.querySelector('[data-x]').onclick = close;
  w.querySelector('[data-del]')?.addEventListener('click', async () => {
    if (it.auto) F.overrides[it.key] = { ...(F.overrides[it.key] || {}), hidden: true }; else F.manual = F.manual.filter(m => m.key !== it.key);
    await persist(); close(); render(); toast('목록에서 뺐어요');
  });
  w.querySelector('form').onsubmit = async e => {
    e.preventDefault(); const f = new FormData(e.target), num = n => Number(String(f.get(n) || '').replace(/[^0-9]/g, '')) || 0;
    const v = { name: String(f.get('name')).trim() || it.name, amount: num('amount'), day: Math.min(31, Math.max(1, num('day') || 1)), type: f.get('type'), total: num('total') || undefined, start: f.get('start') || undefined };
    if (it.auto) F.overrides[it.key] = { ...(F.overrides[it.key] || {}), ...v };
    else { v.pay = String(f.get('pay') || '').trim(); const i = F.manual.findIndex(m => m.key === it.key); if (i >= 0) F.manual[i] = { ...F.manual[i], ...v }; else F.manual.push({ key: it.key, ...v }); }
    await persist(); close(); render(); toast('저장했어요');
  };
}

// ---------- Gmail 불러오기 (OAuth 리디렉트, 서버 없음) ----------
// 토큰은 메모리에만 두고, 불러오기가 끝나면 바로 취소(revoke)합니다.
let GTOKEN = null;
const appUrl = () => location.origin + location.pathname;
function gmailStart() {
  const id = DATA.settings.gmail.clientId;
  if (!id) { toast('먼저 아래 Gmail 연결에 클라이언트 ID를 넣어 주세요'); return; }
  const state = b64(rand(16)).replace(/[^A-Za-z0-9]/g, '');
  try { sessionStorage.setItem('gstate', state); } catch {}
  const q = new URLSearchParams({ client_id: id, redirect_uri: appUrl(), response_type: 'token', scope: 'https://www.googleapis.com/auth/gmail.readonly', state, include_granted_scopes: 'false', prompt: 'select_account' });
  location.href = 'https://accounts.google.com/o/oauth2/v2/auth?' + q;
}
function gmailCatchRedirect() {
  if (!location.hash || !/access_token=|error=/.test(location.hash)) return;
  const h = new URLSearchParams(location.hash.slice(1));
  history.replaceState(null, '', appUrl());
  let saved = null; try { saved = sessionStorage.getItem('gstate'); sessionStorage.removeItem('gstate'); } catch {}
  if (h.get('error')) { setTimeout(() => toast('Google 로그인이 취소됐어요'), 300); return; }
  if (!saved || h.get('state') !== saved) { setTimeout(() => toast('로그인 확인값이 맞지 않아 무시했어요'), 300); return; }
  GTOKEN = h.get('access_token');
}
async function gapi(token, path) {
  const r = await fetch('https://gmail.googleapis.com/gmail/v1/users/me/' + path, { headers: { Authorization: 'Bearer ' + token } });
  if (!r.ok) throw new Error(r.status === 401 || r.status === 403 ? 'Gmail 권한이 없어요. 다시 시도해 주세요' : 'Gmail 응답 오류 (' + r.status + ')');
  return r.json();
}
const b64url = s => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
function findAttachment(part) {
  if (part.filename && /\.(zip|xlsx)$/i.test(part.filename) && part.body?.attachmentId) return part;
  for (const p of part.parts || []) { const f = findAttachment(p); if (f) return f; }
  return null;
}
async function gmailImport(token) {
  UI.tab = 'setting'; render();
  const msg = () => $('#importMsg');
  try {
    msg().textContent = 'Gmail에서 뱅크샐러드 메일을 찾는 중…';
    const list = await gapi(token, 'messages?maxResults=10&q=' + encodeURIComponent(DATA.settings.gmail.query));
    let found = null;
    for (const m of list.messages || []) {
      const full = await gapi(token, 'messages/' + m.id + '?format=full');
      const att = findAttachment(full.payload);
      if (att) { found = { id: m.id, att, date: new Date(Number(full.internalDate)), subject: (full.payload.headers || []).find(x => x.name.toLowerCase() === 'subject')?.value || '' }; break; }
    }
    if (!found) throw new Error('첨부파일이 있는 뱅크샐러드 메일을 찾지 못했어요. 메일 검색어를 확인해 주세요');
    msg().textContent = `${found.date.toLocaleString('ko-KR')} 메일의 ${found.att.filename} 내려받는 중…`;
    const a = await gapi(token, `messages/${found.id}/attachments/${found.att.body.attachmentId}`);
    const r = await importBuffer(b64url(a.data).buffer, found.att.filename);
    toast(`Gmail에서 불러오기 완료 · ${r.added.toLocaleString()}건 (${r.from} ~ ${r.to})`);
    UI.tab = 'today'; render();
  } catch (err) { if (msg()) msg().innerHTML = `<span class="exp">${esc(err.message)}</span>`; }
  finally { fetch('https://oauth2.googleapis.com/revoke?token=' + encodeURIComponent(token), { method: 'POST' }).catch(() => {}); }
}

// ---------- events ----------
let toastT;
function toast(msg) {
  document.querySelector('.toast')?.remove(); clearTimeout(toastT);
  const d = document.createElement('div'); d.className = 'toast'; d.textContent = msg; document.body.appendChild(d);
  toastT = setTimeout(() => d.remove(), 3200);
}
function shiftDay(n) { const d = new Date(UI.day + 'T00:00:00'); d.setDate(d.getDate() + n); UI.day = ymd(d); }
function shiftMonth(n) { const [y, m] = UI.month.split('-').map(Number); const d = new Date(y, m - 1 + n, 1); UI.month = `${d.getFullYear()}-${pad2(d.getMonth() + 1)}`; }
function readCards() {
  return [...document.querySelectorAll('#cards .cardrow')].map(r => ({
    label: r.querySelector('[data-f=label]').value.trim() || '카드', target: Number(String(r.querySelector('[data-f=target]').value).replace(/[^0-9]/g, '')) || 0,
    pay: r.querySelector('[data-f=pay]').value, note: r.querySelector('[data-f=note]').value.trim() }));
}
document.addEventListener('click', async e => {
  const el = e.target.closest('button,[data-gomonth]'); if (!el || !DEK) return;
  const d = el.dataset;
  if (d.tab) { if (d.tab === 'setting' && UI.tab !== 'setting') UI.prevTab = UI.tab; UI.tab = d.tab; return render(); }
  if (d.fixed) return editFixed(d.fixed);
  if ('fixadd' in d) return editFixed(null);
  if (d.go) { UI.tab = d.go; return render(); }
  if (d.day) { if (d.day === '0') UI.day = today; else shiftDay(+d.day); return render(); }
  if (d.month) { shiftMonth(+d.month); UI.year = UI.month.slice(0, 4); return render(); }
  if (d.year) { UI.year = String(+UI.year + +d.year); return render(); }
  if (d.gomonth) { UI.month = d.gomonth; UI.tab = 'month'; return render(); }
  const sg = el.closest('[data-seg]');
  if (sg && d.v) {
    const k = sg.dataset.seg;
    if (k === 'theme') { if (d.v === 'auto') { delete document.documentElement.dataset.theme; try { localStorage.removeItem('theme'); } catch {} } else { document.documentElement.dataset.theme = d.v; try { localStorage.setItem('theme', d.v); } catch {} } }
    else UI[k] = d.v;
    return render();
  }
  if (d.delcard) { DATA.settings.cards = readCards(); DATA.settings.cards.splice(+d.delcard, 1); await persist(); return render(); }
  switch (el.id) {
    case 'addCard': DATA.settings.cards = readCards(); DATA.settings.cards.push({ label: '새 카드', target: 300000, pay: '', note: '' }); return render();
    case 'saveCards': DATA.settings.cards = readCards().filter(c => c.pay); await persist(); toast('카드 실적 목표를 저장했어요'); return render();
    case 'saveRules': {
      const R = DATA.settings.rules; R.salary = $('#rSalary').value; R.reimb = $('#rReimb').value; R.wife = $('#rWife').value;
      DATA.settings.startDate = $('#rStart').value || DEFAULT_SETTINGS.startDate;
      DATA.txs = DATA.txs.filter(t => t.d >= DATA.settings.startDate);
      reclassify(); await persist(); toast('분류 규칙을 저장했어요'); return render();
    }
    case 'bioToggle':
      if (META.bio) { delete META.bio; await idb.set('meta', META); toast('Face ID를 껐어요'); return render(); }
      try { await enrollBio(); toast('Face ID를 켰어요. 다음부터 얼굴로 열 수 있어요'); } catch (err) { toast(err.name === 'NotAllowedError' ? '취소됐어요' : err.message); }
      return render();
    case 'chPin':
      pinStage = 'change-new'; $('#app').classList.add('hidden'); $('#tabbar').classList.add('hidden'); $('#lock').classList.remove('hidden'); $('#bioBtn').classList.add('hidden');
      return lockMsg('새 비밀번호 6자리를 입력하세요');
    case 'lockNow': return lock();
    case 'saveGmail': DATA.settings.gmail.clientId = $('#gClient').value.trim(); DATA.settings.gmail.query = $('#gQuery').value.trim() || DEFAULT_SETTINGS.gmail.query; await persist(); toast('Gmail 설정을 저장했어요'); return render();
    case 'gmailImport': return gmailStart();
    case 'wipe':
      if (!confirm('이 기기에 저장된 가계부 데이터와 비밀번호를 모두 지울까요? 되돌릴 수 없어요.')) return;
      await idb.clear(); META = null; DEK = null; DATA = null; location.reload(); return;
  }
});
document.addEventListener('change', async e => {
  if (e.target.id !== 'file' || !e.target.files[0]) return;
  const msg = $('#importMsg'); msg.textContent = '파일을 읽는 중…';
  try {
    const r = await importFile(e.target.files[0]);
    toast(`업데이트 완료 · ${r.added.toLocaleString()}건 (${r.from} ~ ${r.to})`);
    UI.tab = 'today'; render();
  } catch (err) { msg.innerHTML = `<span class="exp">${esc(err.message)}</span>`; }
});
$('#bioBtn').addEventListener('click', unlockBio);

// ---------- boot ----------
(async function boot() {
  try { const th = localStorage.getItem('theme'); if (th) document.documentElement.dataset.theme = th; } catch {}
  setupPad();
  gmailCatchRedirect();
  if (!window.crypto?.subtle) { lockMsg('보안 연결(https)에서만 열 수 있어요'); $('#pad').classList.add('hidden'); return; }
  META = await idb.get('meta');
  if (!META) { pinStage = 'new'; $('#lockTitle').textContent = '처음 오셨네요'; lockMsg('이 기기에서 쓸 비밀번호 6자리를 정하세요'); }
  else if (META.bio) { $('#bioBtn').classList.remove('hidden'); }
  if (GTOKEN && META) lockMsg('Gmail 연결됨 · 잠금을 풀면 바로 불러와요');
  if ('serviceWorker' in navigator && location.protocol === 'https:') navigator.serviceWorker.register('sw.js').catch(() => {});
})();
