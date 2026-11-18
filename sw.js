// 앱 화면 파일만 캐시합니다. 금융 데이터는 캐시하지 않습니다(IndexedDB에 암호화 저장).
const V = 'gagyebu-v2';
const SHELL = ['./', 'index.html', 'app.js', 'xlsx.mini.min.js', 'zip.min.js', 'manifest.webmanifest', 'icon-180.png', 'icon-192.png', 'icon-512.png'];
self.addEventListener('install', e => { e.waitUntil(caches.open(V).then(c => c.addAll(SHELL)).then(() => self.skipWaiting())); });
self.addEventListener('activate', e => { e.waitUntil(caches.keys().then(ks => Promise.all(ks.filter(k => k !== V).map(k => caches.delete(k)))).then(() => self.clients.claim())); });
self.addEventListener('fetch', e => {
  if (e.request.method !== 'GET' || new URL(e.request.url).origin !== location.origin) return;
  // 네트워크 우선(업데이트 반영), 오프라인이면 캐시
  e.respondWith(fetch(e.request).then(r => { const c = r.clone(); caches.open(V).then(x => x.put(e.request, c)); return r; }).catch(() => caches.match(e.request, { ignoreSearch: true })));
});
