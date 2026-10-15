// 서비스 워커 — 앱 화면·악보 보기 프로그램을 기기에 보관해 인터넷 없이도 앱이 열리게 함 (악보 파일 보관은 index.html의 IndexedDB가 담당)
var CACHE = 'wsl-app-v1';

// 처음 설치할 때 미리 보관할 것
var CORE = ['/', '/manifest.webmanifest', '/icon-192.png', '/icon-512.png', '/apple-touch-icon.png'];
var CDN = [
  'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.min.js',
  'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.worker.min.js'
];
// 바뀌지 않는 외부 파일(악보 보기 프로그램, 글꼴) — 한 번 받으면 보관본 사용
var CDN_HOSTS = ['cdnjs.cloudflare.com', 'fonts.googleapis.com', 'fonts.gstatic.com'];

self.addEventListener('install', function (e) {
  e.waitUntil(caches.open(CACHE).then(function (c) {
    return c.addAll(CORE).then(function () {
      // 외부 파일은 하나가 실패해도 설치는 계속
      return Promise.all(CDN.map(function (u) { return c.add(new Request(u, { mode: 'cors' })).catch(function () {}); }));
    });
  }));
  self.skipWaiting();
});

self.addEventListener('activate', function (e) {
  e.waitUntil(caches.keys().then(function (keys) {
    return Promise.all(keys.filter(function (k) { return k !== CACHE; }).map(function (k) { return caches.delete(k); }));
  }).then(function () { return self.clients.claim(); }));
});

self.addEventListener('fetch', function (e) {
  var req = e.request;
  if (req.method !== 'GET') return;               // /api/gas (POST)는 손대지 않음
  var url = new URL(req.url);

  // 앱 화면: 인터넷이 되면 항상 최신 화면(새 버전 자동 적용), 안 되거나 4초 넘게 걸리면 보관본
  if (req.mode === 'navigate') {
    e.respondWith(networkFirst(req));
    return;
  }
  if (url.origin === self.location.origin) {
    if (url.pathname.indexOf('/api/') === 0) return;
    e.respondWith(staleWhileRevalidate(req));
    return;
  }
  if (CDN_HOSTS.indexOf(url.hostname) >= 0) {
    e.respondWith(cacheFirst(req));
  }
});

function networkFirst(req) {
  return caches.open(CACHE).then(function (c) {
    var net = fetch(req).then(function (res) {
      if (res && res.ok) c.put('/', res.clone());
      return res;
    });
    var timeout = new Promise(function (resolve) { setTimeout(resolve, 4000); });
    return Promise.race([net.catch(function () { return null; }), timeout]).then(function (res) {
      if (res) return res;
      return c.match('/').then(function (hit) { return hit || net; });
    });
  });
}

function staleWhileRevalidate(req) {
  return caches.open(CACHE).then(function (c) {
    return c.match(req).then(function (hit) {
      var net = fetch(req).then(function (res) {
        if (res && res.ok) c.put(req, res.clone());
        return res;
      }).catch(function () { return hit; });
      return hit || net;
    });
  });
}

function cacheFirst(req) {
  return caches.open(CACHE).then(function (c) {
    return c.match(req).then(function (hit) {
      if (hit) return hit;
      return fetch(req).then(function (res) {
        if (res && (res.ok || res.type === 'opaque')) c.put(req, res.clone());
        return res;
      });
    });
  });
}
