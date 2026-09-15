// ==========================================
// SPORTBOOK - Service Worker
// ==========================================

const CACHE_NAME = 'sportbook-v2';
const ASSETS = [
  '/',
  '/index.html',
  '/select-game.html',
  '/manifest.json',
  '/icon-192.png',
  '/icon-512.png'
];

self.addEventListener('install', e => {
  e.waitUntil(
    caches.open(CACHE_NAME).then(cache => cache.addAll(ASSETS))
  );
  self.skipWaiting();
});

self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k)))
    )
  );
  self.clients.claim();
});

self.addEventListener('fetch', e => {
  if (e.request.url.includes('supabase.co')) return; // Don't cache API calls
  // Network-first, cache as offline fallback only. The old cache-first
  // strategy served stale HTML/JS indefinitely after every deploy unless
  // CACHE_NAME was manually bumped - that's exactly what caused a player
  // to keep re-running pre-fix login code no matter how many times she
  // logged in, since her browser never re-fetched select-game.html. This
  // way a normal (online) load always gets the latest deploy, and the
  // cache only kicks in if the network request actually fails.
  e.respondWith(
    fetch(e.request).then(res => {
      const resClone = res.clone();
      caches.open(CACHE_NAME).then(cache => cache.put(e.request, resClone));
      return res;
    }).catch(() => caches.match(e.request))
  );
});
