const VERSION='mis-2027-offline-v13';
const STATIC_CACHE=`${VERSION}-static`;
const DATA_CACHE=`${VERSION}-data`;
const STUDY_CACHE=`${VERSION}-study`;
const STATIC=['/','/index.html','/styles.css?v=20260924h-pdf-preview','/app.js?v=20260924h-pdf-preview','/manifest.webmanifest?v=20260924h-pdf-preview','/favicon.svg?v=20260924h-pdf-preview','/mis-logo.png','/icon-192.png','/icon-512.png'];
self.addEventListener('install',event=>{event.waitUntil(caches.open(STATIC_CACHE).then(c=>c.addAll(STATIC)).then(()=>self.skipWaiting()))});
self.addEventListener('activate',event=>{event.waitUntil((async()=>{for(const key of await caches.keys())if(![STATIC_CACHE,DATA_CACHE,STUDY_CACHE].includes(key))await caches.delete(key);await self.clients.claim()})())});
async function networkFirst(req,cacheName){const cache=await caches.open(cacheName);try{const res=await fetch(req);if(res&&res.ok)cache.put(req,res.clone());return res}catch{const hit=await cache.match(req);if(hit)return hit;throw new Error('offline')}}
async function cacheFirst(req,cacheName){const cache=await caches.open(cacheName);const hit=await cache.match(req);if(hit)return hit;const res=await fetch(req);if(res&&res.ok)cache.put(req,res.clone());return res}
self.addEventListener('fetch',event=>{const req=event.request;if(req.method!=='GET')return;const url=new URL(req.url);if(url.origin!==self.location.origin)return;if(url.pathname.startsWith('/api/admin/')||url.pathname.startsWith('/api/auth/'))return;
  if(req.mode==='navigate'){event.respondWith(networkFirst(req,STATIC_CACHE).catch(()=>caches.match('/index.html')));return}
  if(url.pathname==='/api/public'){event.respondWith(networkFirst(req,DATA_CACHE));return}
  if(/^\/api\/(files|explanation-files|explanation-preview)\//.test(url.pathname)){event.respondWith(networkFirst(req,STUDY_CACHE));return}
  if(['style','script','image','font','manifest'].includes(req.destination)||url.pathname==='/favicon.svg'){event.respondWith(cacheFirst(req,STATIC_CACHE));return}
});
self.addEventListener('message',event=>{const data=event.data||{};if(data.type!=='CACHE_STUDY_CONTENT'||!Array.isArray(data.urls))return;event.waitUntil((async()=>{const cache=await caches.open(STUDY_CACHE);let ok=0,failed=0;for(const path of data.urls){try{const req=new Request(path,{credentials:'same-origin'});const res=await fetch(req);if(!res.ok)throw new Error(String(res.status));await cache.put(req,res.clone());ok++}catch{failed++}}const clients=await self.clients.matchAll({includeUncontrolled:true,type:'window'});for(const client of clients)client.postMessage({type:'OFFLINE_CACHE_DONE',ok,failed,silent:!!data.silent})})())});
self.addEventListener('notificationclick',event=>{event.notification.close();event.waitUntil((async()=>{const all=await self.clients.matchAll({type:'window',includeUncontrolled:true});if(all.length){await all[0].focus();return}await self.clients.openWindow('/')})())});
