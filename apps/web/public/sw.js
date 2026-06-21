const cacheName = "evbus-shell-v1";
const shellAssets = ["/", "/manifest.webmanifest"];

self.addEventListener("install", (event) => {
  event.waitUntil(caches.open(cacheName).then((cache) => cache.addAll(shellAssets)));
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((keys) => Promise.all(keys.filter((key) => key !== cacheName).map((key) => caches.delete(key))))
  );
});

self.addEventListener("fetch", (event) => {
  const request = event.request;
  const url = new URL(request.url);
  const isShellAsset =
    url.origin === self.location.origin &&
    (request.mode === "navigate" ||
      url.pathname === "/" ||
      url.pathname === "/index.html" ||
      url.pathname === "/manifest.webmanifest" ||
      url.pathname.startsWith("/assets/"));

  if (request.method !== "GET" || !isShellAsset) return;

  event.respondWith(
    fetch(request)
      .then((response) => {
        const copy = response.clone();
        event.waitUntil(caches.open(cacheName).then((cache) => cache.put(request, copy)));
        return response;
      })
      .catch(() => caches.match(request).then((cached) => cached ?? caches.match("/")))
  );
});
