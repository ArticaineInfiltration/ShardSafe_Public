// compressWorker.js
importScripts("https://cdnjs.cloudflare.com/ajax/libs/pako/2.1.0/pako.min.js");

self.onmessage = function (e) {
  const { type, buffer } = e.data;

  if (type === 'compress') {
    try {
      const uint8 = new Uint8Array(buffer);
      const compressed = pako.deflate(uint8);
      self.postMessage({ status: 'success', compressed: compressed.buffer }, [compressed.buffer]);
    } catch (err) {
      self.postMessage({ status: 'error', message: err.message });
    }
  }
};