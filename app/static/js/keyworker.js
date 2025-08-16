let storedKey = null;

self.addEventListener('message', async (event) => {
  const { type, data } = event.data;

  switch (type) {
    case 'set':
      storedKey = data; // e.g. a CryptoKey or raw key
      self.postMessage({ success: true, message: 'Key stored securely' });
      break;

    case 'get':
      if(storedKey == null){
        self.postMessage({ success: false, key: null });
      }else{
        self.postMessage({ success: true, key: storedKey });
      }
      break;

    case 'clear':
      storedKey = null;
      self.postMessage({ success: true, message: 'Key cleared' });
      break;

    default:
      self.postMessage({ success: false, message: 'Unknown command' });
  }
});
