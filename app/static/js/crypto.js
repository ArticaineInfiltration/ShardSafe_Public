async function generateLoginKeyPair() {
  const loginKeyPair = await window.crypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 2048,
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
      hash: "SHA-256",
    },
    true, // extractable
    ["sign", "verify"]
  );

  return loginKeyPair;
}

async function generateRandomAESKey(){
  const key = await crypto.subtle.generateKey(
    {name:"AES-GCM",
      length:256,
    }, 
    true,
    ["encrypt","decrypt"],
  );

  // get the raw key: 
  const rawKey = await crypto.subtle.exportKey("raw",key);

 return rawKey;
}


 function rawKeyToHex(rawKey){
  const keyHex = Array.from(new Uint8Array(rawKey))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
  return keyHex;
  }

  function rawKeyToB64(rawKey){
    const uint8Array = new Uint8Array(rawKey);
    const base64Key = btoa(String.fromCharCode(...uint8Array));

    return base64Key;
  }

// hex to arraybuffer
function hexToArrayBuffer(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes.buffer;
}

async function arrayBufferToAESKey(rawKeyBuffer) {
  const key = await crypto.subtle.importKey(
    "raw",              
    rawKeyBuffer,        
    { name: "AES-GCM" },
    false,               
    ["encrypt", "decrypt"] 
  );
  return key;
}


async function importBase64PublicKey(base64Key) {
  const binaryKey = base64ToArrayBuffer(base64Key);
  console.log("post binary");
  return await crypto.subtle.importKey(
    'spki',
    binaryKey,
    {
      name: 'RSA-OAEP',
      hash: 'SHA-256'
    },
    false,
    ['encrypt']
  );
}

async function importAESKeyFromHex(hexKey) {
  const rawKey = hexToArrayBuffer(hexKey);
  return await crypto.subtle.importKey(
    "raw",
    rawKey,
    { name: "AES-GCM",length:256, },
    false, // not extractable
    ["encrypt","decrypt"]
  );
}

async function hexToKey(hex){
  const key = await importAESKeyFromHex(hex);
  return key;
}

function generateSalt(length = 16) {
  const salt = new Uint8Array(length);
  window.crypto.getRandomValues(salt);
  return btoa(String.fromCharCode(...salt)); // Base64-encoded
}
async function deriveKeyFromPassword(password,salt) {
    const encoder = new TextEncoder();

    //encode the password 
    const keyMaterial = await crypto.subtle.importKey(
        "raw",
        encoder.encode(password),
        {name:"PBKDF2"},
        false,
        ["deriveBits","deriveKey"]
    );

    // derive the key: 
    const derivedKey = await crypto.subtle.deriveKey(
        {
            name:"PBKDF2",
            salt : encoder.encode(salt),
            iterations: 10000,
            hash: "SHA-256",

        },
        keyMaterial,
        {
            name: "AES-GCM",
            length:256,
        },
        true,
        ["encrypt","decrypt"]
    );
    return derivedKey;
    
}

async function generateEncryptionKeyPair() {
    const encKeyPair = await window.crypto.subtle.generateKey(
      {
        name: "RSA-OAEP",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1,0,1]),
        hash: "SHA-256"
      },
      true,
      ["encrypt", "decrypt"]
    );
    return encKeyPair;
}

function getCookie(name) {
  const value = `; ${document.cookie}`;
  const parts = value.split(`; ${name}=`);
  if (parts.length === 2) {
    cookieVal = parts.pop().split(';').shift();
    //console.log("cookieVal->"+cookieVal);
    return cookieVal;
  }
  return null;

  }

function bufferToBase64(buffer) {
  return btoa(String.fromCharCode(...new Uint8Array(buffer)));
}
async function hashPassword(password) {
    const encoder = new TextEncoder();
    const data = encoder.encode(password);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    return hashHex;
}

  async function processUpdateMessage() {
    await allowProcessingOfData();
  }

function allowProcessingOfData(){
  return new Promise(resolve => setTimeout(resolve, 1500));
}
function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}
function base64ToArrayBuffer(base64) {
  const binaryString = atob(base64); 
  const len = binaryString.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes.buffer; 
}

async function exportPublicKey(key) {
    const exported = await window.crypto.subtle.exportKey('spki', key);
    return await arrayBufferToBase64(exported);
}

async function exportPrivateKeyRaw(key) {
  return await window.crypto.subtle.exportKey('pkcs8', key);
}

// Encrypt private key with derived AES key
async function encryptPrivateKey(privateKey, derivedKey) {
  // Export private key to PKCS8 (binary format)
  const pkcs8 = await exportPrivateKeyRaw(privateKey);

  // Generate a random IV for AES-GCM
  const iv = crypto.getRandomValues(new Uint8Array(12));

  // Encrypt the private key bytes
  const encrypted = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv,
    },
    derivedKey,
    pkcs8
  );

  return {
    encryptedPrivateKey: new Uint8Array(encrypted),
    iv,

  };
}
function base64ToUint8Array(base64) {
  const raw = atob(base64);
  const rawLength = raw.length;
  const array = new Uint8Array(rawLength);
  for (let i = 0; i < rawLength; i++) {
    array[i] = raw.charCodeAt(i);
  }
  return array;
}
function base64ToArrayBuffer(base64) {
  const binaryString = atob(base64); // decode base64 to binary string
  const len = binaryString.length;
  const bytes = new Uint8Array(len);

  for (let i = 0; i < len; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }

  return bytes.buffer; // returns an ArrayBuffer
}
async function decryptLoginPrivateKey(encryptedPrivateKey, derivedKey, iv) {
  console.log("in dec, iv: "+ iv);
  try {
    // Decrypt the PKCS8 private key bytes
   
    const decrypted = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: base64ToUint8Array(iv), // same IV used during encryption
      },
      derivedKey,
      base64ToUint8Array(encryptedPrivateKey)
    );

    // Import the decrypted private key back into CryptoKey format
    const privateKey = await crypto.subtle.importKey(
      "pkcs8",                  // format
      decrypted,                // decrypted ArrayBuffer
      {
        name: "RSASSA-PKCS1-v1_5",
        hash: "SHA-256",
      },
      true,                     // extractable
      ["sign"]                  // key usages
    );

    return privateKey;

  } catch (err) {
    //console.error("Decryption failed:", err);
    return null;
  }
}

async function decryptEncPrivateKey(encryptedPrivateKey, derivedKey, iv) {
  try {
    // Decrypt the PKCS8 private key bytes
      console.log("in dec, iv: "+ iv);
    const decrypted = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: base64ToUint8Array(iv), // same IV used during encryption
      },
      derivedKey,
      base64ToUint8Array(encryptedPrivateKey)
    );

    // Import the decrypted private key back into CryptoKey format
    const privateKey = await crypto.subtle.importKey(
      "pkcs8",                  // format
      decrypted,                // decrypted ArrayBuffer
      {
        name: "RSA-OAEP",
        hash: "SHA-256",
      },
      true,                     // extractable
      ["decrypt"]                  // key usages
    );
    console.log("successful decryption!");
    return privateKey;

  } catch (err) {
    console.log("unsuccessful decryption!");
    console.log(err);
    return null
   
  }
}


async function signData(data, privateKey) {
  // Convert string to Uint8Array
  const encoder = new TextEncoder();
  const encodedData = encoder.encode(data);

  // Sign 
  const signature = await window.crypto.subtle.sign(
    {
      name: "RSASSA-PKCS1-v1_5",
    },
    privateKey,         
    encodedData         
  );

  // Return b64 signature
  return btoa(String.fromCharCode(...new Uint8Array(signature)));
}

  async function encryptRawAESKeyWithPublicKey(publicKey, rawAESKey) {
    const encrypted = await crypto.subtle.encrypt(
      { name: 'RSA-OAEP' },
      publicKey,
      rawAESKey
    );
    return btoa(String.fromCharCode(...new Uint8Array(encrypted))); // base64 output
  }

  async function importAESKey(rawKeyBuffer) {
  return await crypto.subtle.importKey(
    "raw",                   // format of the input key
    rawKeyBuffer,            // raw key material (ArrayBuffer or Uint8Array)
    { name: "AES-GCM" },     // algorithm the key will be used for
    true,                    // whether the key is extractable
    ["encrypt", "decrypt"]   // allowed usages
  );
}
 async function hashFileToBase64(arrayBuffer) {
    
    const hashBuffer = await crypto.subtle.digest("SHA-256", arrayBuffer);
    return arrayBufferToBase64(hashBuffer);
  }
async function RSADecryptAESKey(privateKey, encryptedAESKey){ //pk is cryptoKeym encryptedAESKey is b64
    try {
    // Step 1: Convert Base64 to ArrayBuffer
    console.log(encryptedAESKey);
    const encryptedBuffer = base64ToArrayBuffer(encryptedAESKey);

    const decryptedKeyBuffer = await crypto.subtle.decrypt(
      {
        name: "RSA-OAEP"
      },
      privateKey,
      encryptedBuffer
    );

    //return as raw ArrayBuffer 
    console.log("dec key buffer: "+ decryptedKeyBuffer);
    return decryptedKeyBuffer;

  } catch (err) {
    console.error("RSA decryption failed:", err);
    return null; // BIG CHANGE HERE!
  }
}


async function generateSGK() {
  return await crypto.subtle.generateKey(
    { name: "AES-KW", length: 256 },
    true,
    ["wrapKey", "unwrapKey"]
  );
}



async function generateCEK() {
  return await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );
}

// Wrap CEK with SGK
async function wrapCEK(sgk, cek) {
  const wrappedKey = await crypto.subtle.wrapKey(
    "raw",      // format
    cek,        // key to wrap
    sgk,        // wrapping key (SGK)
    "AES-KW"    // wrapping algorithm
  );
  return wrappedKey;
}

// Unwrap CEK with SGK
async function unwrapCEK(wrappedKey, sgk) {
  return await crypto.subtle.unwrapKey(
    "raw",
    wrappedKey,
    sgk,
    "AES-KW",
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );
}
