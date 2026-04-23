/**
 * Crypto Helper for Client-Side E2EE
 * Menggunakan Web Crypto API (AES-GCM)
 */

// Generate random key untuk AES-256
async function generateEncryptionKey() {
  return await window.crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );
}

// Export key ke format yang bisa disimpan (Hex)
async function exportKey(key) {
  const exported = await window.crypto.subtle.exportKey("raw", key);
  return bufToHex(exported);
}

// Import key dari format Hex
async function importKey(hexKey) {
  const buf = hexToBuf(hexKey);
  return await window.crypto.subtle.importKey(
    "raw",
    buf,
    "AES-GCM",
    true,
    ["encrypt", "decrypt"]
  );
}

// Fungsi Enkripsi File
async function encryptFile(file, key) {
  const iv = window.crypto.getRandomValues(new Uint8Array(12)); // IV untuk AES-GCM (12 bytes)
  const fileData = await file.arrayBuffer();

  const encryptedContent = await window.crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv },
    key,
    fileData
  );

  return {
    encryptedContent,
    iv: bufToHex(iv)
  };
}

// Fungsi Dekripsi File
async function decryptFile(encryptedContent, hexKey, hexIv) {
  const key = await importKey(hexKey);
  const iv = hexToBuf(hexIv);

  const decryptedContent = await window.crypto.subtle.decrypt(
    { name: "AES-GCM", iv: iv },
    key,
    encryptedContent
  );

  return decryptedContent;
}

// Utility: Buffer to Hex
function bufToHex(buffer) {
  return Array.from(new Uint8Array(buffer))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

// Utility: Hex to Buffer
function hexToBuf(hex) {
  const view = new Uint8Array(hex.length / 2);
  for (let i = 0; i < view.length; i++) {
    view[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return view.buffer;
}
