import fs from "fs";

const chunks = JSON.parse(fs.readFileSync("secure_storage.files.chunks.json"));
const sorted = chunks.sort((a, b) => a.n - b.n);
const buffers = sorted.map(c => Buffer.from(c.data.$binary.base64, "base64"));
fs.writeFileSync("output.bin", Buffer.concat(buffers));

console.log("✅ File berhasil disusun ulang jadi output.bin");