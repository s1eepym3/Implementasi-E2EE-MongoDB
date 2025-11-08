import express from "express";
import mongoose from "mongoose";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import multer from "multer";
import crypto from "crypto";
import fs from "fs";
import path from "path";
import cors from "cors";
import { fileURLToPath } from "url";
import { GridFSBucket, ObjectId } from "mongodb";
import User from "./models/User.js";

const app = express();
const upload = multer({ dest: "uploads/" });
const JWT_SECRET = "secret_key_rahasia"; // ganti .env di produksi

// === KONEKSI MONGODB ===
const uri =
  "mongodb+srv://mohdhaykhal67_db_user:XimQCHzLiibrHPBf@cluster0.6f0lwfx.mongodb.net/secure_storage?retryWrites=true&w=majority";

const conn = mongoose.connection;
let gfs;

async function connectMongo() {
  try {
    await mongoose.connect(uri);
    console.log("✅ Connected to MongoDB Atlas");
    gfs = new GridFSBucket(conn.db, { bucketName: "files" });
    console.log("📦 GridFS bucket initialized");
  } catch (err) {
    console.error("❌ Gagal koneksi MongoDB:", err.message);
  }
}
await connectMongo();

// === MIDDLEWARE DASAR ===
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
app.use(cors({
  origin: [
    "https://accused-margret-s1eepym3-afed2c18.koyeb.app",
    "http://localhost:3000"
  ],
  credentials: true,
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));

// === JWT AUTH ===
function auth(req, res, next) {
  let token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ message: "Unauthorized" });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(403).json({ message: "Token tidak valid atau kedaluwarsa" });
  }
}

// === VERIFY TOKEN ===
app.get("/verify", auth, (req, res) => {
  res.json({ username: req.user.username, role: req.user.role });
});


// === REGISTER ===
app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ message: "Isi username & password" });

  try {
    const existing = await User.findOne({ username });
    if (existing)
      return res.status(400).json({ message: "Username sudah digunakan" });

    const user = new User({ username, password });
    await user.save();
    res.json({ message: "✅ Registrasi berhasil!" });
  } catch (err) {
    res.status(500).json({ message: "Terjadi kesalahan server" });
  }
});

// === LOGIN ===
app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });
  if (!user) return res.status(400).json({ message: "User tidak ditemukan" });

  const valid = await user.comparePassword(password);
  if (!valid) return res.status(400).json({ message: "Password salah" });

  // ✨ tambahkan role ke token
  const token = jwt.sign(
    { id: user._id, username, role: user.role },
    JWT_SECRET,
    { expiresIn: "1h" }
  );

  res.json({
    message: "✅ Login sukses",
    token,
    role: user.role, // dikirim ke frontend
  });
});


// === UPLOAD (terenkripsi) ===
app.post("/upload", auth, upload.single("file"), (req, res) => {
  if (!req.file) return res.status(400).send("Tidak ada file diunggah.");
  if (!gfs) return res.status(503).send("GridFS belum siap.");

  const key = crypto.randomBytes(32);
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
  const input = fs.createReadStream(req.file.path);

  const uploadStream = gfs.openUploadStream(req.file.originalname, {
    metadata: {
      user: req.user.username,
      iv: iv.toString("hex"),
      key: key.toString("hex"),
    },
  });

  input
    .pipe(cipher)
    .pipe(uploadStream)
    .on("finish", () => {
      fs.unlinkSync(req.file.path);
      console.log("✅ Upload sukses:", uploadStream.id.toString());
      res.json({
        message: "✅ File terenkripsi & tersimpan!",
        fileId: uploadStream.id,
      });
    })
    .on("error", (err) => {
      res.status(500).send("Gagal menyimpan file: " + err.message);
    });
});

// === DOWNLOAD (dekripsi otomatis) ===
app.get("/download/:id", async (req, res) => {
  const token = req.query.token || req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ message: "Unauthorized" });

  try {
    const user = jwt.verify(token, JWT_SECRET);
    const fileId = new ObjectId(req.params.id);
    const file = await conn.db.collection("files.files").findOne({ _id: fileId });
    if (!file) return res.status(404).send("File tidak ditemukan.");

    // ✅ Izinkan admin download semua file
    if (file.metadata?.user && file.metadata.user !== user.username && user.role !== "admin") {
      return res.status(403).send("Akses ditolak: bukan file Anda.");
    }

    console.log(`📥 ${user.username} mendownload file ${file.filename}`);

    const key = Buffer.from(file.metadata.key, "hex");
    const iv = Buffer.from(file.metadata.iv, "hex");
    const decipher = crypto.createDecipheriv("aes-256-cbc", key, iv);
    const downloadStream = gfs.openDownloadStream(fileId);

    res.set({
      "Content-Type": "application/octet-stream",
      "Content-Disposition": `attachment; filename="${file.filename}"`,
    });

    downloadStream.pipe(decipher).pipe(res);
  } catch (err) {
    console.error("❌ Error di /download:", err.message);
    res.status(400).send("Token atau file ID tidak valid.");
  }
});

// === LIST FILES (scope=user / all) ===
app.get("/files", auth, async (req, res) => {
  try {
    const scope = req.query.scope;
    let query = {};

    // Jika user memilih "user", tampilkan hanya file miliknya
    if (scope === "user") {
      query = { "metadata.user": req.user.username };
    }
    // Jika memilih "all", tampilkan semua file (tapi filter akses download di frontend)
    else if (scope === "all") {
      query = {}; // tampilkan semua file
    }

    const files = await conn.db.collection("files.files")
      .find(query)
      .sort({ uploadDate: -1 })
      .toArray();

    res.json(files);
  } catch (err) {
    console.error("❌ Gagal memuat daftar file:", err.message);
    res.status(500).send("Gagal memuat daftar file.");
  }
});

// === DELETE ===
app.delete("/delete/:id", auth, async (req, res) => {
  try {
    const fileId = new ObjectId(req.params.id);
    const file = await conn.db.collection("files.files").findOne({ _id: fileId });
    if (!file) return res.status(404).send("File tidak ditemukan.");

    if (file.metadata?.user !== req.user.username)
      return res.status(403).send("Tidak diizinkan menghapus file ini.");

await gfs.delete(fileId);
console.log(`🗑️ File dihapus: ${fileId.toString()} oleh ${req.user.username}`);
res.json({ message: "✅ File berhasil dihapus." });
  } catch (err) {
    console.error("❌ Gagal menghapus file:", err.message);
    res.status(500).send("Gagal menghapus file: " + err.message);
  }
});

// === ADMIN: GET SEMUA FILE ===
app.get("/admin/files", auth, async (req, res) => {
  try {
    if (req.user.role !== "admin")
      return res.status(403).json({ message: "Hanya admin yang boleh." });

    const files = await conn.db.collection("files.files").find({}).toArray();
    res.json(files);
  } catch (err) {
    res.status(500).send("Gagal memuat file admin: " + err.message);
  }
});

// === ADMIN: DELETE FILE APA SAJA ===
app.delete("/admin/delete/:id", auth, async (req, res) => {
  try {
    if (req.user.role !== "admin")
      return res.status(403).json({ message: "Hanya admin yang boleh." });

    const fileId = new ObjectId(req.params.id);
    const file = await conn.db.collection("files.files").findOne({ _id: fileId });
    if (!file) return res.status(404).send("File tidak ditemukan.");

    await gfs.delete(fileId);
    console.log(`🗑️ Admin (${req.user.username}) menghapus file: ${file.filename}`);
    res.json({ message: `✅ File '${file.filename}' berhasil dihapus oleh admin.` });
  } catch (err) {
    console.error("❌ Gagal hapus file admin:", err.message);
    res.status(500).send("Gagal hapus file admin: " + err.message);
  }
});

// === STORAGE INFO ===
app.get("/storage", auth, async (req, res) => {
  try {
    const stats = await conn.db.stats();
    const dataSizeMB = (stats.dataSize / (1024 * 1024)).toFixed(2);
    const fileCount = await conn.db
      .collection("files.files")
      .countDocuments({ "metadata.user": req.user.username });
    const maxCapacityMB = 512;
    const usedMB = parseFloat(dataSizeMB);
    const remainingMB = (maxCapacityMB - usedMB).toFixed(2);

    res.json({
      files: fileCount,
      usedMB,
      maxCapacityMB,
      remainingMB,
      message: `📦 ${fileCount} file tersimpan — digunakan ${usedMB} MB dari ${maxCapacityMB} MB (tersisa ${remainingMB} MB)`,
    });
  } catch {
    res.status(500).send("Gagal mengambil info storage");
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
