import crypto from "crypto";
import fs from "fs";
import { ObjectId } from "mongodb";
import mongoose from "mongoose";
import { getGFS } from "../config/db.js";

export const uploadFile = (req, res) => {
  if (!req.file) return res.status(400).send("Tidak ada file diunggah.");
  const gfs = getGFS();
  if (!gfs) return res.status(503).send("GridFS belum siap.");

  // Metadata dikirim dari frontend via FormData
  const { iv, key } = req.body;
  
  console.log("-----------------------------------------");
  console.log(`📂 MENERIMA UPLOAD: ${req.file.originalname}`);
  console.log(`🔑 IV: ${iv ? "DITERIMA (" + iv.length + " chars)" : "TIDAK ADA"}`);
  console.log(`🔐 KEY: ${key ? "DITERIMA (" + key.length + " chars)" : "TIDAK ADA"}`);
  console.log("-----------------------------------------");

  if (!iv || !key) {
      console.error("❌ ERROR: Metadata (IV/Key) tidak terdeteksi oleh Multer!");
  }

  const input = fs.createReadStream(req.file.path);
  const uploadStream = gfs.openUploadStream(req.file.originalname, {
    metadata: {
      user: req.user.username,
      iv: iv,
      key: key,
    },
  });

  input
    .pipe(uploadStream)
    .on("finish", () => {
      fs.unlinkSync(req.file.path);
      console.log(`✅ BERHASIL: File ${req.file.originalname} disimpan dengan ID ${uploadStream.id}`);
      res.json({
        message: "✅ File terenkripsi & tersimpan!",
        fileId: uploadStream.id,
      });
    })
    .on("error", (err) => {
      console.error("❌ ERROR SAAT PIPING:", err.message);
      res.status(500).send("Gagal menyimpan file: " + err.message);
    });
};

export const downloadFile = async (req, res) => {
  try {
    const gfs = getGFS();
    const fileId = new ObjectId(req.params.id);
    const file = await mongoose.connection.db.collection("files.files").findOne({ _id: fileId });
    
    if (!file) return res.status(404).send("File tidak ditemukan.");

    console.log(`📥 REQUEST DOWNLOAD: ${file.filename} (${fileId})`);
    console.log(`🔑 METADATA DI DB: IV=${file.metadata?.iv ? 'OK' : 'MISSING'}, KEY=${file.metadata?.key ? 'OK' : 'MISSING'}`);

    // Cek kepemilikan
    if (file.metadata?.user && file.metadata.user !== req.user.username && req.user.username !== 'admin') {
       return res.status(403).send("Akses ditolak.");
    }

    const downloadStream = gfs.openDownloadStream(fileId);

    res.set({
      "Content-Type": "application/octet-stream",
      "Content-Disposition": `attachment; filename="${file.filename}"`,
    });

    downloadStream.pipe(res);
  } catch (err) {
    console.error("❌ ERROR DOWNLOAD:", err.message);
    res.status(400).send("File ID tidak valid.");
  }
};

export const listFiles = async (req, res) => {
  try {
    const scope = req.query.scope;
    let query = {};

    if (scope === "user" || (scope === "all" && req.user.username !== "admin")) {
      query = { "metadata.user": req.user.username };
    } 
    else if (req.user.username === "admin") {
      query = {}; 
    }

    const files = await mongoose.connection.db.collection("files.files")
      .find(query)
      .sort({ uploadDate: -1 })
      .toArray();

    res.json(files);
  } catch (err) {
    res.status(500).send("Gagal memuat daftar file.");
  }
};

export const deleteFile = async (req, res) => {
  try {
    const gfs = getGFS();
    const fileId = new ObjectId(req.params.id);
    const file = await mongoose.connection.db.collection("files.files").findOne({ _id: fileId });
    
    if (!file) return res.status(404).send("File tidak ditemukan.");

    if (file.metadata?.user !== req.user.username && req.user.username !== 'admin')
      return res.status(403).send("Tidak diizinkan menghapus file ini.");

    await gfs.delete(fileId);
    console.log(`🗑️ FILE DIHAPUS: ${fileId}`);
    res.json({ message: "✅ File berhasil dihapus." });
  } catch (err) {
    res.status(500).send("Gagal menghapus file: " + err.message);
  }
};

export const getStorageInfo = async (req, res) => {
  try {
    const stats = await mongoose.connection.db.stats();
    const dataSizeMB = (stats.dataSize / (1024 * 1024)).toFixed(2);
    const fileCount = await mongoose.connection.db
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
};
