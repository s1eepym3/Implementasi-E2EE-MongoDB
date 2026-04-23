import express from "express";
import multer from "multer";
import { auth } from "../middleware/auth.js";
import {
  uploadFile,
  downloadFile,
  listFiles,
  deleteFile,
  getStorageInfo
} from "../controllers/fileController.js";

const router = express.Router();
const upload = multer({ dest: "uploads/" });

router.post("/upload", auth, upload.single("file"), uploadFile);
router.get("/download/:id", auth, downloadFile); 
router.get("/files", auth, listFiles);
router.delete("/delete/:id", auth, deleteFile);
router.get("/storage", auth, getStorageInfo);

// Admin routes
router.get("/admin/files", auth, listFiles); // Reuse listFiles with proper logic if needed
router.delete("/admin/delete/:id", auth, deleteFile);

export default router;
