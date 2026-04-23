import mongoose from "mongoose";
import { GridFSBucket } from "mongodb";
import dotenv from "dotenv";

dotenv.config();

const uri = process.env.MONGODB_URI;

let gfs;

const connectDB = async () => {
  try {
    await mongoose.connect(uri);
    console.log("✅ Connected to MongoDB Atlas");
    
    const conn = mongoose.connection;
    gfs = new GridFSBucket(conn.db, { bucketName: "files" });
    console.log("📦 GridFS bucket initialized");
    
    return conn;
  } catch (err) {
    console.error("❌ Gagal koneksi MongoDB:", err.message);
    process.exit(1);
  }
};

export const getGFS = () => gfs;
export default connectDB;
