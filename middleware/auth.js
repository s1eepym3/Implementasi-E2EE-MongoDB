import jwt from "jsonwebtoken";
import dotenv from "dotenv";

dotenv.config();

const JWT_SECRET = process.env.JWT_SECRET || "fallback_secret";

export const auth = (req, res, next) => {
  // Ambil token dari Header ATAU dari Query Parameter (untuk download)
  let token = req.headers.authorization?.split(" ")[1] || req.query.token;
  
  if (!token) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(403).json({ message: "Token tidak valid atau kedaluwarsa" });
  }
};
