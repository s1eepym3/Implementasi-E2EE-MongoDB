import jwt from "jsonwebtoken";
import User from "../models/User.js";
import dotenv from "dotenv";

dotenv.config();

const JWT_SECRET = process.env.JWT_SECRET || "fallback_secret";

export const register = async (req, res) => {
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
};

export const login = async (req, res) => {
  const { username, password } = req.body;
  try {
    const user = await User.findOne({ username });
    if (!user) return res.status(400).json({ message: "User tidak ditemukan" });

    const valid = await user.comparePassword(password);
    if (!valid) return res.status(400).json({ message: "Password salah" });

    const token = jwt.sign(
      { id: user._id, username, role: user.role },
      JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.json({
      message: "✅ Login sukses",
      token,
      role: user.role,
    });
  } catch (err) {
    res.status(500).json({ message: "Gagal login" });
  }
};

export const verify = (req, res) => {
  res.json({ username: req.user.username, role: req.user.role });
};
