# PrivateCloud E2EE - Secure Storage System 🛡️

**PrivateCloud** adalah aplikasi penyimpanan data berbasis web yang mengutamakan privasi tingkat tinggi menggunakan metode **End-to-End Encryption (E2EE)**. Proyek ini dibangun untuk mendemonstrasikan bagaimana data dapat disimpan dengan aman di MongoDB tanpa membiarkan server memiliki akses ke isi file asli.

## ✨ Fitur Utama
- **True End-to-End Encryption**: Proses enkripsi dan dekripsi dilakukan sepenuhnya di sisi klien (browser) menggunakan **Web Crypto API (AES-GCM)**. Server hanya menerima dan menyimpan data yang sudah terenkripsi.
- **GridFS Integration**: Menggunakan MongoDB GridFS untuk menangani penyimpanan file berukuran besar secara efisien.
- **Modern Glassmorphism UI**: Antarmuka pengguna yang mewah, responsif, dan interaktif dengan dukungan **Dark/Light Mode**.
- **Drag & Drop Upload**: Pengalaman unggah file yang mudah dan cepat.
- **Admin & User Panel**: Pemisahan hak akses antara pengguna biasa dan administrator untuk pengelolaan file.
- **Real-time Search & File Sorting**: Pencarian file secara instan dan deteksi tipe file otomatis (Gambar, Video, Musik, Dokumen).
- **Security First**: Kunci enkripsi dikelola secara unik untuk setiap file dan disimpan dalam metadata terenkripsi.

## 🛠️ Tech Stack
- **Backend**: Node.js, Express.js
- **Database**: MongoDB (Atlas) & GridFS
- **Security**: Web Crypto API (AES-GCM 256-bit), JWT (JSON Web Token), Bcrypt
- **Frontend**: Vanilla JS, Bootstrap 5, Lucide Icons, CSS Custom (Glassmorphism)

## 🚀 Cara Instalasi

1. **Clone Repository**
   ```bash
   git clone https://github.com/s1eepym3/Implementasi-E2EE-MongoDB.git
   cd Implementasi-E2EE-MongoDB
   ```

2. **Instal Dependensi**
   ```bash
   npm install
   ```

3. **Konfigurasi Environment Variable**
   Buat file `.env` di root direktori dan masukkan kredensial berikut:
   ```env
   PORT=3000
   MONGODB_URI=mongodb+srv://your_connection_string
   JWT_SECRET=your_super_secret_key
   ```

4. **Jalankan Aplikasi**
   ```bash
   node server.js
   ```
   Akses aplikasi di `http://localhost:3000`.

## 🔒 Alur Keamanan (E2EE)
1. **Encryption**: Saat user memilih file, browser membangkitkan kunci simetris AES-GCM 256-bit secara lokal. File dienkripsi di dalam browser sebelum dikirim ke server.
2. **Storage**: Server menerima file yang sudah berupa *ciphertext* (data acak) dan menyimpannya ke MongoDB GridFS.
3. **Decryption**: Saat download, browser mengambil data terenkripsi dari server, mengambil kunci dari metadata, dan melakukan dekripsi di memori browser sebelum file disimpan ke perangkat user.

## 📄 Lisensi
Proyek ini dibuat untuk tujuan edukasi dan pengembangan keamanan data.
