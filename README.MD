# **YouTube Comment Manager**

## **Deskripsi**
YouTube Comment Manager adalah aplikasi GUI berbasis **PyQt6** yang digunakan untuk menyaring dan menghapus komentar di YouTube secara otomatis. Aplikasi ini menggunakan **YouTube API** dan memerlukan autentikasi OAuth 2.0.

Aplikasi ini dikhususkan untuk menghapus komentar yang meresahkan seperti **judi online, komentar inapropriate, spam, serta komentar yang mengandung karakter tidak wajar**. Dengan ini, pemilik channel dapat menjaga kolom komentar tetap bersih dan nyaman untuk komunitasnya.

🚀 Sekarang sudah terintegrasi dengan AI Gemini Flash 2.0 untuk menyaring komentar secara lebih cerdas dan fleksibel sesuai kebutuhan!
---

## **Fitur**
✅ Mengambil komentar dari video YouTube secara otomatis  
✅ Menyaring komentar berdasarkan karakter khusus  
✅ Menghapus atau menyembunyikan komentar yang tidak sesuai  
✅ Menampilkan daftar pengguna yang diblokir  
✅ Menggunakan autentikasi **OAuth 2.0** untuk keamanan  
✅ Bisa diubah menjadi aplikasi **.exe** untuk Windows  
✅ **Integrasi dengan AI Gemini Flash 2.0 untuk filtering lebih cerdas**  
✅ **Dapat memasukkan API Key Gemini langsung dari GUI**  

---

## **Metode Filtering**
Aplikasi ini sekarang mendukung dua metode filtering:
1. **Filtering Karakter Standar**: Hanya mengizinkan komentar yang menggunakan karakter dari keyboard standar.
2. **Filtering Berbasis AI (Gemini Flash 2.0)**: Menggunakan model AI untuk menganalisis dan memfilter komentar berdasarkan prompt yang bisa disesuaikan.

Dengan metode AI, pengguna dapat mengatur sendiri kriteria komentar yang akan difilter, misalnya:
- "Hapus semua komentar yang mengandung kata-kata promosi judi online."
- "Tolak komentar yang bersifat ofensif atau mengandung ujaran kebencian."
- "Hanya izinkan komentar yang relevan dengan isi video."

---

## **1. Instalasi**
### **1.1. Persyaratan Sistem**
- **Python 3.7+**
- **Google API Client Libraries**
- **PyQt6** untuk antarmuka pengguna

### **1.2. Membuat Virtual Environment**
1. **Buka Terminal atau Command Prompt**  
2. **Jalankan perintah berikut untuk membuat Virtual Environment:**
   ```sh
   python -m venv venv
   ```
3. **Aktifkan Virtual Environment**  
   - **Windows**:
     ```sh
     venv\Scripts\activate
     ```
   - **Mac/Linux**:
     ```sh
     source venv/bin/activate
     ```

4. **Instalasi Dependensi**
   ```sh
   pip install -r requirements.txt
   ```

---

## **2. Menyiapkan OAuth 2.0 untuk YouTube API**
### **2.1. Mengaktifkan YouTube API**
1. **Buka Google Cloud Console** di [Google Developer Console](https://console.cloud.google.com/).
2. Pilih proyek yang ingin digunakan atau buat proyek baru.
3. Masuk ke **API & Services > Library**.
4. Cari **YouTube Data API v3**, lalu klik **Enable** untuk mengaktifkan API tersebut.

### **2.2. Membuat OAuth Credentials**
1. **Buka** menu **API & Services > Credentials**.
2. Klik **Create Credentials** → **OAuth Client ID**.
3. Jika muncul peringatan **"Configure Consent Screen"**, klik **Configure Consent Screen** dan isi informasi yang diperlukan.
4. Kembali ke **API & Services > Credentials**, lalu buat **OAuth Client ID** dengan **Application Type: Desktop App**.
5. Klik **Create**, lalu unduh file `client_secret_XXXXX.json` dan simpan di direktori proyek.

### **2.3. Menambahkan Pengguna untuk Pengujian OAuth**
1. Buka **Google Cloud Console > API & Services > OAuth Consent Screen**.
2. Scroll ke bawah ke bagian **Test Users**.
3. Klik **Add Users**, lalu masukkan email akun Google yang akan digunakan untuk login.
4. Klik **Save**.

### **2.4. Batasan API YouTube**
Perlu diperhatikan bahwa **YouTube API memiliki batas kuota harian**, sehingga jumlah permintaan untuk mengambil dan menghapus komentar tidak bisa dilakukan tanpa batas. Jika aplikasi ini digunakan secara intensif, kemungkinan besar akan terkena batas kuota dan harus menunggu hingga kuota diperbarui oleh Google.

Untuk melihat penggunaan kuota API:
1. Buka **Google Cloud Console**.
2. Masuk ke **API & Services > Dashboard**.
3. Pilih proyek yang digunakan.
4. Cek jumlah pemakaian kuota pada **YouTube Data API v3**.

Jika aplikasi membutuhkan lebih banyak kuota, Anda bisa **mengajukan permintaan peningkatan kuota ke Google** melalui Google Cloud Console.

---

## **3. Menjalankan Aplikasi**
1. **Pastikan Virtual Environment sudah aktif**.
2. Jalankan perintah berikut:
   ```sh
   python app.py
   ```
3. Saat pertama kali dijalankan, aplikasi akan membuka browser untuk login ke akun Google yang telah didaftarkan di daftar penguji.
4. Setelah login, token akan disimpan agar tidak perlu login ulang.

---

## **4. Membuat File .EXE**
Jika ingin menjalankan aplikasi tanpa Python, gunakan **PyInstaller** untuk membuat file `.exe`.

### **4.1. Instal PyInstaller**
```sh
pip install pyinstaller
```

### **4.2. Compile menjadi EXE**
```sh
pyinstaller --onefile --windowed --name "YouTubeCommentManager" app.py
```
Setelah proses selesai, file `.exe` akan tersedia di folder `dist/`.

---
## **5. Menyiapkan API Key Gemini Flash 2.0**

Untuk menggunakan fitur filtering AI, Anda perlu mendapatkan API Key dari **Google AI Studio**.

### **5.1. Cara Mendapatkan API Key**
1. **Buka Google AI Studio**: [https://aistudio.google.com/](https://aistudio.google.com/)
2. Login dengan akun Google Anda.
3. Pilih **API & Keys** di menu navigasi.
4. Klik **Generate API Key**, lalu salin API Key tersebut.
5. Masukkan API Key melalui GUI aplikasi pada kolom "Gemini API Key".

### **5.2. Batasan Kuota API Gemini**
Perlu diperhatikan bahwa **API Gemini Flash 2.0 memiliki batas kuota harian**, sehingga jumlah permintaan ke AI untuk menganalisis komentar tidak bisa dilakukan tanpa batas. Jika kuota habis, pengguna harus menunggu hingga kuota diperbarui oleh Google.

Untuk melihat penggunaan kuota API:
1. Buka **Google AI Studio**.
2. Masuk ke **API & Keys**.
3. Cek jumlah pemakaian kuota API yang tersisa.

---

## **6. Konfigurasi Prompt AI untuk Filtering**
Prompt AI dapat disesuaikan sesuai kebutuhan filtering komentar. Contoh prompt yang bisa digunakan:
- "Blokir semua komentar yang mengandung kata-kata kasar atau spam."
- "Hapus komentar yang mempromosikan produk atau layanan."
- "Filter komentar yang tidak relevan dengan video."

Untuk mengatur prompt ini, pengguna dapat menyesuaikan sesuai dengan kebutuhan mereka.

---
## **7. Disclaimer**
Aplikasi ini masih dalam tahap pengembangan dan mungkin masih memiliki beberapa bug. **Penggunaan aplikasi ini sepenuhnya menjadi tanggung jawab pengguna. Pengembang tidak bertanggung jawab atas segala kerusakan atau masalah yang terjadi akibat penggunaan aplikasi ini. Penggunaan AI dalam aplikasi ini tidak 100% akurat, pengguna juga bertanggung jawab atas hasil filtering, serta perlu memperhatikan batas kuota API Gemini Flash 2.0 dan YouTube API.**

---

## **8. Kontribusi**
Kami sangat menyambut kontribusi dari komunitas! Jika Anda ingin berpartisipasi dalam pengembangan dan perbaikan aplikasi ini, silakan buat **pull request** atau ajukan **issue** di repository ini. Setiap masukan dan kontribusi sangat kami hargai.

---

## **9. Lisensi**
Proyek ini dilisensikan di bawah **MIT License**. Silakan baca [LICENSE](LICENSE) untuk informasi lebih lanjut.

---

## **10. Donasi**
Jika Anda merasa proyek ini bermanfaat dan ingin mendukung pengembangannya, Anda bisa memberikan donasi melalui:

[![Saweria](https://img.shields.io/badge/Donate-Saweria-orange)](https://saweria.co/dodotnanda)

---

## **11. Author**
👨‍💻 **Dodot Nanda Trihanggoro**  
📧 Email: [dodotnanda@gmail.com](mailto:dodotnanda@gmail.com)  
🔗 LinkedIn: [Dodot Nanda](https://www.linkedin.com/in/dodotnanda/)

---

🚀 **Dengan README ini, Anda dapat menginstal, menjalankan, dan mengembangkan aplikasi dengan lebih mudah!** 🚀

