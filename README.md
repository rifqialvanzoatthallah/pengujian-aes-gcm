# 🔐 Pengujian AES-GCM pada Data Transaksi Keuangan

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)
![cryptography](https://img.shields.io/badge/library-cryptography-0A7E8C)
![Tujuan](https://img.shields.io/badge/tujuan-riset%20akademik-6A5ACD)
![Data](https://img.shields.io/badge/data-sintetis-lightgrey)

Skrip pengujian untuk jurnal **"Analisis Kinerja Mode Operasi Block Cipher AES-GCM dalam Menjamin Kerahasiaan dan Integritas Data Transaksi Keuangan"**.

Skrip ini membandingkan **AES-GCM** dengan **AES-CBC** dan **AES-CBC + HMAC-SHA256** dari tiga sisi: **seberapa cepat**, **apakah data yang diubah terdeteksi**, dan **apa akibatnya bila nonce dipakai ulang**.

---

## ✨ Apa yang diuji

| Skema | Kunci | Autentikasi data | Tambahan ukuran per pesan |
|---|---|---|---|
| AES-128-GCM | 128-bit | Ya (tag 128-bit) | 28 byte |
| AES-256-GCM | 256-bit | Ya (tag 128-bit) | 28 byte |
| AES-256-CBC | 256-bit | **Tidak ada** | 32 byte |
| AES-256-CBC + HMAC-SHA256 | 256-bit + kunci HMAC terpisah | Ya (encrypt-then-MAC) | 64 byte |

Ada tiga pengujian:

1. **Kinerja.** Waktu enkripsi dan dekripsi (median) pada data berukuran 1 KB, 10 KB, 100 KB, 1 MB, dan 10 MB, beserta throughput dan overhead ukuran.
2. **Integritas.** Satu bit ciphertext diubah secara acak sebanyak 1.000 kali per skema, lalu dicek apakah perubahannya terdeteksi.
3. **Pemakaian ulang nonce pada GCM.** Dua pesan dienkripsi dengan kunci dan nonce yang sama, lalu diperiksa apakah hasil XOR ciphertext sama dengan XOR plaintext.

---

## 📊 Hasil ringkas (data 10 MB)

Hasil dari satu run di laptop penulis (lihat bagian Lingkungan pengujian).

| Skema | Enkripsi (ms) | Dekripsi (ms) | Throughput enkripsi (MB/s) | Overhead (byte) |
|---|---|---|---|---|
| AES-128-GCM | 7,7753 | 7,7195 | 1.286,1 | 28 |
| AES-256-GCM | **7,6227** | 7,7946 | **1.311,9** | 28 |
| AES-256-CBC | 16,7921 | 14,1466 | 595,5 | 32 |
| AES-256-CBC + HMAC | 25,2873 | 23,0068 | 395,5 | 64 |

**Deteksi perubahan data (1.000 percobaan per skema):**

| Skema | Terdeteksi | Data rusak diterima tanpa peringatan |
|---|---|---|
| AES-256-GCM | 1.000 | 0 |
| AES-256-CBC | 32 | **968** |
| AES-256-CBC + HMAC | 1.000 | 0 |

### 🔎 Temuan utama

- AES-256-GCM sekitar **2,2 kali** lebih cepat daripada AES-256-CBC dan **3,3 kali** lebih cepat daripada CBC + HMAC pada enkripsi 10 MB.
- AES-CBC tanpa autentikasi **tidak menjamin integritas**: hampir semua data yang diubah diterima begitu saja.
- Pada GCM, **nonce yang dipakai ulang membocorkan hubungan antar pesan** (XOR ciphertext sama dengan XOR plaintext).

> ⚠️ Angka waktu bergantung pada perangkat keras, pustaka, dan sistem operasi. Jalankan ulang di perangkatmu sendiri sebelum membandingkan.

---

## 🚀 Cara menjalankan

Kebutuhan: **Python 3.10 atau lebih baru**.

```bash
git clone https://github.com/rifqialvanzoatthallah/pengujian-aes-gcm.git
cd pengujian-aes-gcm
pip install cryptography
python pengujian_aes_gcm.py
```

Skrip mencetak versi Python dan pustaka, tabel kinerja, hasil uji integritas, dan hasil uji nonce di terminal. Semua hasil juga disimpan ke `hasil_pengujian.json`.

> 💡 `hasil_pengujian.json` **ditimpa setiap kali skrip dijalankan**. Salin dulu berkasnya bila ingin menyimpan hasil run sebelumnya.

Tips agar hasil lebih stabil: colokkan charger, pilih mode daya performa, dan tutup aplikasi lain sebelum menjalankan skrip.

---

## 📁 Isi repositori

```
pengujian-aes-gcm/
├── pengujian_aes_gcm.py    # skrip pengujian lengkap
├── hasil_pengujian.json    # hasil run yang dipakai di jurnal
└── README.md
```

---

## ⚙️ Cara kerja pengujian

- **Data uji:** transaksi **sintetis** berformat JSON per baris (ID transaksi, rekening asal, rekening tujuan, nominal, mata uang). Data dibuat dengan *seed* tetap (`2026`), sehingga isinya sama setiap kali skrip dijalankan. Tidak ada data nyata yang dipakai.
- **Kunci dan nonce:** kunci dibuat acak dengan `os.urandom` setiap run. Pada GCM, nonce 96-bit dibuat acak untuk setiap pesan dengan AAD berupa teks `hdr`. Pada CBC, IV 128-bit dibuat acak dengan padding PKCS#7.
- **Pengukuran waktu:** memakai `time.perf_counter()` dengan satu kali pemanasan, lalu diambil **median** dari beberapa pengulangan (300, 300, 100, 30, dan 10 kali untuk ukuran 1 KB sampai 10 MB).
- **Pemeriksaan:** setiap hasil dekripsi dibandingkan dengan data asli sebelum waktu diukur.
- **Uji integritas:** posisi bit yang diubah ditentukan oleh generator acak ber-*seed* tetap, sehingga hasilnya dapat diulang.

---

## 💻 Lingkungan pengujian

| Komponen | Nilai |
|---|---|
| Perangkat | Acer Nitro V 15 |
| Prosesor | Intel Core i5-13420H (generasi ke-13), mendukung AES-NI |
| Sistem operasi | Windows 11 Home 64-bit |
| Python | 3.10.11 |
| Pustaka | cryptography 50.0.2 |

---

## ⚠️ Catatan penting

- Skrip ini dibuat untuk **keperluan riset dan pembelajaran**, bukan untuk dipakai langsung di sistem produksi. Sistem nyata memerlukan manajemen kunci dan manajemen nonce yang tidak dicakup di sini.
- Pengukuran dilakukan di memori, tanpa jaringan atau penyimpanan, pada satu perangkat. Hasilnya tidak dapat digeneralisasi ke perangkat lain.
- Uji pemakaian ulang nonce hanya menunjukkan kebocoran XOR plaintext. Dampak terhadap kunci autentikasi tidak diuji.

---

## 📖 Sitasi

Jika kamu memakai skrip ini, sebutkan jurnal terkait:

> Atthallah, R. A., dkk. (2026). *Analisis kinerja mode operasi block cipher AES-GCM dalam menjamin kerahasiaan dan integritas data transaksi keuangan*. [Nama jurnal, volume, halaman]

---

## 👥 Penulis

Rifqi Alvanzo Atthallah, Dio Tri Firnanda, Muhammad Partua Langka Situmeang, Arif Maulana, Afra Dhiya Lisara, dan Muhammad Ramadhana Aryandi
Universitas Malikussaleh, Indonesia
