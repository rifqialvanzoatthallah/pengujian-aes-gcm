"""
Pengujian kecil: AES-GCM vs AES-CBC vs AES-CBC + HMAC-SHA256
Untuk jurnal: Analisis Kinerja Mode Operasi Block Cipher AES-GCM dalam
Menjamin Kerahasiaan dan Integritas Data Transaksi Keuangan

Cara pakai:
    pip install cryptography
    python pengujian_aes_gcm.py
"""
import hashlib
import hmac
import json
import os
import platform
import random
import statistics
import time

import cryptography
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SEED = 2026
UKURAN = {"1 KB": 1024, "10 KB": 10 * 1024, "100 KB": 100 * 1024,
          "1 MB": 1024 * 1024, "10 MB": 10 * 1024 * 1024}
ULANG = {"1 KB": 300, "10 KB": 300, "100 KB": 100, "1 MB": 30, "10 MB": 10}


def buat_data_transaksi(n_byte: int) -> bytes:
    """Data transaksi sintetis (JSON) dengan ukuran kira-kira n_byte."""
    rnd = random.Random(SEED)
    baris, total = [], 0
    while total < n_byte:
        trx = {
            "id": "TRX%010d" % rnd.randrange(10 ** 10),
            "rek_asal": "%012d" % rnd.randrange(10 ** 12),
            "rek_tujuan": "%012d" % rnd.randrange(10 ** 12),
            "nominal": rnd.randrange(10_000, 50_000_000),
            "mata_uang": "IDR",
        }
        s = json.dumps(trx)
        baris.append(s)
        total += len(s) + 1
    return "\n".join(baris).encode()[:n_byte]


# ---------- AES-GCM ----------
def gcm_enc(key, data):
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, data, b"hdr")


def gcm_dec(key, blob):
    return AESGCM(key).decrypt(blob[:12], blob[12:], b"hdr")


# ---------- AES-CBC (tanpa autentikasi) ----------
def cbc_enc(key, data):
    iv = os.urandom(16)
    p = padding.PKCS7(128).padder()
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return iv + enc.update(p.update(data) + p.finalize()) + enc.finalize()


def cbc_dec(key, blob):
    dec = Cipher(algorithms.AES(key), modes.CBC(blob[:16])).decryptor()
    u = padding.PKCS7(128).unpadder()
    return u.update(dec.update(blob[16:]) + dec.finalize()) + u.finalize()


# ---------- AES-CBC + HMAC-SHA256 (encrypt-then-MAC) ----------
def cbcmac_enc(keys, data):
    k_enc, k_mac = keys
    blob = cbc_enc(k_enc, data)
    return blob + hmac.new(k_mac, blob, hashlib.sha256).digest()


def cbcmac_dec(keys, blob):
    k_enc, k_mac = keys
    isi, tag = blob[:-32], blob[-32:]
    if not hmac.compare_digest(tag, hmac.new(k_mac, isi, hashlib.sha256).digest()):
        raise ValueError("MAC tidak cocok")
    return cbc_dec(k_enc, isi)


K128, K256, KMAC = os.urandom(16), os.urandom(32), os.urandom(32)
SKEMA = {
    "AES-128-GCM": (K128, gcm_enc, gcm_dec),
    "AES-256-GCM": (K256, gcm_enc, gcm_dec),
    "AES-256-CBC": (K256, cbc_enc, cbc_dec),
    "AES-256-CBC+HMAC": ((K256, KMAC), cbcmac_enc, cbcmac_dec),
}


def ukur(fn, *args, ulang):
    fn(*args)  # pemanasan
    waktu = []
    for _ in range(ulang):
        t = time.perf_counter()
        fn(*args)
        waktu.append((time.perf_counter() - t) * 1000)
    return statistics.median(waktu)


def uji_kinerja():
    hasil = []
    for label, n in UKURAN.items():
        data = buat_data_transaksi(n)
        for nama, (kunci, enc, dec) in SKEMA.items():
            blob = enc(kunci, data)
            assert dec(kunci, blob) == data, "dekripsi gagal"
            t_enc = ukur(enc, kunci, data, ulang=ULANG[label])
            t_dec = ukur(dec, kunci, blob, ulang=ULANG[label])
            mb = n / (1024 * 1024)
            hasil.append({
                "ukuran": label, "skema": nama,
                "enkripsi_ms": round(t_enc, 4), "dekripsi_ms": round(t_dec, 4),
                "enkripsi_MBps": round(mb / (t_enc / 1000), 1),
                "dekripsi_MBps": round(mb / (t_dec / 1000), 1),
                "overhead_byte": len(blob) - n,
            })
    return hasil


def uji_integritas(percobaan=1000):
    """Ubah 1 bit pada ciphertext lalu cek apakah perubahan terdeteksi."""
    data = buat_data_transaksi(1024)
    rnd = random.Random(SEED)
    out = {}
    for nama, (kunci, enc, dec) in SKEMA.items():
        if nama == "AES-128-GCM":
            continue
        terdeteksi = lolos_diam = 0
        for _ in range(percobaan):
            blob = bytearray(enc(kunci, data))
            i = rnd.randrange(len(blob))
            blob[i] ^= 1 << rnd.randrange(8)
            try:
                hasil = dec(kunci, bytes(blob))
                if hasil != data:
                    lolos_diam += 1  # data rusak tapi diterima tanpa peringatan
                else:
                    terdeteksi += 0
            except (InvalidTag, ValueError):
                terdeteksi += 1
        out[nama] = {"percobaan": percobaan, "terdeteksi": terdeteksi,
                     "data_rusak_diterima": lolos_diam}
    return out


def uji_nonce_ulang():
    """Pemakaian ulang nonce pada GCM membocorkan XOR dua plaintext."""
    key, nonce = os.urandom(32), os.urandom(12)
    p1 = b"TRANSFER 5000000 KE 111122223333"
    p2 = b"TRANSFER 9000000 KE 444455556666"
    c1 = AESGCM(key).encrypt(nonce, p1, None)[:-16]
    c2 = AESGCM(key).encrypt(nonce, p2, None)[:-16]
    xor_c = bytes(a ^ b for a, b in zip(c1, c2))
    xor_p = bytes(a ^ b for a, b in zip(p1, p2))
    return xor_c == xor_p


if __name__ == "__main__":
    print("Python", platform.python_version(), "| cryptography", cryptography.__version__,
          "|", platform.platform(), "|", platform.processor() or platform.machine())
    kinerja = uji_kinerja()
    print("\n=== KINERJA (median) ===")
    for h in kinerja:
        print(h)
    integ = uji_integritas()
    print("\n=== INTEGRITAS (1 bit ciphertext diubah) ===")
    print(json.dumps(integ, indent=2))
    nonce = uji_nonce_ulang()
    print("\n=== NONCE DIPAKAI ULANG PADA GCM: XOR ciphertext == XOR plaintext ? ->", nonce)
    with open("hasil_pengujian.json", "w") as f:
        json.dump({"kinerja": kinerja, "integritas": integ, "nonce_ulang_bocor": nonce}, f,
                  indent=2)