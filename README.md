# Sincan2 POC wincok 10-11

## Deskripsi

Ini adalah Proof of Concept (PoC) untuk kerentanan SMBv3 yang ditemukan dalam CVE-2020-0796, juga dikenal sebagai "SMBGhost". PoC ini dirancang untuk Windows 10 dan Windows 11. 

Kerentanan ini mempengaruhi versi tertentu dari protokol SMB (Server Message Block) dan dapat memungkinkan penyerang untuk mengeksekusi kode berbahaya jarak jauh.

**Penulis:** Sincan2

## Fitur

- **Negosiasi SMBv3:** Mengirimkan paket negosiasi untuk memulai sesi dengan server SMB.
- **Kompresi SMB:** Mengirimkan data terkompresi untuk memanfaatkan kerentanan.

## Prasyarat

- Python 3.x
- Modul Python: `socket`, `struct`, dan `sys`

## Instalasi

1. **Clone Repository:**

    ```bash
    git clone https://github.com/Sincan2/Wincok-11-dan-10-BOSD.git
    ```

2. **Arahkan ke direktori proyek:**

    ```bash
    cd Wincok-11-dan-10-BOSD
    ```

## Penggunaan

Jalankan script dengan memberikan alamat IP target sebagai argumen:

```bash
python sincan2.py <target_ip>
