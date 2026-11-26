# Tutorial Menjalankan Remote Administration Lab

Panduan ini untuk menjalankan **server** dan **client** dengan EXE. Cara menjalankan dari source Python ada di bagian alternatif.

Aplikasi ini adalah remote administration lab dengan izin dan persetujuan. Client tidak dipasang diam-diam, tidak punya persistence tersembunyi, dan tidak membuka remote shell arbitrer.

---

## 0. Kredensial lab saat ini

Nilai ini berlaku untuk konfigurasi yang sedang dipakai.

| Item | Nilai |
|---|---|
| Username admin | `admin` |
| Password admin | `<ADMIN_PASSWORD>` |
| Enrollment code client | `<ENROLLMENT_CODE>` |

Jika server dijalankan ulang setelah config dihapus/bootstrap ulang, nilai baru akan dicetak sekali di console saat first run. Password dan enrollment code tidak disimpan plaintext; yang tersimpan hanya hash di `server\config\settings.json`.

---

## 1. Peta folder penting

```text
C:\Users\Ridha\remote-admin-lab\
├── dist\remote-admin-server\remote-admin-server.exe
├── server\config\settings.json
├── server\certs\server.crt
├── server\data\server.sqlite3
└── client-release\
    ├── README.md
    ├── config\settings.json
    ├── certs\server.crt
    ├── exe\remote-admin-client.exe
    ├── src\run-client.bat
    ├── src\requirements-client.txt
    └── data\
```

Dashboard admin adalah **GUI yang berjalan di komputer/server**, bukan halaman web yang dibuka dari komputer client. API admin tetap tersedia di `https://<server>:8443/admin/...`, tetapi dipakai oleh dashboard.

---

## 2. Menjalankan server

### 2.1 Mode GUI

Jalankan:

```powershell
& "C:\Users\Ridha\remote-admin-lab\dist\remote-admin-server\remote-admin-server.exe"
```

Atau double-click file tersebut.

Pada first run, server akan:
- membuat/menyiapkan `server\config\settings.json`;
- membuat sertifikat self-signed di `server\certs\`;
- membuat database `server\data\server.sqlite3`;
- mencetak password admin dan enrollment code sekali.

Setelah dashboard muncul:
1. Isi username `admin`.
2. Isi password dari tabel kredensial di atas.
3. Pastikan CA certificate mengarah ke `C:\Users\Ridha\remote-admin-lab\server\certs\server.crt`.
4. Login.

### 2.2 Mode API tanpa GUI

Dipakai kalau server dijalankan sebagai layanan/headless:

```powershell
& "C:\Users\Ridha\remote-admin-lab\dist\remote-admin-server\remote-admin-server.exe" --no-gui --host 0.0.0.0 --port 8443
```

Gunakan `--host 0.0.0.0` jika client berada di komputer lain. Untuk lab satu komputer, default `127.0.0.1` sudah cukup.

### 2.3 Cek server hidup

```powershell
curl.exe -k https://127.0.0.1:8443/health
```

Status sukses: HTTP `200`.

Jika client di komputer lain, pastikan firewall server mengizinkan TCP `8443`. Jalankan PowerShell sebagai Administrator di server:

```powershell
New-NetFirewallRule -DisplayName "Remote Admin Lab 8443" -Direction Inbound -Protocol TCP -LocalPort 8443 -Action Allow
```

---

## 3. Menjalankan client

### 3.1 Atur alamat server

Buka:

```text
C:\Users\Ridha\remote-admin-lab\client-release\config\settings.json
```

Ubah `server_url` sesuai kebutuhan:

```json
{
  "server_url": "wss://127.0.0.1:8443/ws/client"
}
```

Contoh lain:

```text
wss://192.168.1.10:8443/ws/client
wss://relay.example.com:8443/ws/client
```

Mode LAN yang sedang dipakai di lab ini:

```json
{
  "server_url": "wss://192.168.100.253:8443/ws/client"
}
```

Alamat `192.168.100.253` adalah IP server. Gunakan IP server, bukan IP client.

Jangan ubah `ca_cert` dan `data_dir` kecuali disuruh admin. Keduanya sudah di-resolve relatif terhadap folder `client-release`.

### 3.2 Sertifikat

Default:

```json
"ca_cert": "certs\\server.crt"
```

Artinya client memakai:

```text
client-release\certs\server.crt
```

Sertifikat self-signed bawaan mencakup `localhost`, `127.0.0.1`, `remote-admin-lab.local`, dan IP server lab `192.168.100.253`. Masa berlakunya mulai 7 hari sebelum tanggal generate agar toleran terhadap selisih jam client. Untuk IP LAN/VPS lain, sertifikat harus dibuat ulang dengan SAN alamat tersebut. Untuk produksi, pakai Let’s Encrypt.

### 3.3 Jalankan EXE client

```powershell
& "C:\Users\Ridha\remote-admin-lab\client-release\exe\remote-admin-client.exe"
```

Atau double-click:

```text
client-release\exe\remote-admin-client.exe
```

Pada GUI client:
1. Buka tab **Koneksi**.
2. Isi `Enrollment code` dengan `<ENROLLMENT_CODE>`.
3. Klik **Simpan Pengaturan**.
4. Klik **Connect**.
5. Tunggu status berubah menjadi `online` / `terhubung ke server`.

Setelah berhasil, `identity.blob` dibuat di `client-release\config\identity.blob`. Koneksi berikutnya memakai token perangkat yang tersimpan di sana; enrollment code tidak perlu diisi ulang.

**Jangan salin `identity.blob` atau isi folder `data\` ke komputer lain.** Keduanya terikat ke akun Windows dan perangkat tempat client pertama kali dijalankan.

---

## 4. Alur operasi harian

### 4.1 Task administratif

Di dashboard server:
1. Buka **Task Management**.
2. Pilih client yang online.
3. Pilih task yang diizinkan, misalnya `system_info`, `cpu_ram`, `disk`, `network`, `agent_status`.
4. Buat task.
5. Klik **Approve**.

Client akan menerima task, menjalankan allowlisted collector, lalu mengirim `task_result` ke server.

### 4.2 File protection

Di client:
1. Buka tab **File Protection**.
2. Pilih file atau folder.
3. Klik **Protect**.
4. Salinan terenkripsi AES-256-GCM dibuat di `client-release\data\protected\`.
5. Admin menyetujui lewat dashboard server.
6. Jika muncul konfirmasi lokal, setujui.

File asli tetap ada dan tidak ditimpa.

### 4.3 Unlock / recovery

Di client:
1. Buka tab **Unlock Requests**.
2. Klik **Request Unlock**.
3. Tunggu admin menyetujui di dashboard.
4. Klik **Konfirmasi & Pulihkan**.
5. Pilih folder tujuan.
6. Client membuka kunci DPAPI lokal, mendekripsi salinan, memverifikasi hash, lalu menulis file ke folder tujuan.

Jika server offline, tombol recovery offline tetap tersedia selama akun Windows yang sama bisa membuka DPAPI.

### 4.4 Audit

Di dashboard server, buka **Audit Logs**. Status hash chain harus `valid`. Setiap protect, approve, unlock, dan recovery tercatat di sana.

---

## 5. Cara alternatif menjalankan dari source

### 5.1 Siapkan lingkungan

```powershell
cd C:\Users\Ridha\remote-admin-lab
python -m venv .venv
.\.venv\Scripts\python -m pip install -r requirements.txt
```

### 5.2 Server source

```powershell
.\.venv\Scripts\python -m server.main
```

Headless:

```powershell
.\.venv\Scripts\python -m server.main --no-gui --host 0.0.0.0 --port 8443
```

### 5.3 Client source dari folder release

```powershell
cd C:\Users\Ridha\remote-admin-lab\client-release\src
pip install -r requirements-client.txt
.\run-client.bat
```

`run-client.bat` otomatis mengatur `CLIENT_HOME` dan `PYTHONPATH`, lalu memakai config dan data yang sama dengan EXE.

### 5.4 Client source langsung dari repo

```powershell
cd C:\Users\Ridha\remote-admin-lab
.\.venv\Scripts\python -m client.main
```

---

## 6. Verifikasi cepat

Dari folder proyek:

```powershell
.\.venv\Scripts\python -m pytest -q
.\.venv\Scripts\python -m tools.e2e_check --enrollment-code <ENROLLMENT_CODE>
```

Smoke test sukses jika muncul:

```text
e2e-ok status=('online', 'terhubung ke server') messages=['hello_ack']
```

---

## 7. Masalah umum

| Gejala | Penyebab | Tindakan |
|---|---|---|
| `kode enrolling tidak valid` | Enrollment code salah/sudah diganti | Minta kode baru dari server |
| Client tidak online | Server mati, `server_url` salah, firewall menolak | Jalankan `.\diagnose.ps1` di folder client dan kirim hasilnya ke admin |
| TLS/certificate mismatch | Sertifikat tidak mencakup IP/domain yang dipakai | Regenerate cert untuk alamat tersebut atau pakai Let’s Encrypt |
| `certificate is not yet valid` | Waktu komputer client lebih mundur dari waktu server | Sinkronkan jam Windows; sertifikat dev sekarang sudah di-backdate 7 hari untuk toleransi |
| `identity.blob tidak bisa dibuka` | DPAPI terikat ke user Windows lain | Pakai user yang sama atau minta admin buat identity baru |
| Approval tidak muncul | Admin belum approve di dashboard | Buka dashboard server dan setujui permintaan |
| Dashboard error `extra_forbidden` | Server EXE lama sebelum perbaikan | Pakai EXE terbaru dari `dist\remote-admin-server\` |
| Login gagal padahal password benar | Dashboard lama memakai path CA relatif dari folder EXE | Tutup dan buka ulang EXE terbaru; field CA harus absolut `C:\Users\Ridha\remote-admin-lab\server\certs\server.crt` |

Untuk diagnosis client, di folder `client-release` komputer client, double-click:

```text
diagnose.bat
```

Atau lewat PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File .\diagnose.ps1
```

Script ini menampilkan `server_url`, hasil `Test-NetConnection`, hash sertifikat, dan hasil health check.

---

## 8. Ringkasan singkat

1. Jalankan server EXE.
2. Login dashboard dengan `admin` / `<ADMIN_PASSWORD>`.
3. Atur `server_url` di client.
4. Jalankan client EXE.
5. Isi enrollment code `<ENROLLMENT_CODE>`, lalu Connect.
6. Setiap aksi sensitif butuh approve admin dan konfirmasi lokal client.
