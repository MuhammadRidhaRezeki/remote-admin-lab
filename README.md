# Remote Administration & File Protection Lab

Aplikasi Windows 10/11 64-bit untuk dua perangkat yang saling terotorisasi: server pusat (FastAPI, WebSocket/TLS, SQLite, dashboard admin) dan client agent yang dijalankan secara sadar oleh pemilik perangkat.

Tidak ada remote shell arbitrer, persistence, credential harvesting, atau kunci enkripsi yang dikirim melalui jaringan.

Panduan menjalankan server dan client ada di `TUTORIAL.md`.

## Struktur

```text
remote-admin-lab/
├── server/          API, autentikasi, WebSocket, approval, SQLite, GUI admin
├── client/          koneksi, identitas DPAPI, system info, file vault, recovery, GUI
├── shared/          protocol, model Pydantic, AES-GCM + DPAPI helpers
├── tests/           pengujian protokol, kripto, database, API, client vault
├── tools/           sertifikat dev, smoke test TLS, build EXE
├── requirements.txt
└── README.md
```

## Persyaratan

- Python 3.12+ (dikembangkan dan diuji pada 3.14)
- Windows 10/11 64-bit pada komputer yang dipakai
- VPS dengan domain publik untuk mode relay produksi
- Sertifikat TLS; mode lokal memakai sertifikat self-signed yang dibuat otomatis

## Instalasi

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install -r requirements.txt
.\.venv\Scripts\python -m pytest -q
```

## Menjalankan server

```powershell
.\.venv\Scripts\python -m server.main
```

Pada menjalankan pertama, server mencetak sekali:

- Admin password: `<ADMIN_PASSWORD>`
- Enrollment code: `<ENROLLMENT_CODE>`

Username admin adalah `admin`. Keduanya tidak disimpan plaintext. Yang disimpan di `server/config/settings.json` adalah salt + hash PBKDF2-SHA256 untuk kata sandi admin dan hash SHA-256 untuk enrollment code. Sertifikat dev self-signed dibuat di `server/certs/` bila belum ada.

Dashboard admin melakukan login ke `https://127.0.0.1:8443` dengan CA certificate `server/certs/server.crt`.

Mode API tanpa GUI:

```powershell
.\.venv\Scripts\python -m server.main --no-gui --host 0.0.0.0 --port 8443
```

## Menjalankan client

```powershell
.\.venv\Scripts\python -m client.main
```

Pada frame **Koneksi**:

1. Isi `Server URL`, misalnya `wss://relay.example.com:8443/ws/client`.
2. Isi `CA certificate` dengan file sertifikat CA/server yang dipercaya.
3. Isi `Enrollment code` dari server.
4. Tekan **Simpan Pengaturan**, lalu **Connect**.

Identity client (`device_id`, token, enrollment code) disimpan di `client/config/identity.blob`, terlindungi DPAPI untuk akun Windows yang bersangkutan.

## Relay produksi

Rekomendasi: VPS dengan domain dan sertifikat Let’s Encrypt.

1. Arahkan DNS `relay.example.com` ke VPS.
2. Terbitkan sertifikat untuk domain tersebut.
3. Jalankan server dengan cert/key Let’s Encrypt:
   - `cert_file` → `/etc/letsencrypt/live/relay.example.com/fullchain.pem`
   - `key_file` → `/etc/letsencrypt/live/relay.example.com/privkey.pem`
   - `server_name` → `relay.example.com`
4. Buka hanya port yang diperlukan di firewall.
5. Distribusikan CA publik (atau chain Let’s Encrypt) ke client; client tetap memverifikasi hostname dan sertifikat.

Untuk lab lokal, sertifikat self-signed sudah mencakup `localhost` dan `127.0.0.1` pada SAN.

## Alur operasi

### Task administratif

1. Admin memilih client dan allowlisted task: `system_info`, `cpu_ram`, `disk`, `network`, `agent_status`, `transfer_file`.
2. Task dibuat dengan status `pending`.
3. Admin menekan **Approve** atau **Reject**.
4. Task yang disetujui dikirim ke client melalui WebSocket.
5. Client menjalankan task dan mengembalikan `task_result`.

`transfer_file` hanya mengirim salinan terenkripsi, memerlukan persetujuan admin dan konfirmasi lokal pengguna client. Batas default 25 MB per transfer.

### File protection

1. Pengguna memilih file atau folder secara manual.
2. Client membuat salinan terenkripsi AES-256-GCM dengan kunci acak 32 byte.
3. Salinan divalidasi dengan dekripsi uji dan hash SHA-256 sebelum status menjadi `protected`.
4. Kunci dibungkus DPAPI dan tetap di perangkat client.
5. File asli tidak dihapus atau ditimpa.

### Unlock dan recovery

1. Client membuat `unlock_request` berisi request ID, client ID, file, waktu, alasan, status.
2. Admin melihat metadata file dan menyetujui atau menolak.
3. Persetujuan server dikirim ke client, tetapi tidak membuka file.
4. Pengguna client menekan **Konfirmasi & Pulihkan** dan memilih lokasi tujuan.
5. Client membuka kunci DPAPI lokal, mendekripsi salinan, memverifikasi tag GCM dan hash, lalu menulis hasil pemulihan.
6. Hasil dicatat di audit log lokal dan server.

Jika server offline, **Recover Offline** tetap tersedia selama akun Windows pengguna dapat membuka DPAPI. Event recovery offline disinkronkan ke server setelah koneksi kembali.

## Database

Tabel: `clients`, `sessions`, `tasks`, `file_records`, `unlock_requests`, `approvals`, `audit_logs`.

`audit_logs` bersifat append-only (trigger menolak UPDATE/DELETE) dan memiliki hash chain. Dashboard menampilkan status `valid` atau `RUSAK`.

## Keamanan

- TLS/WSS dengan verifikasi sertifikat dan hostname.
- Token unik per perangkat, diverifikasi sebagai hash.
- Enrollment code sekali pakai pada proses pendaftaran awal, diverifikasi sebagai hash.
- Kata sandi admin PBKDF2-SHA256, 210.000 iterasi.
- Rate limiting untuk login, endpoint admin, dan handshake WebSocket.
- Validasi seluruh pesan memakai model Pydantic dengan `extra="forbid"`.
- Kunci AES tidak pernah dikirim ke server.

## Pengujian

```powershell
.\.venv\Scripts\python -m pytest -q
.\.venv\Scripts\python -m tools.e2e_check --enrollment-code <kode-dari-server>
```

## Packaging EXE

Mode one-dir dipilih agar sertifikat, database, dan file konfigurasi dapat dikelola di luar binary.

```powershell
.\.venv\Scripts\python -m tools.build_exe all
```

Hasil berada di `dist/remote-admin-server/` dan `dist/remote-admin-client/`.

Perintah `all` juga membuat paket client mandiri di `client-release/`. Untuk hanya membuat paket tersebut:

```powershell
.\.venv\Scripts\python -m tools.build_exe client-release
```

Struktur `client-release/`:

```text
config/settings.json
certs/server.crt
exe/remote-admin-client.exe
exe/_internal/
src/client/
src/shared/
src/requirements-client.txt
src/run-client.bat
data/
README.md
```

Petunjuk untuk komputer client ada di `client-release/README.md`.

Jalankan EXE:

```powershell
.\client-release\exe\remote-admin-client.exe
```

Jalankan source:

```powershell
cd .\client-release\src
pip install -r requirements-client.txt
.\run-client.bat
```

Sebelum dipakai di komputer lain, ubah `server_url` di `config/settings.json` ke alamat server sebenarnya. Jangan kirim `config/identity.blob` dan folder `data/` ke komputer lain; keduanya dibuat lokal saat client pertama kali dijalankan.
