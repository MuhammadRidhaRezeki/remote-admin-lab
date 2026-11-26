PETUNJUK CLIENT - Remote Administration Lab
===========================================

Folder ini khusus untuk komputer client. Tidak perlu Python, tidak perlu file admin/server, dan tidak perlu password admin.
Panduan lengkap server + client ada di ..\TUTORIAL.md.

1. PERSIAPAN
   - Pakai Windows 10/11 64-bit.
   - Pastikan folder ini utuh: config\, certs\, exe\, src\, data\.
   - Minta enrollment code dari admin.
   - Kode default lab: <ENROLLMENT_CODE>
   - Jika admin mengganti kode, pakai kode yang baru.

2. ATUR ALAMAT SERVER
   - Buka config\settings.json dengan Notepad.
   - Ubah baris server_url menjadi alamat server sebenarnya:
       "server_url": "wss://<IP-atau-domain-server>:8443/ws/client"
    - Contoh:
        "server_url": "wss://192.168.1.10:8443/ws/client"
    - Lab ini memakai IP server 192.168.100.253:
        "server_url": "wss://192.168.100.253:8443/ws/client"
    - Jangan ubah ca_cert dan data_dir kecuali admin meminta.


3. JALANKAN CLIENT
   - Double-click: exe\remote-admin-client.exe
   - Tunggu jendela client muncul.

4. KONEK PERTAMA KALI
   - Buka tab "Koneksi".
   - Isi enrollment code pada kolom yang tersedia.
   - Klik Connect.
   - Status harus berubah menjadi online / terhubung ke server.
   - Biarkan jendela client tetap terbuka selama perangkat perlu diawasi.

5. FILE PROTECTION
   - Buka tab "File Protection".
   - Pilih file atau folder yang akan dilindungi.
   - Klik Protect.
   - Admin harus menyetujui permintaan lewat dashboard server.
   - Jika muncul konfirmasi lokal, setujui.

6. UNLOCK / RECOVERY
   - Buka tab "Unlock Requests".
   - Klik Request Unlock.
   - Tunggu persetujuan admin.
   - Klik "Konfirmasi & Pulihkan", lalu pilih folder tujuan.
   - File hasil dekripsi disimpan di folder yang dipilih.

7. CARA ALTERNATIF PAKAI SOURCE
   - Install Python 3.10 atau lebih baru.
   - Buka Command Prompt di folder src.
   - Jalankan: pip install -r requirements-client.txt
   - Double-click run-client.bat.
   - Source memakai config dan data yang sama dengan EXE.

8. JANGAN DILAKUKAN
   - Jangan salin config\identity.blob ke komputer lain.
   - Jangan salin isi folder data\ ke komputer lain.
   - Jangan menuliskan password admin di client.
   - Jangan menutup client saat proses protect/unlock berjalan.

9. MASALAH UMUM
   - "kode enrolling tidak valid" -> minta kode baru ke admin.
    - Status tidak online -> double-click diagnose.bat, lalu kirim hasilnya ke admin.

   - "identity.blob tidak bisa dibuka" -> DPAPI terikat ke user Windows. Pakai user yang sama, atau minta admin membuat identity baru.
   - Persetujuan tidak muncul -> admin belum menyetujui lewat dashboard.

Ringkasan: jalankan EXE, isi enrollment code, lalu tunggu persetujuan admin untuk setiap aksi sensitif.
