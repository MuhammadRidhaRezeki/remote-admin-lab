"""PyInstaller one-dir build script for server and client EXE."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RELEASE = ROOT / "client-release"

COMMON_HIDDEN = [
    "uvicorn",
    "uvicorn.protocols.http.httptools_impl",
    "uvicorn.protocols.websockets.websockets_impl",
    "websockets.asyncio.client",
    "customtkinter",
    "cryptography",
    "psutil",
    "requests",
    "pydantic",
    "shared",
]

CLIENT_SETTINGS = {
    "server_url": "wss://127.0.0.1:8443/ws/client",
    "server_name": "remote-admin-lab.local",
    "ca_cert": "certs\\server.crt",
    "agent_version": "1.0.0",
    "data_dir": "data",
    "allow_offline_recovery": True,
    "chunk_size_bytes": 262144,
}

CLIENT_REQUIREMENTS = """pydantic>=2.9,<3
websockets>=14,<17
cryptography>=43,<47
psutil>=6.0,<8
customtkinter>=5.2,<6
requests>=2.32,<3
"""

RUN_CLIENT_BAT = """@echo off
set CLIENT_HOME=%~dp0..
set PYTHONPATH=%~dp0
python -m client.main
"""

CLIENT_DIAGNOSE_PS1 = r"""$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$settingsPath = Join-Path $root 'config\settings.json'
$certPath = Join-Path $root 'certs\server.crt'

if (-not (Test-Path -LiteralPath $settingsPath)) {
    Write-Host "settings_missing=$settingsPath"
    exit 1
}

$settings = Get-Content -LiteralPath $settingsPath -Raw | ConvertFrom-Json
$uri = [Uri]$settings.server_url
$hostName = $uri.Host
$port = $uri.Port
Write-Host "server_url=$($settings.server_url)"
Write-Host "target=$hostName`:$port"
Write-Host "settings_written=$((Get-Item -LiteralPath $settingsPath).LastWriteTime.ToString('s'))"
Write-Host "local_time=$(Get-Date -Format s)"

$tcp = Test-NetConnection -ComputerName $hostName -Port $port -InformationLevel Quiet -WarningAction SilentlyContinue
Write-Host "tcp_reachable=$tcp"

if (Test-Path -LiteralPath $certPath) {
    $hash = (Get-FileHash -LiteralPath $certPath -Algorithm SHA256).Hash
    $x509 = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($certPath)
    Write-Host "cert=$certPath"
    Write-Host "cert_sha256=$hash"
    Write-Host "cert_not_before=$($x509.NotBefore.ToString('s'))"
    Write-Host "cert_not_after=$($x509.NotAfter.ToString('s'))"
} else {
    Write-Host "cert_missing=$certPath"
}

$identityPath = Join-Path $root 'config\identity.blob'
if (Test-Path -LiteralPath $identityPath) {
    $identity = Get-Item -LiteralPath $identityPath
    Write-Host "identity_present=True"
    Write-Host "identity_bytes=$($identity.Length)"
    Write-Host "identity_written=$($identity.LastWriteTime.ToString('s'))"
} else {
    Write-Host "identity_present=False"
}

$healthUrl = "https://{0}:{1}/health" -f $hostName, $port
$curl = Get-Command curl.exe -ErrorAction SilentlyContinue
if ($curl) {
    $health = & curl.exe -k -s -o NUL -w "%{http_code}" --max-time 8 $healthUrl
    Write-Host "health_http=$health"
} else {
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
    try {
        $response = Invoke-WebRequest -Uri $healthUrl -UseBasicParsing -TimeoutSec 8
        Write-Host "health_http=$($response.StatusCode)"
    } catch {
        Write-Host "health_error=$($_.Exception.Message)"
    }
}
"""

CLIENT_DIAGNOSE_BAT = """@echo off
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0diagnose.ps1"
pause
"""

CLIENT_README = r"""PETUNJUK CLIENT - Remote Administration Lab
===========================================

Folder ini khusus untuk komputer client. Tidak perlu Python, tidak perlu file admin/server, dan tidak perlu password admin.
Panduan lengkap server + client ada di ..\TUTORIAL.md.

1. PERSIAPAN
   - Pakai Windows 10/11 64-bit.
   - Pastikan folder ini utuh: config\, certs\, exe\, src\, data\.
   - Minta enrollment code dari admin.
   - Kode default lab: gj16QIxeGH34tJWtKfY
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
"""


def build(target: str) -> None:
    entry = {
        "server": ROOT / "server" / "main.py",
        "client": ROOT / "client" / "main.py",
    }[target]
    command = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--clean",
        "--onedir",
        "--name",
        f"remote-admin-{target}",
        "--paths",
        str(ROOT),
        "--distpath",
        str(ROOT / "dist"),
        "--workpath",
        str(ROOT / "build"),
        "--specpath",
        str(ROOT / "build"),
        "--collect-all",
        "uvicorn",
        "--collect-all",
        "customtkinter",
    ]
    for module in COMMON_HIDDEN:
        command.extend(["--hidden-import", module])
    command.append(str(entry))
    print(f"[build] {target}: {' '.join(command)}")
    subprocess.run(command, cwd=ROOT, check=True)


def package_client_release() -> None:
    source_exe = ROOT / "dist" / "remote-admin-client"
    exe_dir = RELEASE / "exe"
    if exe_dir.exists():
        shutil.rmtree(exe_dir)
    shutil.copytree(source_exe, exe_dir)

    for name in ("config", "data", "certs", "src"):
        (RELEASE / name).mkdir(parents=True, exist_ok=True)
    shutil.copy2(ROOT / "server" / "certs" / "server.crt", RELEASE / "certs" / "server.crt")

    source_dir = RELEASE / "src"
    for package in ("client", "shared"):
        destination = source_dir / package
        if destination.exists():
            shutil.rmtree(destination)
        shutil.copytree(
            ROOT / package,
            destination,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
        )
    (source_dir / "requirements-client.txt").write_text(CLIENT_REQUIREMENTS, encoding="utf-8")
    (source_dir / "run-client.bat").write_text(
        RUN_CLIENT_BAT.replace("\n", "\r\n"), encoding="utf-8"
    )
    (RELEASE / "README.md").write_text(CLIENT_README, encoding="utf-8")
    (RELEASE / "diagnose.ps1").write_text(
        CLIENT_DIAGNOSE_PS1.replace("\n", "\r\n"), encoding="utf-8"
    )
    (RELEASE / "diagnose.bat").write_text(
        CLIENT_DIAGNOSE_BAT.replace("\n", "\r\n"), encoding="utf-8"
    )

    settings_path = RELEASE / "config" / "settings.json"
    if not settings_path.exists():
        settings_path.write_text(
            json.dumps(CLIENT_SETTINGS, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
    print(f"[package] client-release: {RELEASE}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "target",
        choices=["server", "client", "client-release", "all"],
        nargs="?",
        default="all",
    )
    args = parser.parse_args()

    if args.target == "all":
        build("server")
        build("client")
        package_client_release()
    elif args.target == "client-release":
        build("client")
        package_client_release()
    else:
        build(args.target)


if __name__ == "__main__":
    main()
