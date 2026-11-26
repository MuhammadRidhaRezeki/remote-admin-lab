"""CustomTkinter client interface — visible, explicit, local consent."""

from __future__ import annotations

import base64
import math
import queue
import threading
from pathlib import Path
from typing import Any

import customtkinter as ctk
from tkinter import filedialog, messagebox

from shared.models import Envelope, MessageType, new_id
from shared.protocol import make_envelope, sanitize_filename

from ..authentication import ClientIdentity, save_identity
from ..config import IDENTITY_PATH, SETTINGS_PATH, save_settings
from ..connection import AgentConnection
from ..file_protection import Vault
from ..recovery import RecoveryService
from ..system_info import device_identity, system_snapshot

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

ACCENT = "#38bdf8"
MUTED = "#94a3b8"


class ClientApp(ctk.CTk):
    def __init__(
        self,
        settings: dict[str, Any],
        identity: ClientIdentity,
        settings_path: Path | str | None = None,
        identity_path: Path | str | None = None,
    ) -> None:
        super().__init__()
        self.settings = settings
        self.identity = identity
        self.settings_path = Path(settings_path) if settings_path else SETTINGS_PATH
        self.identity_path = Path(identity_path) if identity_path else IDENTITY_PATH
        self.vault = Vault(str(settings["data_dir"]), identity.device_id)
        self.recovery = RecoveryService(self.vault)
        self.events: queue.Queue[tuple[str, Any]] = queue.Queue()
        self.approvals: dict[str, dict[str, Any]] = {}
        self.selected_paths: list[Path] = []
        self._status = "stopped"

        self.connection = AgentConnection(
            settings, identity, self._on_message, self._on_status
        )

        self.title("Remote Administration Lab — Client")
        self.geometry("1180x760")
        self.minsize(980, 640)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self._build_shell()
        self._build_navigation()
        self._build_header()
        self._build_frames()
        self.show_frame("connection")
        self._refresh_device()
        self._refresh_records()
        self._refresh_activity()
        self._after_id = self.after(150, self._drain_events)

    # ---------- shell ----------

    def _build_shell(self) -> None:
        self.sidebar = ctk.CTkFrame(self, width=224, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsw")
        self.sidebar.grid_rowconfigure(20, weight=1)

        self.content = ctk.CTkFrame(self, corner_radius=0, fg_color=("#0f172a", "#0b1220"))
        self.content.grid(row=0, column=1, sticky="nsew")
        self.content.grid_columnconfigure(0, weight=1)
        self.content.grid_rowconfigure(1, weight=1)

    def _build_navigation(self) -> None:
        ctk.CTkLabel(
            self.sidebar,
            text="REMOTE ADMIN\nLAB / CLIENT",
            justify="left",
            font=("Segoe UI", 16, "bold"),
            text_color=ACCENT,
        ).grid(row=0, column=0, padx=20, pady=(24, 22), sticky="w")

        items = [
            ("connection", "Koneksi"),
            ("device", "Informasi Perangkat"),
            ("files", "File Protection"),
            ("unlock", "Unlock Requests"),
            ("activity", "Riwayat Aktivitas"),
        ]
        self.nav_buttons: dict[str, ctk.CTkButton] = {}
        for index, (key, label) in enumerate(items, start=1):
            button = ctk.CTkButton(
                self.sidebar,
                text=label,
                anchor="w",
                height=38,
                fg_color="transparent",
                text_color=("#334155", "#cbd5e1"),
                hover_color=("#e2e8f0", "#1e293b"),
                command=lambda item=key: self.show_frame(item),
            )
            button.grid(row=index, column=0, padx=14, pady=4, sticky="ew")
            self.nav_buttons[key] = button

        ctk.CTkLabel(
            self.sidebar,
            text="agent berjalan hanya saat\ndijalankan oleh pemilik perangkat",
            font=("Segoe UI", 11),
            text_color=MUTED,
            justify="left",
        ).grid(row=20, column=0, padx=20, pady=18, sticky="sw")

    def _build_header(self) -> None:
        header = ctk.CTkFrame(self.content, height=68, corner_radius=14)
        header.grid(row=0, column=0, sticky="ew", padx=24, pady=(22, 12))
        header.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            header,
            text=str(self.settings["server_name"]),
            font=("Segoe UI", 15, "bold"),
        ).grid(row=0, column=0, padx=18, pady=16, sticky="w")

        self.status_label = ctk.CTkLabel(
            header, text="● stopped", font=("Segoe UI", 13), text_color=MUTED
        )
        self.status_label.grid(row=0, column=1, padx=12, sticky="w")

        ctk.CTkButton(
            header, text="Connect", width=96, command=self._connect
        ).grid(row=0, column=2, padx=6, pady=14)
        ctk.CTkButton(
            header,
            text="Disconnect",
            width=104,
            fg_color="#475569",
            command=self._disconnect,
        ).grid(row=0, column=3, padx=6, pady=14)
        ctk.CTkButton(
            header,
            text="Stop Agent",
            width=104,
            fg_color="#7f1d1d",
            hover_color="#991b1b",
            command=self._stop_agent,
        ).grid(row=0, column=4, padx=(6, 18), pady=14)

        self.frame_host = ctk.CTkFrame(self.content, fg_color="transparent")
        self.frame_host.grid(row=1, column=0, sticky="nsew", padx=24, pady=(0, 24))
        self.frame_host.grid_columnconfigure(0, weight=1)
        self.frame_host.grid_rowconfigure(0, weight=1)

    def _build_frames(self) -> None:
        self.frames: dict[str, ctk.CTkFrame] = {}
        self.frames["connection"] = self._connection_frame()
        self.frames["device"] = self._device_frame()
        self.frames["files"] = self._files_frame()
        self.frames["unlock"] = self._unlock_frame()
        self.frames["activity"] = self._activity_frame()

    def show_frame(self, name: str) -> None:
        for frame in self.frames.values():
            frame.grid_forget()
        self.frames[name].grid(row=0, column=0, sticky="nsew")
        active = self.nav_buttons[name]
        for button in self.nav_buttons.values():
            button.configure(fg_color="transparent", text_color=MUTED)
        active.configure(fg_color=("#1d4ed8", "#1e40af"), text_color="#ffffff")

    @staticmethod
    def _set_text(widget: ctk.CTkTextbox, text: str) -> None:
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", text)
        widget.configure(state="disabled")

    # ---------- sections ----------

    def _connection_frame(self) -> ctk.CTkFrame:
        frame = ctk.CTkFrame(self.frame_host)
        frame.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            frame, text="Koneksi ke Server", font=("Segoe UI", 20, "bold")
        ).grid(row=0, column=0, columnspan=3, padx=24, pady=(22, 16), sticky="w")

        rows = [
            ("Server URL", "server_url", str(self.settings["server_url"])),
            ("Server name", "server_name", str(self.settings["server_name"])),
            ("CA certificate", "ca_cert", str(self.settings["ca_cert"])),
        ]
        self.connection_entries: dict[str, ctk.CTkEntry] = {}
        for index, (label, key, value) in enumerate(rows, start=1):
            ctk.CTkLabel(frame, text=label, font=("Segoe UI", 13)).grid(
                row=index, column=0, padx=(24, 12), pady=10, sticky="w"
            )
            entry = ctk.CTkEntry(frame, height=36)
            entry.insert(0, value)
            entry.grid(row=index, column=1, columnspan=2, padx=12, pady=10, sticky="ew")
            self.connection_entries[key] = entry

        ctk.CTkLabel(frame, text="Enrollment code", font=("Segoe UI", 13)).grid(
            row=4, column=0, padx=(24, 12), pady=10, sticky="w"
        )
        self.enrollment_entry = ctk.CTkEntry(frame, height=36, show="*")
        self.enrollment_entry.insert(0, self.identity.enrollment_code)
        self.enrollment_entry.grid(row=4, column=1, columnspan=2, padx=12, pady=10, sticky="ew")

        ctk.CTkLabel(frame, text="Device ID", font=("Segoe UI", 13)).grid(
            row=5, column=0, padx=(24, 12), pady=10, sticky="w"
        )
        ctk.CTkLabel(
            frame, text=self.identity.device_id, font=("Consolas", 12), text_color=ACCENT
        ).grid(row=5, column=1, columnspan=2, padx=12, pady=10, sticky="w")

        ctk.CTkButton(
            frame, text="Simpan Pengaturan", command=self._save_connection_settings
        ).grid(row=6, column=1, padx=12, pady=22, sticky="w")

        note = (
            "Koneksi memakai WSS dengan verifikasi sertifikat CA. Token perangkat dan enrollment code "
            "disimpan terlindungi DPAPI untuk akun Windows ini. Agent tidak berjalan otomatis."
        )
        ctk.CTkLabel(
            frame, text=note, font=("Segoe UI", 12), text_color=MUTED, wraplength=700, justify="left"
        ).grid(row=7, column=0, columnspan=3, padx=24, pady=(0, 24), sticky="w")
        return frame

    def _device_frame(self) -> ctk.CTkFrame:
        frame = ctk.CTkFrame(self.frame_host)
        frame.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(
            frame, text="Informasi Perangkat", font=("Segoe UI", 20, "bold")
        ).grid(row=0, column=0, columnspan=2, padx=24, pady=(22, 18), sticky="w")
        self.device_labels: dict[str, ctk.CTkLabel] = {}
        keys = [
            ("hostname", "Hostname"),
            ("os", "Sistem operasi"),
            ("python", "Python"),
            ("ips", "IP privat"),
            ("agent", "Versi agent"),
            ("status", "Status"),
        ]
        for index, (key, label) in enumerate(keys, start=1):
            ctk.CTkLabel(frame, text=label, font=("Segoe UI", 13), text_color=MUTED).grid(
                row=index, column=0, padx=(24, 12), pady=12, sticky="w"
            )
            value = ctk.CTkLabel(frame, text="-", font=("Segoe UI", 13))
            value.grid(row=index, column=1, padx=12, pady=12, sticky="w")
            self.device_labels[key] = value
        return frame

    def _files_frame(self) -> ctk.CTkFrame:
        frame = ctk.CTkFrame(self.frame_host)
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(
            frame, text="File Protection", font=("Segoe UI", 20, "bold")
        ).grid(row=0, column=0, columnspan=2, padx=20, pady=(20, 12), sticky="w")

        ctk.CTkLabel(frame, text="Pilihan pengguna", font=("Segoe UI", 14, "bold")).grid(
            row=1, column=0, padx=20, pady=8, sticky="w"
        )
        self.selected_text = ctk.CTkTextbox(frame, height=140)
        self.selected_text.grid(row=2, column=0, padx=20, pady=6, sticky="nsew")

        picker_row = ctk.CTkFrame(frame, fg_color="transparent")
        picker_row.grid(row=3, column=0, padx=20, pady=8, sticky="ew")
        ctk.CTkButton(
            picker_row, text="Pilih File", width=110, command=self._pick_files
        ).pack(side="left", padx=(0, 8))
        ctk.CTkButton(
            picker_row, text="Pilih Folder", width=112, command=self._pick_folder
        ).pack(side="left")
        ctk.CTkButton(
            picker_row, text="Protect", width=100, fg_color="#0f766e", command=self._protect
        ).pack(side="right")

        ctk.CTkLabel(frame, text="File terlindungi", font=("Segoe UI", 14, "bold")).grid(
            row=1, column=1, padx=20, pady=8, sticky="w"
        )
        self.records_text = ctk.CTkTextbox(frame, height=140)
        self.records_text.grid(row=2, column=1, padx=20, pady=6, sticky="nsew")

        actions = ctk.CTkFrame(frame, fg_color="transparent")
        actions.grid(row=3, column=1, padx=20, pady=8, sticky="ew")
        self.file_combo = ctk.CTkComboBox(actions, values=["-"], width=220)
        self.file_combo.set("-")
        self.file_combo.pack(side="left", padx=(0, 8))
        ctk.CTkButton(
            actions, text="Request Unlock", width=126, command=self._request_unlock
        ).pack(side="left", padx=(0, 8))
        ctk.CTkButton(
            actions, text="Recover Offline", width=132, command=self._recover_offline
        ).pack(side="left")

        ctk.CTkLabel(frame, text="Alasan pembukaan", font=("Segoe UI", 13)).grid(
            row=4, column=1, padx=20, pady=(12, 4), sticky="w"
        )
        self.reason_entry = ctk.CTkEntry(frame, height=34, placeholder_text="contoh: audit bulanan")
        self.reason_entry.grid(row=5, column=1, padx=20, pady=4, sticky="ew")

        explanation = (
            "_protect membuat salinan terenkripsi AES-256-GCM. File asli tidak dihapus atau ditimpa. "
            "Kunci dibuat acak dan dibungkus DPAPI hanya di perangkat ini; server tidak menerima kunci."
        )
        ctk.CTkLabel(
            frame, text=explanation, font=("Segoe UI", 12), text_color=MUTED,
            wraplength=1000, justify="left"
        ).grid(row=6, column=0, columnspan=2, padx=20, pady=(16, 20), sticky="w")
        frame.grid_rowconfigure(2, weight=1)
        return frame

    def _unlock_frame(self) -> ctk.CTkFrame:
        frame = ctk.CTkFrame(self.frame_host)
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(
            frame, text="Unlock Requests", font=("Segoe UI", 20, "bold")
        ).grid(row=0, column=0, columnspan=2, padx=20, pady=(20, 12), sticky="w")

        ctk.CTkLabel(
            frame, text="Persetujuan server — butuh konfirmasi lokal",
            font=("Segoe UI", 14, "bold"),
        ).grid(row=1, column=0, padx=20, pady=8, sticky="w")
        self.approval_combo = ctk.CTkComboBox(frame, values=["-"], width=260)
        self.approval_combo.set("-")
        self.approval_combo.grid(row=2, column=0, padx=20, pady=8, sticky="w")
        self.approval_text = ctk.CTkTextbox(frame, height=150)
        self.approval_text.grid(row=3, column=0, padx=20, pady=6, sticky="nsew")
        buttons = ctk.CTkFrame(frame, fg_color="transparent")
        buttons.grid(row=4, column=0, padx=20, pady=12, sticky="w")
        ctk.CTkButton(
            buttons, text="Konfirmasi & Pulihkan", fg_color="#0f766e",
            command=self._confirm_unlock,
        ).pack(side="left", padx=(0, 8))
        ctk.CTkButton(
            buttons, text="Tolak", fg_color="#7f1d1d", command=self._reject_unlock
        ).pack(side="left")

        ctk.CTkLabel(
            frame, text="Permintaan saya", font=("Segoe UI", 14, "bold")
        ).grid(row=1, column=1, padx=20, pady=8, sticky="w")
        self.unlock_text = ctk.CTkTextbox(frame, height=150)
        self.unlock_text.grid(row=2, column=1, rowspan=3, padx=20, pady=6, sticky="nsew")
        frame.grid_rowconfigure(3, weight=1)
        return frame

    def _activity_frame(self) -> ctk.CTkFrame:
        frame = ctk.CTkFrame(self.frame_host)
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(1, weight=1)
        ctk.CTkLabel(
            frame, text="Riwayat Aktivitas", font=("Segoe UI", 20, "bold")
        ).grid(row=0, column=0, padx=20, pady=(20, 12), sticky="w")
        self.activity_text = ctk.CTkTextbox(frame)
        self.activity_text.grid(row=1, column=0, padx=20, pady=(0, 20), sticky="nsew")
        return frame

    # ---------- actions ----------

    def _save_connection_settings(self) -> None:
        for key, entry in self.connection_entries.items():
            self.settings[key] = entry.get().strip()
        self.identity.enrollment_code = self.enrollment_entry.get().strip()
        save_identity(self.identity, self.identity_path)
        save_settings(self.settings, self.settings_path)
        self._log("pengaturan koneksi disimpan")

    def _connect(self) -> None:
        if self._status == "online":
            return
        self.identity.enrollment_code = self.enrollment_entry.get().strip()
        if not self.identity.enrollment_code:
            messagebox.showwarning("Enrollment", "Masukkan enrollment code dari server.")
            return
        save_identity(self.identity, self.identity_path)
        self.connection.start()

    def _disconnect(self) -> None:
        self.connection.stop()

    def _stop_agent(self) -> None:
        self.connection.stop()
        self.connect_button_disabled = True
        self._log("agent dihentikan oleh pengguna")

    def _pick_files(self) -> None:
        paths = filedialog.askopenfilenames(title="Pilih file yang akan dilindungi")
        if paths:
            self.selected_paths = [Path(item) for item in paths]
            self._refresh_selection()

    def _pick_folder(self) -> None:
        folder = filedialog.askdirectory(title="Pilih folder yang akan dilindungi")
        if folder:
            self.selected_paths = [Path(folder)]
            self._refresh_selection()

    def _refresh_selection(self) -> None:
        files = self.vault.expand_selection(self.selected_paths)
        lines = [
            f"{item['name']}  |  {item['size_bytes']:,} B  |  {item['path']}"
            for item in self.vault.describe(files)
        ]
        self._set_text(self.selected_text, "\n".join(lines) or "Belum ada pilihan.")

    def _protect(self) -> None:
        if not self.selected_paths:
            messagebox.showinfo("Pilih file", "Pilih file atau folder terlebih dahulu.")
            return
        try:
            records = self.vault.protect(self.selected_paths)
        except Exception as exc:
            messagebox.showerror("Protect gagal", str(exc))
            return
        for record in records:
            self.connection.send(
                make_envelope(MessageType.FILE_RECORD, self.identity.device_id, record)
            )
            self._log(f"dilindungi: {record['file_name']} ({record['file_id']})")
        self._refresh_records()

    def _refresh_records(self) -> None:
        records = self.vault.list_records()
        lines = [
            f"{r['file_id']}  |  {r['file_name']}  |  {r['size_bytes']:,} B  |  {r['status']}\n"
            f"    asli: {r['original_path']}\n    salinan: {r['protected_path']}"
            for r in records
        ]
        self._set_text(self.records_text, "\n\n".join(lines) or "Belum ada file terlindungi.")
        values = [r["file_id"] for r in records] or ["-"]
        self.file_combo.configure(values=values)
        if values and self.file_combo.get() not in values:
            self.file_combo.set(values[0])

    def _selected_file_id(self) -> str | None:
        value = self.file_combo.get().strip()
        return None if value in {"", "-"} else value

    def _request_unlock(self) -> None:
        file_id = self._selected_file_id()
        reason = self.reason_entry.get().strip()
        if not file_id or len(reason) < 3:
            messagebox.showinfo("Unlock", "Pilih file dan isi alasan minimal 3 karakter.")
            return
        record = self.vault.get_record(file_id)
        if not record:
            return
        request_id = new_id("unlock")
        self.vault.append_event(
            "unlock_requested", {"request_id": request_id, "file_id": file_id, "reason": reason}
        )
        delivered = self.connection.send(
            make_envelope(
                MessageType.UNLOCK_REQUEST,
                self.identity.device_id,
                {"file_id": file_id, "reason": reason},
                request_id=request_id,
            )
        )
        self._log(
            f"permintaan {request_id} untuk {record.file_name} "
            f"({'dikirim' if delivered else 'tertunda'})"
        )
        self._refresh_unlock_text()

    def _refresh_unlock_text(self) -> None:
        events = [
            e for e in self.vault.list_events(200) if e["action"] == "unlock_requested"
        ]
        lines = [
            f"{e['detail'].get('request_id', e['event_id'])}  |  {e['detail']['file_id']}  |  "
            f"{e['detail']['reason']}  |  {e['ts']}"
            for e in events
        ]
        self._set_text(self.unlock_text, "\n".join(lines) or "Belum ada permintaan.")

    def _refresh_approvals(self) -> None:
        values = list(self.approvals.keys()) or ["-"]
        self.approval_combo.configure(values=values)
        if values and self.approval_combo.get() not in values:
            self.approval_combo.set(values[0])
        lines = [
            f"{request_id}  |  {item.get('file_name', item['file_id'])}  |  "
            f"{item['decision']}  |  oleh {item.get('decided_by', '-')}"
            for request_id, item in self.approvals.items()
        ]
        self._set_text(self.approval_text, "\n".join(lines) or "Belum ada persetujuan server.")

    def _destination(self, file_name: str) -> Path | None:
        folder = filedialog.askdirectory(title="Pilih folder tujuan pemulihan")
        if not folder:
            return None
        return Path(folder) / sanitize_filename(file_name)

    def _confirm_unlock(self) -> None:
        request_id = self.approval_combo.get().strip()
        approval = self.approvals.get(request_id)
        if not approval:
            messagebox.showinfo("Konfirmasi", "Pilih persetujuan server terlebih dahulu.")
            return
        if approval["decision"] != "approved":
            messagebox.showinfo("Ditolak", "Server menolak permintaan ini.")
            return
        destination = self._destination(str(approval.get("file_name") or approval["file_id"]))
        if destination is None:
            return
        try:
            result = self.recovery.recover(
                approval["file_id"], destination, request_id=request_id, offline=False
            )
        except Exception as exc:
            messagebox.showerror("Recovery gagal", str(exc))
            return
        self.connection.send(
            make_envelope(MessageType.RECOVERY_RESULT, self.identity.device_id, result)
        )
        self._log(f"dipulihkan setelah persetujuan: {destination}")
        self.vault.append_event("local_confirmation", {"request_id": request_id})

    def _reject_unlock(self) -> None:
        request_id = self.approval_combo.get().strip()
        if request_id in self.approvals:
            self.approvals.pop(request_id)
            self.vault.append_event("unlock_rejected_local", {"request_id": request_id})
            self._log(f"konfirmasi lokal ditolak: {request_id}")
            self._refresh_approvals()

    def _recover_offline(self) -> None:
        file_id = self._selected_file_id()
        record = self.vault.get_record(file_id) if file_id else None
        if not record:
            messagebox.showinfo("Recovery", "Pilih file terlindungi terlebih dahulu.")
            return
        if not bool(self.settings.get("allow_offline_recovery", True)):
            messagebox.showinfo("Recovery", "Recovery offline dinonaktifkan pada pengaturan.")
            return
        destination = self._destination(record.file_name)
        if destination is None:
            return
        try:
            result = self.recovery.recover(record.file_id, destination, offline=True)
        except Exception as exc:
            messagebox.showerror("Recovery gagal", str(exc))
            return
        if self.connection.connected:
            self.connection.send(
                make_envelope(MessageType.RECOVERY_RESULT, self.identity.device_id, result)
            )
        self._log(f"recovery offline terverifikasi: {destination}")
        self._refresh_activity()

    # ---------- inbound ----------

    def _on_status(self, status: str, detail: str) -> None:
        self.events.put(("status", (status, detail)))

    def _on_message(self, envelope: Envelope) -> None:
        self.events.put(("message", envelope))

    def _drain_events(self) -> None:
        while True:
            try:
                kind, value = self.events.get_nowait()
            except queue.Empty:
                break
            if kind == "status":
                status, detail = value
                self._status = status
                colors = {"online": ACCENT, "offline": "#f59e0b", "stopped": MUTED}
                self.status_label.configure(
                    text=f"● {status}", text_color=colors.get(status, MUTED)
                )
                self.device_labels["status"].configure(text=f"{status} — {detail}")
                self._log(f"koneksi: {status} ({detail})")
                if status == "online":
                    self.recovery.flush_offline_events(
                        lambda payload: self.connection.send(
                            make_envelope(
                                MessageType.RECOVERY_RESULT, self.identity.device_id, payload
                            )
                        )
                    )
            elif kind == "message":
                self._handle_message(value)
        self._after_id = self.after(150, self._drain_events)

    def _handle_message(self, envelope: Envelope) -> None:
        if envelope.type is MessageType.PING:
            self.connection.send(
                make_envelope(MessageType.PONG, self.identity.device_id, {})
            )
            return
        if envelope.type is MessageType.HELLO_ACK:
            self._log(f"server: {envelope.payload.get('server_name', 'terhubung')}")
            return
        if envelope.type is MessageType.TASK_REQUEST:
            self._handle_task(envelope)
            return
        if envelope.type is MessageType.UNLOCK_DECISION:
            self.approvals[envelope.request_id] = envelope.payload
            self._refresh_approvals()
            self._log(
                f"keputusan server {envelope.request_id}: {envelope.payload.get('decision')}"
            )
            return
        if envelope.type is MessageType.TASK_RESULT:
            self._log(f"task {envelope.payload.get('task_id')}: {envelope.payload.get('status')}")
            return

    def _handle_task(self, envelope: Envelope) -> None:
        payload = envelope.payload
        task_id = str(payload.get("task_id", ""))
        task_type = str(payload.get("task_type", ""))
        device_id = self.identity.device_id

        if task_type == "transfer_file":
            self._handle_transfer(envelope, task_id)
            return

        snapshot = system_snapshot("online")
        subsets = {
            "system_info": ["hostname", "os_name", "os_version", "python_version", "private_ips"],
            "cpu_ram": ["cpu_percent", "cpu_cores_logical", "memory_total_gb", "memory_used_gb"],
            "disk": ["disk_total_gb", "disk_free_gb"],
            "network": ["network_interfaces"],
            "agent_status": ["agent_status", "uptime_seconds"],
        }
        keys = subsets.get(task_type)
        if keys is None:
            self.connection.send(
                make_envelope(
                    MessageType.TASK_RESULT,
                    device_id,
                    {"task_id": task_id, "status": "failed", "result": {"error": "task di luar allowlist"}},
                )
            )
            return
        result = {key: snapshot[key] for key in keys}
        self.connection.send(
            make_envelope(
                MessageType.TASK_RESULT,
                device_id,
                {"task_id": task_id, "status": "completed", "result": result},
            )
        )
        self._log(f"task selesai: {task_type}")

    def _handle_transfer(self, envelope: Envelope, task_id: str) -> None:
        device_id = self.identity.device_id
        file_id = str(envelope.payload.get("file_id", ""))
        record = self.vault.get_record(file_id)
        if not record:
            self.connection.send(
                make_envelope(
                    MessageType.TASK_RESULT,
                    device_id,
                    {"task_id": task_id, "status": "failed", "result": {"error": "file tidak ada"}},
                )
            )
            return

        approved = messagebox.askyesno(
            "Persetujuan lokal",
            f"Server meminta transfer salinan terenkripsi:\n\n{record.file_name}\n\nSetuju?",
        )
        if not approved:
            self.connection.send(
                make_envelope(
                    MessageType.TASK_RESULT,
                    device_id,
                    {"task_id": task_id, "status": "rejected", "result": {"reason": "ditolak pengguna"}},
                )
            )
            self._log(f"transfer ditolak pengguna: {record.file_name}")
            return

        chunk_size = int(self.settings.get("chunk_size_bytes", 262144))
        source = Path(record.protected_path)
        total_chunks = max(1, math.ceil(source.stat().st_size / chunk_size))
        sent = 0
        with source.open("rb") as handle:
            for index in range(total_chunks):
                data = handle.read(chunk_size)
                chunk_envelope = make_envelope(
                    MessageType.FILE_CHUNK,
                    device_id,
                    {
                        "task_id": task_id,
                        "file_id": file_id,
                        "file_name": record.file_name,
                        "chunk_index": index,
                        "total_chunks": total_chunks,
                        "data_b64": base64.b64encode(data).decode("ascii"),
                    },
                    request_id=f"{envelope.request_id}-chunk-{index}",
                )
                if not self.connection.send(chunk_envelope):
                    self.connection.send(
                        make_envelope(
                            MessageType.TASK_RESULT,
                            device_id,
                            {"task_id": task_id, "status": "failed", "result": {"error": "chunk gagal"}},
                        )
                    )
                    return
                sent += len(data)

        self.connection.send(
            make_envelope(
                MessageType.TASK_RESULT,
                device_id,
                {
                    "task_id": task_id,
                    "status": "completed",
                    "result": {
                        "file_name": record.file_name,
                        "transferred_bytes": sent,
                        "note": "hanya salinan terenkripsi yang dikirim",
                    },
                },
            )
        )
        self._log(f"transfer selesai: {record.file_name} ({sent} byte ciphertext)")

    # ---------- helpers ----------

    def _refresh_device(self) -> None:
        identity = device_identity()
        self.device_labels["hostname"].configure(text=identity.hostname)
        self.device_labels["os"].configure(text=f"{identity.os_name} {identity.os_version}")
        self.device_labels["python"].configure(text=identity.python_version)
        self.device_labels["ips"].configure(text=", ".join(identity.private_ips))
        self.device_labels["agent"].configure(text=identity.agent_version)
        self.device_labels["status"].configure(text=self._status)

    def _log(self, message: str) -> None:
        from shared.models import utcnow

        line = f"[{utcnow().strftime('%Y-%m-%d %H:%M:%S')}] {message}"
        self.activity_text.configure(state="normal")
        self.activity_text.insert("end", line + "\n")
        self.activity_text.configure(state="disabled")
        self._refresh_unlock_text()

    def _refresh_activity(self) -> None:
        events = self.vault.list_events(200)
        lines = [f"[{e['ts']}] {e['action']} — {e['detail']}" for e in events]
        self._set_text(self.activity_text, "\n".join(lines) or "Belum ada aktivitas.")

    def on_close(self) -> None:
        if getattr(self, "_after_id", None):
            self.after_cancel(self._after_id)
        self.connection.stop()
        self.update_idletasks()
        self.destroy()
