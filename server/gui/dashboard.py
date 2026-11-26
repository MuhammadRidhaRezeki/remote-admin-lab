"""CustomTkinter administration dashboard for the remote administration lab."""

from __future__ import annotations

from typing import Any

import customtkinter as ctk
import requests

from server.config import CERT_DIR, ServerConfig
from shared.models import TASK_ALLOWLIST

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

ACCENT = "#38bdf8"
MUTED = "#94a3b8"


class AdminClient:
    def __init__(self, base_url: str, ca_cert: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.ca_cert = ca_cert
        self.token: str | None = None

    @property
    def headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token}"} if self.token else {}

    def request(
        self, method: str, path: str, payload: dict[str, Any] | None = None
    ) -> Any:
        verify: str | bool = self.ca_cert if self.ca_cert else True
        response = requests.request(
            method,
            self.base_url + path,
            json=payload,
            headers=self.headers,
            verify=verify,
            timeout=12,
        )
        response.raise_for_status()
        return response.json() if response.content else None

    def login(self, username: str, password: str) -> None:
        data = self.request("POST", "/admin/login", {"username": username, "password": password})
        self.token = data["access_token"]


class ServerDashboard(ctk.CTk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Remote Administration Lab — Server")
        self.geometry("1280x800")
        self.minsize(1080, 700)
        self.api: AdminClient | None = None
        self.poll_enabled = False
        self._poll_after_id: str | None = None
        self.frames: dict[str, ctk.CTkFrame] = {}
        self.nav_buttons: dict[str, ctk.CTkButton] = {}
        self._build_login()

    # ---------- login ----------

    def _build_login(self) -> None:
        self.login_frame = ctk.CTkFrame(self, width=520, height=520, corner_radius=18)
        self.login_frame.place(relx=0.5, rely=0.5, anchor="center")
        ctk.CTkLabel(
            self.login_frame,
            text="REMOTE ADMIN LAB\nSERVER CONSOLE",
            font=("Segoe UI", 24, "bold"),
            text_color=ACCENT,
            justify="left",
        ).pack(padx=36, pady=(40, 28), anchor="w")

        self.login_entries: dict[str, ctk.CTkEntry] = {}
        config = ServerConfig.load()
        login_host = "127.0.0.1" if config.host in {"0.0.0.0", "::"} else config.host
        fields = [
            ("base_url", "Server URL", f"https://{login_host}:{config.port}", False),
            ("ca_cert", "CA certificate", str(CERT_DIR / "server.crt"), False),
            ("username", "Username", config.admin_username, False),
            ("password", "Password", "", True),
        ]
        for key, label, default, secret in fields:
            ctk.CTkLabel(self.login_frame, text=label, font=("Segoe UI", 13)).pack(
                padx=36, anchor="w"
            )
            entry = ctk.CTkEntry(self.login_frame, height=38, show="*" if secret else "")
            entry.insert(0, default)
            entry.pack(padx=36, pady=(6, 14), fill="x")
            self.login_entries[key] = entry

        self.login_error = ctk.CTkLabel(
            self.login_frame, text="", text_color="#f87171", font=("Segoe UI", 12)
        )
        self.login_error.pack(padx=36, anchor="w")
        ctk.CTkButton(
            self.login_frame, text="Masuk", height=40, command=self._login
        ).pack(padx=36, pady=24, fill="x")

    def _login(self) -> None:
        values = {key: entry.get().strip() for key, entry in self.login_entries.items()}
        api = AdminClient(values["base_url"], values["ca_cert"])
        try:
            api.login(values["username"], values["password"])
        except Exception as exc:
            self.login_error.configure(text=f"Login gagal: {exc}")
            return
        self.api = api
        self.login_frame.destroy()
        self._build_shell()
        self._poll()
        self.poll_enabled = True

    # ---------- shell ----------

    def _build_shell(self) -> None:
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.sidebar = ctk.CTkFrame(self, width=236, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsw")
        self.sidebar.grid_rowconfigure(20, weight=1)

        self.content = ctk.CTkFrame(self, corner_radius=0, fg_color=("#0f172a", "#0b1220"))
        self.content.grid(row=0, column=1, sticky="nsew")
        self.content.grid_columnconfigure(0, weight=1)
        self.content.grid_rowconfigure(1, weight=1)

        ctk.CTkLabel(
            self.sidebar,
            text="CONTROL PLANE\nREMOTE ADMIN LAB",
            font=("Segoe UI", 16, "bold"),
            text_color=ACCENT,
            justify="left",
        ).grid(row=0, column=0, padx=20, pady=(24, 22), sticky="w")

        nav = [
            ("dashboard", "Dashboard"),
            ("clients", "Connected Clients"),
            ("tasks", "Task Management"),
            ("files", "File Protection Requests"),
            ("audit", "Audit Logs"),
            ("settings", "Settings"),
        ]
        for index, (key, label) in enumerate(nav, start=1):
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
            text="akses hanya dengan\nakun admin tunggal",
            font=("Segoe UI", 11),
            text_color=MUTED,
            justify="left",
        ).grid(row=20, column=0, padx=20, pady=18, sticky="sw")

        header = ctk.CTkFrame(self.content, height=64, corner_radius=14)
        header.grid(row=0, column=0, sticky="ew", padx=24, pady=(22, 12))
        header.grid_columnconfigure(1, weight=1)
        self.status_label = ctk.CTkLabel(
            header, text="● siap", font=("Segoe UI", 13), text_color=ACCENT
        )
        self.status_label.grid(row=0, column=0, padx=18, sticky="w")
        ctk.CTkButton(header, text="Refresh", width=90, command=self._poll).grid(
            row=0, column=1, padx=6, pady=12, sticky="e"
        )
        ctk.CTkButton(
            header, text="Logout", width=90, fg_color="#475569", command=self._logout
        ).grid(row=0, column=2, padx=(6, 18), pady=12)

        self.frame_host = ctk.CTkFrame(self.content, fg_color="transparent")
        self.frame_host.grid(row=1, column=0, sticky="nsew", padx=24, pady=(0, 24))
        self.frame_host.grid_columnconfigure(0, weight=1)
        self.frame_host.grid_rowconfigure(0, weight=1)

        self.frames = {
            "dashboard": self._dashboard_frame(),
            "clients": self._clients_frame(),
            "tasks": self._tasks_frame(),
            "files": self._files_frame(),
            "audit": self._audit_frame(),
            "settings": self._settings_frame(),
        }
        self.show_frame("dashboard")

    def show_frame(self, name: str) -> None:
        for frame in self.frames.values():
            frame.grid_forget()
        self.frames[name].grid(row=0, column=0, sticky="nsew")
        for button in self.nav_buttons.values():
            button.configure(fg_color="transparent", text_color=MUTED)
        self.nav_buttons[name].configure(fg_color=("#1d4ed8", "#1e40af"), text_color="#ffffff")

    @staticmethod
    def _set_text(widget: ctk.CTkTextbox, text: str) -> None:
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", text)
        widget.configure(state="disabled")

    # ---------- sections ----------

    def _dashboard_frame(self) -> ctk.CTkFrame:
        frame = ctk.CTkFrame(self.frame_host)
        frame.grid_columnconfigure((0, 1, 2, 3), weight=1)
        ctk.CTkLabel(
            frame, text="Dashboard", font=("Segoe UI", 20, "bold")
        ).grid(row=0, column=0, columnspan=4, padx=24, pady=(22, 18), sticky="w")
        self.summary_cards: dict[str, ctk.CTkLabel] = {}
        cards = [
            ("online", "Client online"),
            ("tasks", "Task pending"),
            ("unlocks", "Unlock pending"),
            ("audit", "Audit chain"),
        ]
        for index, (key, label) in enumerate(cards):
            card = ctk.CTkFrame(frame, height=132, corner_radius=14)
            card.grid(row=1, column=index, padx=12, pady=8, sticky="nsew")
            ctk.CTkLabel(card, text=label, font=("Segoe UI", 13), text_color=MUTED).pack(
                padx=18, pady=(20, 8), anchor="w"
            )
            value = ctk.CTkLabel(card, text="-", font=("Segoe UI", 30, "bold"), text_color=ACCENT)
            value.pack(padx=18, anchor="w")
            self.summary_cards[key] = value

        ctk.CTkLabel(
            frame,
            text="Operasi administratif dibatasi allowlist. Setiap aksi sensitif membutuhkan persetujuan admin dan konfirmasi lokal client.",
            font=("Segoe UI", 13),
            text_color=MUTED,
            wraplength=900,
            justify="left",
        ).grid(row=2, column=0, columnspan=4, padx=24, pady=28, sticky="w")
        return frame

    def _clients_frame(self) -> ctk.CTkFrame:
        frame = ctk.CTkFrame(self.frame_host)
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(1, weight=1)
        ctk.CTkLabel(
            frame, text="Connected Clients", font=("Segoe UI", 20, "bold")
        ).grid(row=0, column=0, padx=20, pady=(20, 12), sticky="w")
        self.clients_text = ctk.CTkTextbox(frame)
        self.clients_text.grid(row=1, column=0, padx=20, pady=(0, 20), sticky="nsew")
        return frame

    def _tasks_frame(self) -> ctk.CTkFrame:
        frame = ctk.CTkFrame(self.frame_host)
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(3, weight=1)
        ctk.CTkLabel(
            frame, text="Task Management", font=("Segoe UI", 20, "bold")
        ).grid(row=0, column=0, columnspan=4, padx=20, pady=(20, 12), sticky="w")

        self.task_client_combo = ctk.CTkComboBox(frame, values=["-"], width=240)
        self.task_client_combo.set("-")
        self.task_client_combo.grid(row=1, column=0, padx=20, pady=8, sticky="w")
        self.task_type_combo = ctk.CTkComboBox(frame, values=sorted(TASK_ALLOWLIST), width=180)
        self.task_type_combo.set("system_info")
        self.task_type_combo.grid(row=1, column=1, padx=8, pady=8, sticky="w")
        self.task_file_entry = ctk.CTkEntry(frame, width=180, placeholder_text="file_id (transfer)")
        self.task_file_entry.grid(row=1, column=2, padx=8, pady=8, sticky="w")
        self.task_reason_entry = ctk.CTkEntry(frame, placeholder_text="alasan")
        self.task_reason_entry.grid(row=1, column=3, padx=(8, 20), pady=8, sticky="ew")
        ctk.CTkButton(frame, text="Buat Task", command=self._create_task).grid(
            row=2, column=0, padx=20, pady=8, sticky="w"
        )

        self.task_id_entry = ctk.CTkEntry(frame, width=260, placeholder_text="task_id untuk keputusan")
        self.task_id_entry.grid(row=2, column=1, columnspan=2, padx=8, pady=8, sticky="w")
        ctk.CTkButton(
            frame, text="Approve", fg_color="#0f766e", command=lambda: self._decide_task("approved")
        ).grid(row=2, column=3, padx=(8, 100), pady=8, sticky="w")
        ctk.CTkButton(
            frame, text="Reject", fg_color="#7f1d1d", command=lambda: self._decide_task("rejected")
        ).grid(row=2, column=3, padx=(196, 20), pady=8, sticky="w")

        self.tasks_text = ctk.CTkTextbox(frame)
        self.tasks_text.grid(row=3, column=0, columnspan=4, padx=20, pady=(8, 20), sticky="nsew")
        return frame

    def _files_frame(self) -> ctk.CTkFrame:
        frame = ctk.CTkFrame(self.frame_host)
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_columnconfigure(1, weight=1)
        frame.grid_rowconfigure(3, weight=1)
        ctk.CTkLabel(
            frame, text="File Protection Requests", font=("Segoe UI", 20, "bold")
        ).grid(row=0, column=0, columnspan=2, padx=20, pady=(20, 12), sticky="w")

        self.files_text = ctk.CTkTextbox(frame)
        self.files_text.grid(row=1, column=0, padx=20, pady=6, sticky="nsew")
        self.unlock_text = ctk.CTkTextbox(frame)
        self.unlock_text.grid(row=1, column=1, padx=20, pady=6, sticky="nsew")

        self.unlock_combo = ctk.CTkComboBox(frame, values=["-"], width=280)
        self.unlock_combo.set("-")
        self.unlock_combo.grid(row=2, column=1, padx=20, pady=8, sticky="w")
        ctk.CTkButton(
            frame, text="Approve", fg_color="#0f766e",
            command=lambda: self._decide_unlock("approved"),
        ).grid(row=2, column=0, padx=20, pady=8, sticky="w")
        ctk.CTkButton(
            frame, text="Reject", fg_color="#7f1d1d",
            command=lambda: self._decide_unlock("rejected"),
        ).grid(row=2, column=0, padx=118, pady=8, sticky="w")

        self.file_metadata_text = ctk.CTkTextbox(frame, height=80)
        self.file_metadata_text.grid(
            row=3, column=0, columnspan=2, padx=20, pady=(8, 20), sticky="nsew"
        )
        return frame

    def _audit_frame(self) -> ctk.CTkFrame:
        frame = ctk.CTkFrame(self.frame_host)
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(2, weight=1)
        ctk.CTkLabel(frame, text="Audit Logs", font=("Segoe UI", 20, "bold")).grid(
            row=0, column=0, padx=20, pady=(20, 12), sticky="w"
        )
        self.chain_label = ctk.CTkLabel(frame, text="chain: -", text_color=MUTED)
        self.chain_label.grid(row=1, column=0, padx=20, pady=6, sticky="w")
        self.audit_text = ctk.CTkTextbox(frame)
        self.audit_text.grid(row=2, column=0, padx=20, pady=(0, 20), sticky="nsew")
        return frame

    def _settings_frame(self) -> ctk.CTkFrame:
        frame = ctk.CTkFrame(self.frame_host)
        frame.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(frame, text="Settings", font=("Segoe UI", 20, "bold")).grid(
            row=0, column=0, columnspan=2, padx=20, pady=(20, 14), sticky="w"
        )
        ctk.CTkLabel(
            frame,
            text="Kata sandi admin disimpan sebagai PBKDF2-SHA256. Enrollment code client diverifikasi sebagai hash.",
            font=("Segoe UI", 12),
            text_color=MUTED,
            wraplength=720,
            justify="left",
        ).grid(row=1, column=0, columnspan=2, padx=20, pady=(0, 18), sticky="w")

        self.password_entries: dict[str, ctk.CTkEntry] = {}
        for index, (key, label) in enumerate(
            [("current", "Kata sandi saat ini"), ("new", "Kata sandi baru (min. 12)")], start=2
        ):
            ctk.CTkLabel(frame, text=label, font=("Segoe UI", 13)).grid(
                row=index, column=0, padx=20, pady=10, sticky="w"
            )
            entry = ctk.CTkEntry(frame, height=36, show="*")
            entry.grid(row=index, column=1, padx=20, pady=10, sticky="ew")
            self.password_entries[key] = entry
        ctk.CTkButton(frame, text="Ganti Kata Sandi", command=self._change_password).grid(
            row=4, column=1, padx=20, pady=20, sticky="w"
        )
        return frame

    # ---------- polling and actions ----------

    def _poll(self) -> None:
        if self.api is None:
            return
        try:
            summary = self.api.request("GET", "/admin/summary")
            clients = self.api.request("GET", "/admin/clients")
            tasks = self.api.request("GET", "/admin/tasks")
            unlocks = self.api.request("GET", "/admin/unlock-requests")
            files = self.api.request("GET", "/admin/file-records")
            audit = self.api.request("GET", "/admin/audit-logs?limit=120")

            self.summary_cards["online"].configure(text=str(summary["clients_online"]))
            self.summary_cards["tasks"].configure(text=str(summary["tasks_pending"]))
            self.summary_cards["unlocks"].configure(text=str(summary["unlocks_pending"]))
            self.summary_cards["audit"].configure(
                text="valid" if summary["audit_chain_valid"] else "RUSAK"
            )
            self.status_label.configure(text="● tersinkron", text_color=ACCENT)

            self._set_text(
                self.clients_text,
                "\n\n".join(
                    f"{c['client_id']}  |  {c['hostname']}  |  {c['status']}  |  "
                    f"{c['os_name']} {c['os_version']}  |  py {c['python_version']}\n"
                    f"    IP: {', '.join(c['private_ips'])}  |  last seen: {c['last_seen']}"
                    for c in clients
                ) or "Belum ada client terdaftar.",
            )
            client_values = [c["client_id"] for c in clients] or ["-"]
            self.task_client_combo.configure(values=client_values)
            if client_values and self.task_client_combo.get() not in client_values:
                self.task_client_combo.set(client_values[0])

            self._set_text(
                self.tasks_text,
                "\n".join(
                    f"{t['task_id']}  |  {t['client_id']}  |  {t['task_type']}  |  "
                    f"{t['status']}  |  {t['created_at']}"
                    for t in tasks
                ) or "Belum ada task.",
            )

            self._set_text(
                self.files_text,
                "\n".join(
                    f"{f['file_id']}  |  {f['file_name']}  |  {f['client_id']}  |  {f['status']}"
                    for f in files
                ) or "Belum ada file terlindungi.",
            )
            self._set_text(
                self.unlock_text,
                "\n".join(
                    f"{u['request_id']}  |  {u['file_name'] or u['file_id']}  |  "
                    f"{u['status']}  |  {u['reason']}"
                    for u in unlocks
                ) or "Belum ada permintaan pembukaan.",
            )
            unlock_values = [u["request_id"] for u in unlocks] or ["-"]
            self.unlock_combo.configure(values=unlock_values)
            if unlock_values and self.unlock_combo.get() not in unlock_values:
                self.unlock_combo.set(unlock_values[0])

            self.chain_label.configure(
                text=f"chain: {'valid' if audit['chain_valid'] else 'RUSAK'}",
                text_color=ACCENT if audit["chain_valid"] else "#f87171",
            )
            self._set_text(
                self.audit_text,
                "\n".join(
                    f"[{e['ts']}] {e['actor_type']}:{e['actor_id']} — {e['action']} "
                    f"({e['target_type'] or '-'}/{e['target_id'] or '-'})"
                    for e in audit["events"]
                ) or "Belum ada event audit.",
            )
        except Exception as exc:
            self.status_label.configure(text=f"● error: {str(exc)[:70]}", text_color="#f59e0b")

        if self.poll_enabled:
            self._poll_after_id = self.after(3000, self._poll)

    def _create_task(self) -> None:
        if self.api is None:
            return
        client_id = self.task_client_combo.get().strip()
        if client_id in {"", "-"}:
            return
        payload: dict[str, Any] = {
            "client_id": client_id,
            "task_type": self.task_type_combo.get().strip(),
            "reason": self.task_reason_entry.get().strip() or None,
        }
        file_id = self.task_file_entry.get().strip()
        if file_id:
            payload["file_id"] = file_id
        try:
            result = self.api.request("POST", "/admin/tasks", payload)
            self.task_id_entry.delete(0, "end")
            self.task_id_entry.insert(0, result["task_id"])
        except Exception as exc:
            self.status_label.configure(text=f"● task gagal: {str(exc)[:70]}", text_color="#f87171")
        self._poll()

    def _decide_task(self, decision: str) -> None:
        task_id = self.task_id_entry.get().strip()
        if not task_id or self.api is None:
            return
        try:
            self.api.request(
                "POST", f"/admin/tasks/{task_id}/decision", {"decision": decision}
            )
        except Exception as exc:
            self.status_label.configure(text=f"● keputusan gagal: {str(exc)[:60]}", text_color="#f87171")
        self._poll()

    def _decide_unlock(self, decision: str) -> None:
        request_id = self.unlock_combo.get().strip()
        if request_id in {"", "-"} or self.api is None:
            return
        try:
            self.api.request(
                "POST",
                f"/admin/unlock-requests/{request_id}/decision",
                {"decision": decision},
            )
        except Exception as exc:
            self.status_label.configure(text=f"● keputusan gagal: {str(exc)[:60]}", text_color="#f87171")
        self._poll()

    def _change_password(self) -> None:
        if self.api is None:
            return
        try:
            self.api.request(
                "POST",
                "/admin/change-password",
                {
                    "current_password": self.password_entries["current"].get(),
                    "new_password": self.password_entries["new"].get(),
                },
            )
            for entry in self.password_entries.values():
                entry.delete(0, "end")
            self.status_label.configure(text="● kata sandi diperbarui", text_color=ACCENT)
        except Exception as exc:
            self.status_label.configure(text=f"● gagal: {str(exc)[:70]}", text_color="#f87171")

    def _logout(self) -> None:
        self.poll_enabled = False
        if self._poll_after_id:
            self.after_cancel(self._poll_after_id)
            self._poll_after_id = None
        if self.api:
            self.api.token = None
        for widget in self.winfo_children():
            widget.destroy()
        self.api = None
        self.frames.clear()
        self.nav_buttons.clear()
        self._build_login()
