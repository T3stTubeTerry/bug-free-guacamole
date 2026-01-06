from __future__ import annotations

import json
import queue
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from aegismeta import __app_name__, __version__
from aegismeta.core.anomaly import ExtensionMagicMismatchRule, IsolationForestRule, TimestampInconsistencyRule, ZScoreOutlierRule
from aegismeta.core.case_service import CaseService
from aegismeta.core.extraction_service import AnomalyService, ExtractionService
from aegismeta.core.security import AccessController
from aegismeta.core.timeline import ingest_file_events
from aegismeta.infra import db
from aegismeta.infra.logging_utils import LOGGER
from aegismeta.plugins.base import PluginRegistry
from aegismeta.plugins.generic_signature_checker import GenericSignatureChecker
from aegismeta.plugins.image_exif_extractor import ImageExifExtractor
from aegismeta.plugins.pdf_metadata_extractor import PdfMetadataExtractor
from aegismeta.reports.html_report import generate_html_report


class AppState:
    def __init__(self) -> None:
        self.case_service = CaseService(Path.home() / "aegismeta_cases")
        self.registry = PluginRegistry()
        self.registry.register(ImageExifExtractor())
        self.registry.register(PdfMetadataExtractor())
        self.registry.register(GenericSignatureChecker())
        self.extraction_service = ExtractionService(self.registry)
        self.anomaly_service = AnomalyService(
            [
                TimestampInconsistencyRule(),
                ExtensionMagicMismatchRule(),
                ZScoreOutlierRule("magic_extension"),
                IsolationForestRule("entropy"),
            ]
        )
        self.case_db: db.CaseDatabase | None = None
        self.online_mode = False
        self.rbac = AccessController()


class AegisMetaApp(ttk.Frame):
    def __init__(self, master: tk.Tk, state: AppState) -> None:
        super().__init__(master)
        self.state = state
        self.master.title(__app_name__)
        self.master.geometry("1100x720")
        self.master.protocol("WM_DELETE_WINDOW", self.on_close)
        self.task_queue: queue.Queue = queue.Queue()
        self._build_layout()
        self._poll_queue()

    def _build_layout(self) -> None:
        self.pack(fill=tk.BOTH, expand=True)
        container = ttk.PanedWindow(self, orient=tk.HORIZONTAL)
        container.pack(fill=tk.BOTH, expand=True)

        nav_frame = ttk.Frame(container, width=200)
        nav_frame.pack_propagate(False)
        container.add(nav_frame)

        self.main_frame = ttk.Frame(container)
        container.add(self.main_frame, weight=1)

        sections = [
            "Case",
            "Evidence",
            "Extract",
            "Timeline",
            "Graph",
            "Anomalies",
            "Report",
            "Settings",
            "Logs",
        ]
        self.section_frames: dict[str, ttk.Frame] = {}
        for name in sections:
            btn = ttk.Button(nav_frame, text=name, command=lambda n=name: self._show_section(n))
            btn.pack(fill=tk.X, padx=8, pady=4)
            frame = ttk.Frame(self.main_frame)
            self.section_frames[name] = frame

        self._build_case_section()
        self._build_evidence_section()
        self._build_extract_section()
        self._build_report_section()
        self._build_settings_section()
        self._build_logs_section()
        self._show_section("Case")

    def _show_section(self, name: str) -> None:
        for frame in self.section_frames.values():
            frame.pack_forget()
        frame = self.section_frames[name]
        frame.pack(fill=tk.BOTH, expand=True)

    def _build_case_section(self) -> None:
        frame = self.section_frames["Case"]
        ttk.Label(frame, text=f"{__app_name__} v{__version__}", font=("Segoe UI", 16, "bold")).pack(pady=10)
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(pady=10)
        ttk.Button(btn_frame, text="Create Case", command=self._create_case).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Open Case", command=self._open_case).pack(side=tk.LEFT, padx=5)
        self.case_label = ttk.Label(frame, text="No case loaded")
        self.case_label.pack(pady=6)

    def _build_evidence_section(self) -> None:
        frame = self.section_frames["Evidence"]
        ttk.Button(frame, text="Add Evidence", command=self._add_evidence).pack(pady=6)
        self.evidence_tree = ttk.Treeview(frame, columns=("name", "path", "sha256"), show="headings")
        for col in ("name", "path", "sha256"):
            self.evidence_tree.heading(col, text=col)
            self.evidence_tree.column(col, width=200)
        self.evidence_tree.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)

    def _build_extract_section(self) -> None:
        frame = self.section_frames["Extract"]
        ttk.Button(frame, text="Run Extraction", command=self._run_extraction).pack(pady=6)
        self.metadata_view = tk.Text(frame, height=20)
        self.metadata_view.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)

    def _build_report_section(self) -> None:
        frame = self.section_frames["Report"]
        ttk.Button(frame, text="Generate HTML Report", command=self._generate_report).pack(pady=6)
        self.report_preview = tk.Text(frame, height=25)
        self.report_preview.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)

    def _build_settings_section(self) -> None:
        frame = self.section_frames["Settings"]
        self.online_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(frame, text="Online mode (disabled by default)", variable=self.online_var, command=self._toggle_online).pack(pady=6)
        ttk.Label(frame, text="RBAC Roles available locally: Investigator, Analyst, Admin").pack(pady=6)
        ttk.Label(frame, text="Current role").pack()
        self.role_var = tk.StringVar(value=self.state.rbac.role)
        role_combo = ttk.Combobox(frame, textvariable=self.role_var, values=["Investigator", "Analyst", "Admin"], state="readonly")
        role_combo.pack(pady=4)
        role_combo.bind("<<ComboboxSelected>>", lambda e: self._change_role())

    def _build_logs_section(self) -> None:
        frame = self.section_frames["Logs"]
        self.log_console = tk.Text(frame, height=30)
        self.log_console.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)

    def _create_case(self) -> None:
        if not self.state.rbac.check("create_case"):
            messagebox.showerror("Access denied", "Current role cannot create cases")
            return
        name = simple_input(self.master, "Case Name")
        if not name:
            return
        investigator = simple_input(self.master, "Investigator") or ""
        notes = simple_input(self.master, "Notes") or ""
        bundle = self.state.case_service.create_case(name=name, investigator=investigator, notes=notes)
        self.state.case_db = db.CaseDatabase(bundle.db_path, case_id=bundle.case_id)
        self.case_label.config(text=f"Current case: {name}")
        self._append_log({"event": "case_created", "name": name})

    def _open_case(self) -> None:
        if not self.state.rbac.check("open_case"):
            messagebox.showerror("Access denied", "Current role cannot open cases")
            return
        path = filedialog.askdirectory(title="Select case bundle")
        if not path:
            return
        bundle = self.state.case_service.open_case(Path(path))
        self.state.case_db = db.CaseDatabase(bundle.db_path, case_id=bundle.case_id)
        self.case_label.config(text=f"Current case: {bundle.path.name}")
        self._load_evidence()
        self._append_log({"event": "case_opened", "path": path})

    def _add_evidence(self) -> None:
        if not self.state.rbac.check("add_evidence"):
            messagebox.showerror("Access denied", "Current role cannot add evidence")
            return
        if not self.state.case_db:
            messagebox.showerror("No case", "Open or create a case first")
            return
        path = filedialog.askopenfilename(title="Add evidence")
        if not path:
            return
        logical_name = Path(path).name
        evidence_id = self.state.case_service.add_evidence(Path(path), logical_name=logical_name)
        self._append_log({"event": "evidence_added", "id": evidence_id})
        self._load_evidence()

    def _load_evidence(self) -> None:
        if not self.state.case_db:
            return
        for row in self.evidence_tree.get_children():
            self.evidence_tree.delete(row)
        conn = self.state.case_db.conn
        items = db.fetch_evidence_items(conn, self.state.case_db.case_id or 1)
        for item in items:
            self.evidence_tree.insert("", tk.END, values=(item["logical_name"], item["path"], item["sha256"]))

    def _run_extraction(self) -> None:
        if not self.state.rbac.check("run_extraction"):
            messagebox.showerror("Access denied", "Current role cannot run extraction")
            return
        if not self.state.case_db:
            messagebox.showerror("No case", "Open or create a case first")
            return
        conn = self.state.case_db.conn
        evidence = db.fetch_evidence_items(conn, self.state.case_db.case_id or 1)
        if not evidence:
            messagebox.showinfo("No evidence", "Add evidence to extract")
            return
        self.metadata_view.delete("1.0", tk.END)
        threading.Thread(target=self._execute_extraction, args=(list(evidence),), daemon=True).start()

    def _execute_extraction(self, evidence) -> None:
        for item in evidence:
            derived = self.state.extraction_service.run(self.state.case_db, item["id"], Path(item["path"]))
            ingest_file_events(self.state.case_db.conn, item["case_id"], item["id"], Path(item["path"]))
            self.task_queue.put({"type": "metadata", "data": [f"{d.key}: {d.value}" for d in derived]})
        self.state.anomaly_service.evaluate(self.state.case_db, self.state.case_db.case_id or 1)

    def _generate_report(self) -> None:
        if not self.state.rbac.check("generate_report"):
            messagebox.showerror("Access denied", "Current role cannot generate reports")
            return
        if not self.state.case_db:
            messagebox.showerror("No case", "Open or create a case first")
            return
        output = self.state.case_db.path.parent / "reports" / f"case_{self.state.case_db.case_id}.html"
        generate_html_report(self.state.case_db, output)
        self.report_preview.delete("1.0", tk.END)
        self.report_preview.insert(tk.END, output.read_text()[:5000])
        self._append_log({"event": "report_generated", "path": str(output)})

    def _toggle_online(self) -> None:
        self.state.online_mode = bool(self.online_var.get())
        self._append_log({"event": "online_mode", "enabled": self.state.online_mode})

    def _change_role(self) -> None:
        self.state.rbac.set_role(self.role_var.get())
        self._append_log({"event": "role_changed", "role": self.state.rbac.role})

    def _append_log(self, payload: dict) -> None:
        self.log_console.insert(tk.END, json.dumps(payload) + "\n")
        self.log_console.see(tk.END)

    def _poll_queue(self) -> None:
        try:
            while True:
                item = self.task_queue.get_nowait()
                if item["type"] == "metadata":
                    for line in item["data"]:
                        self.metadata_view.insert(tk.END, line + "\n")
        except queue.Empty:
            pass
        self.after(200, self._poll_queue)

    def on_close(self) -> None:
        if self.state.case_db:
            self.state.case_db.close()
        self.master.destroy()


def simple_input(master: tk.Tk, prompt: str) -> str | None:
    dialog = tk.Toplevel(master)
    dialog.title(prompt)
    ttk.Label(dialog, text=prompt).pack(pady=4)
    entry = ttk.Entry(dialog)
    entry.pack(padx=6, pady=4)
    entry.focus()
    value: list[str | None] = [None]

    def submit() -> None:
        value[0] = entry.get()
        dialog.destroy()

    ttk.Button(dialog, text="OK", command=submit).pack(pady=4)
    master.wait_window(dialog)
    return value[0]


def run_app() -> None:
    root = tk.Tk()
    state = AppState()
    app = AegisMetaApp(root, state)
    app.mainloop()
