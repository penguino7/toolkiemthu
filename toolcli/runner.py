from __future__ import annotations

import os
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import List


@dataclass
class RunResult:
    """Kết quả sau khi launcher chạy một command."""

    return_code: int
    log_path: Path


class LiveCommandRunner:
    """Chạy command và in log realtime ra terminal.

    Class này chỉ là lớp bọc ngoài CLI hiện có. Nó không biết logic recon/fuzz,
    chỉ nhận command, chạy subprocess, rồi stream stdout/stderr từng dòng.
    """

    def __init__(self, project_root: Path | None = None, logs_dir: str = "runs") -> None:
        self.project_root = project_root or Path(__file__).resolve().parents[1]
        self.logs_dir = self.project_root / logs_dir

    def run_python_module(self, title: str, module: str, args: List[str]) -> RunResult:
        command = [str(self.python_bin()), "-u", "-B", "-m", module, *args]
        return self.run_command(title, command)

    def run_command(self, title: str, command: List[str]) -> RunResult:
        self.logs_dir.mkdir(parents=True, exist_ok=True)
        log_path = self.logs_dir / f"{self._timestamp()}-{self._safe_name(title)}.log"

        env = dict(os.environ)
        env["PYTHONUNBUFFERED"] = "1"
        env["PYTHONIOENCODING"] = "utf-8"

        self._print_header(title, command, log_path)
        with log_path.open("w", encoding="utf-8") as log_file:
            process = subprocess.Popen(
                command,
                cwd=self.project_root,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
            )

            assert process.stdout is not None
            for line in process.stdout:
                print(line, end="")
                log_file.write(line)
                log_file.flush()

            return_code = process.wait()

        print(f"\n[+] Exit code: {return_code}")
        print(f"[+] Log file: {log_path}")
        return RunResult(return_code=return_code, log_path=log_path)

    def python_bin(self) -> Path:
        candidates = [
            self.project_root / ".venv" / "bin" / "python",
            self.project_root / ".venv" / "Scripts" / "python.exe",
        ]
        for candidate in candidates:
            if candidate.exists():
                return candidate
        return Path(sys.executable)

    def _print_header(self, title: str, command: List[str], log_path: Path) -> None:
        print("")
        print("=" * 72)
        print(f"[RUN] {title}")
        print(f"[CMD] {' '.join(command)}")
        print(f"[LOG] {log_path}")
        print("=" * 72)

    def _timestamp(self) -> str:
        return datetime.now().strftime("%Y%m%d-%H%M%S")

    def _safe_name(self, value: str) -> str:
        safe = "".join(ch if ch.isalnum() else "-" for ch in value.lower())
        return "-".join(part for part in safe.split("-") if part) or "run"

