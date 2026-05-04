from __future__ import annotations

import os
import shutil
import signal
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(slots=True)
class ObserverConfig:
    pid: int | None = None
    program_path: str | None = None
    executable: str = "bpftrace"
    command: list[str] | None = None
    output_path: str | None = None
    duration_seconds: float | None = None
    max_events: int | None = None
    env: dict[str, str] = field(default_factory=dict)

    def build_command(self) -> list[str]:
        if self.command:
            return list(self.command)
        if self.pid is None or self.program_path is None:
            raise ValueError("pid and program_path are required when no explicit command is provided.")
        return [self.executable, self.program_path, str(self.pid)]


@dataclass(slots=True)
class ObservationResult:
    command: list[str]
    trace_path: str
    line_count: int
    return_code: int
    lines: list[str]
    metadata_path: str | None = None
    symbol_map_path: str | None = None
    context_map_path: str | None = None


class EbpfObserver:
    """Collect raw trace lines from a bpftrace-compatible observer command."""

    def __init__(self, config: ObserverConfig) -> None:
        self.config = config

    def collect(self) -> ObservationResult:
        command = self.config.build_command()
        output_path = self._resolve_output_path()
        output_path.parent.mkdir(parents=True, exist_ok=True)

        if self.config.command is None:
            executable = shutil.which(self.config.executable)
            if executable is None:
                raise FileNotFoundError(f"Unable to find observer executable '{self.config.executable}'.")
            command[0] = executable

        env = os.environ.copy()
        env.update(self.config.env)
        start_time = time.monotonic()
        lines: list[str] = []

        with output_path.open("w", encoding="utf-8") as handle:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                env=env,
            )
            try:
                assert process.stdout is not None
                for raw_line in process.stdout:
                    line = raw_line.rstrip("\n")
                    handle.write(line + "\n")
                    handle.flush()
                    lines.append(line)

                    if self.config.max_events is not None and len(lines) >= self.config.max_events:
                        self._terminate(process)
                        break

                    if self.config.duration_seconds is not None:
                        elapsed = time.monotonic() - start_time
                        if elapsed >= self.config.duration_seconds:
                            self._terminate(process)
                            break
            finally:
                if process.stdout is not None:
                    process.stdout.close()
                return_code = self._wait_for_process(process)

        return ObservationResult(
            command=command,
            trace_path=str(output_path),
            line_count=len(lines),
            return_code=return_code,
            lines=lines,
        )

    def _resolve_output_path(self) -> Path:
        if self.config.output_path:
            return Path(self.config.output_path)
        timestamp = int(time.time())
        return Path("data/traces") / f"trace-{timestamp}.log"

    def _terminate(self, process: subprocess.Popen[str]) -> None:
        if process.poll() is None:
            process.send_signal(signal.SIGTERM)

    def _wait_for_process(self, process: subprocess.Popen[str]) -> int:
        try:
            return process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            return process.wait(timeout=2)
