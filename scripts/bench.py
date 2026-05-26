#!/usr/bin/env python3

"""Run the kcptun-libev iperf3 benchmark suite and write a Markdown summary."""

from __future__ import annotations

import argparse
import json
import os
import shlex
import shutil
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Sequence, TextIO


ROOT = Path.cwd().resolve()
DEFAULT_BUILD_DIR = ROOT / "build"
DEFAULT_OUTPUT = DEFAULT_BUILD_DIR / "bench.md"
BENCH_NETNS_ENV = "BENCH_NETNS"
KCP_PORT = 5555


@dataclass(frozen=True)
class Scenario:
    name: str
    label: str


@dataclass
class ScenarioResult:
    scenario: Scenario
    command_texts: List[str]
    log_paths: List[Path]
    stderr_paths: List[Path]
    total_bits_per_second: float
    sent_bits_per_second: float
    received_bits_per_second: float
    duration_seconds: float


@dataclass(frozen=True)
class ProcessShutdownBudget:
    sigint_wait_seconds: float
    terminate_wait_seconds: float


SCENARIOS = (
    Scenario("uplink", "Uplink"),
    Scenario("downlink", "Downlink"),
    Scenario("bidir", "Bidirectional"),
    Scenario("parallel", "Parallel Bidirectional"),
)


def log(message: str) -> None:
    print(message, file=sys.stderr)


def quote_command(command: Sequence[str]) -> str:
    return " ".join(shlex.quote(part) for part in command)


def ensure_project_root(root: Path) -> None:
    if not (root / "CMakeLists.txt").exists():
        raise SystemExit(
            "working directory does not look like the project root: %s" % root
        )


def ensure_tool(name: str) -> str:
    path = shutil.which(name)
    if path is None:
        raise SystemExit("required tool not found: %s" % name)
    return path


def resolve_path(base: Path, value: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        path = base / path
    return path.resolve()


def parse_cmake_cache(cache_path: Path) -> Dict[str, str]:
    cache: Dict[str, str] = {}
    if not cache_path.exists():
        return cache
    with cache_path.open("r", encoding="utf-8", errors="replace") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line or line.startswith("#") or line.startswith("//"):
                continue
            key_type, sep, value = line.partition("=")
            if not sep:
                continue
            key, _, _type = key_type.partition(":")
            if key:
                cache[key] = value
    return cache


def relative_path(path: Path) -> str:
    return os.path.relpath(path, start=ROOT).replace(os.sep, "/")


def run_command(
        command: Sequence[str],
        *,
        cwd: Optional[Path] = None,
        timeout: Optional[float] = None,
) -> None:
    log("+ %s" % quote_command(command))
    try:
        subprocess.run(
            list(command),
            cwd=str(cwd) if cwd is not None else None,
            check=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        raise SystemExit("command timed out: %s" % quote_command(command))


def find_iperf_warning_line(text: str) -> Optional[str]:
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if line.upper().startswith("WARNING:"):
            return line
    return None


def compute_command_timeout_seconds(
        duration_seconds: int,
        startup_wait_seconds: float,
) -> float:
    extra_seconds = max(
        30.0,
        min(120.0, float(duration_seconds) * 0.25),
        startup_wait_seconds * 4.0,
    )
    return float(duration_seconds) + extra_seconds


def compute_process_shutdown_budget(
        duration_seconds: int,
        startup_wait_seconds: float,
        *,
        scenario_count: int,
) -> ProcessShutdownBudget:
    sigint_wait_seconds = max(
        5.0,
        min(
            60.0,
            startup_wait_seconds * 2.0
            + float(duration_seconds) * 0.25
            + float(scenario_count),
        ),
    )
    terminate_wait_seconds = max(
        2.0,
        min(15.0, sigint_wait_seconds / 2.0),
    )
    return ProcessShutdownBudget(
        sigint_wait_seconds=sigint_wait_seconds,
        terminate_wait_seconds=terminate_wait_seconds,
    )


def build_server_config(*, use_crypto: bool) -> Dict[str, object]:
    config: Dict[str, object] = {
        "kcp_bind": "127.0.0.1:5555",
        "connect": "127.0.0.1:5201",
        "kcp": {
            "mtu": 1492,
            "sndwnd": 4096,
            "rcvwnd": 4096,
            "nodelay": 1,
            "interval": 10,
            "resend": 2,
            "nc": 1,
        },
        "udp": {
            "sndbuf": 4194304,
            "rcvbuf": 4194304,
        },
        "loglevel": 5,
    }
    if use_crypto:
        config["method"] = "xchacha20poly1305_ietf"
        config["password"] = "bench"
    return config


def build_client_config(*, use_crypto: bool) -> Dict[str, object]:
    config: Dict[str, object] = {
        "kcp_connect": "127.0.0.1:5555",
        "listen": "127.0.0.1:5202",
        "kcp": {
            "mtu": 1492,
            "sndwnd": 4096,
            "rcvwnd": 4096,
            "nodelay": 1,
            "interval": 10,
            "resend": 2,
            "nc": 1,
        },
        "udp": {
            "sndbuf": 4194304,
            "rcvbuf": 4194304,
        },
        "loglevel": 5,
    }
    if use_crypto:
        config["method"] = "xchacha20poly1305_ietf"
        config["password"] = "bench"
    return config


def write_config(path: Path, payload: Dict[str, object]) -> None:
    path.write_text(json.dumps(payload, indent=4) + "\n", encoding="utf-8")


def prepare_runtime_assets(
        runtime_dir: Path,
        *,
        use_crypto: bool,
) -> tuple[Path, Path]:
    runtime_dir.mkdir(parents=True, exist_ok=True)
    server_config_path = runtime_dir / "server.json"
    client_config_path = runtime_dir / "client.json"
    write_config(server_config_path, build_server_config(use_crypto=use_crypto))
    write_config(client_config_path, build_client_config(use_crypto=use_crypto))
    return server_config_path, client_config_path


def terminate_process(
        proc: subprocess.Popen[str],
        name: str,
        *,
        shutdown_budget: ProcessShutdownBudget,
) -> None:
    if proc.poll() is not None:
        return
    log("stopping %s [pid:%d]" % (name, proc.pid))
    proc.send_signal(signal.SIGINT)
    try:
        proc.wait(timeout=shutdown_budget.sigint_wait_seconds)
    except subprocess.TimeoutExpired:
        proc.terminate()
        try:
            proc.wait(timeout=shutdown_budget.terminate_wait_seconds)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=max(2.0, shutdown_budget.terminate_wait_seconds))


def open_log(path: Path) -> TextIO:
    path.parent.mkdir(parents=True, exist_ok=True)
    return path.open("w", encoding="utf-8")


def build_scenario_commands(
        iperf3: str,
        scenario: Scenario,
        duration: int,
        parallel: int,
) -> List[List[str]]:
    base_command = [
        iperf3,
        "-c",
        "127.0.0.1",
        "-p",
        "5202",
        "-t",
        str(duration),
        "--json",
    ]
    if scenario.name == "uplink":
        return [base_command]
    if scenario.name == "downlink":
        return [base_command + ["-R"]]
    if scenario.name == "bidir":
        return [base_command + ["--bidir"]]
    if scenario.name == "parallel":
        return [base_command + ["--bidir", "-P", str(parallel)]]
    raise SystemExit("unsupported scenario: %s" % scenario.name)


def run_json_command(
        command: Sequence[str],
        *,
        cwd: Path,
        log_path: Path,
        stderr_path: Path,
        timeout_seconds: float,
) -> Dict[str, object]:
    log("+ %s" % quote_command(command))
    try:
        proc = subprocess.run(
            list(command),
            cwd=str(cwd),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_seconds,
        )
        output = proc.stdout or ""
        stderr_output = proc.stderr or ""
    except subprocess.TimeoutExpired as exc:
        output = exc.stdout or ""
        stderr_output = exc.stderr or ""
        log_path.write_text(output, encoding="utf-8")
        stderr_path.write_text(stderr_output, encoding="utf-8")
        raise SystemExit(
            "benchmark command timed out after %.1f seconds: %s"
            % (timeout_seconds, quote_command(command))
        )
    log_path.write_text(output, encoding="utf-8")
    stderr_path.write_text(stderr_output, encoding="utf-8")
    warning_line = find_iperf_warning_line(output)
    if warning_line is None:
        warning_line = find_iperf_warning_line(stderr_output)
    if warning_line is not None:
        raise SystemExit(
            "benchmark command emitted iperf3 warning in %s: %s"
            % (log_path, warning_line)
        )
    stderr_lines = [line.strip() for line in stderr_output.splitlines()
                    if line.strip()]
    if stderr_lines:
        raise SystemExit(
            "benchmark command emitted stderr in %s: %s"
            % (stderr_path, stderr_lines[0])
        )
    if proc.returncode != 0:
        raise SystemExit(
            "benchmark command failed with status %d: %s"
            % (proc.returncode, quote_command(command))
        )
    json_start = output.find("{")
    if json_start < 0:
        raise SystemExit("invalid iperf3 JSON output in %s: missing JSON object"
                         % log_path)
    prefix = output[:json_start].strip()
    if prefix:
        raise SystemExit(
            "invalid iperf3 JSON output in %s: unexpected text before JSON: %s"
            % (log_path, prefix.splitlines()[0])
        )
    try:
        report, end = json.JSONDecoder().raw_decode(output[json_start:])
    except json.JSONDecodeError as exc:
        raise SystemExit("invalid iperf3 JSON output in %s: %s" %
                         (log_path, exc))
    suffix = output[json_start + end:].strip()
    if suffix:
        raise SystemExit(
            "invalid iperf3 JSON output in %s: unexpected text after JSON: %s"
            % (log_path, suffix.splitlines()[0])
        )
    return report


def parse_summary_bits(summary: object) -> float:
    if not isinstance(summary, dict):
        return 0.0
    value = summary.get("bits_per_second")
    if isinstance(value, (int, float)):
        return float(value)
    return 0.0


def parse_summary_seconds(summary: object) -> float:
    if not isinstance(summary, dict):
        return 0.0
    value = summary.get("seconds")
    if isinstance(value, (int, float)):
        return float(value)
    return 0.0


def extract_bidir_throughput(end: Dict[str, object]) -> tuple[float, float, float]:
    streams = end.get("streams")
    if not isinstance(streams, list):
        raise SystemExit("iperf3 bidirectional report missing end.streams")

    sent = 0.0
    received = 0.0
    seconds = 0.0
    for stream in streams:
        if not isinstance(stream, dict):
            continue
        sender = stream.get("sender")
        if isinstance(sender, dict):
            if sender.get("sender") is True:
                sent += parse_summary_bits(sender)
                seconds = max(seconds, parse_summary_seconds(sender))
        receiver = stream.get("receiver")
        if isinstance(receiver, dict):
            if receiver.get("sender") is False:
                received += parse_summary_bits(receiver)
                seconds = max(seconds, parse_summary_seconds(receiver))
    return sent, received, seconds


def extract_total_throughput(report: Dict[str, object], scenario: Scenario) -> tuple[float, float, float, float]:
    end = report.get("end")
    if not isinstance(end, dict):
        raise SystemExit(
            "iperf3 report missing end summary for %s" % scenario.name)
    if scenario.name in {"bidir", "parallel"}:
        sent, received, seconds = extract_bidir_throughput(end)
        return sent + received, sent, received, seconds

    sent = parse_summary_bits(end.get("sum_sent"))
    received = parse_summary_bits(end.get("sum_received"))
    seconds = 0.0
    for candidate in (end.get("sum_received"), end.get("sum_sent")):
        if isinstance(candidate, dict):
            value = candidate.get("seconds")
            if isinstance(value, (int, float)):
                seconds = float(value)
                break
    total = max(sent, received)
    return total, sent, received, seconds


def combine_throughput(
        reports: Sequence[Dict[str, object]], scenario: Scenario
) -> tuple[float, float, float, float]:
    total = 0.0
    sent = 0.0
    received = 0.0
    seconds = 0.0
    for report in reports:
        report_total, report_sent, report_received, report_seconds = extract_total_throughput(
            report, scenario
        )
        total += report_total
        sent += report_sent
        received += report_received
        seconds = max(seconds, report_seconds)
    return total, sent, received, seconds


def format_bits_per_second(bits_per_second: float) -> str:
    units = (
            ("bit/s", 1.0),
            ("Kbit/s", 1_000.0),
            ("Mbit/s", 1_000_000.0),
            ("Gbit/s", 1_000_000_000.0),
    )
    for index in range(len(units) - 1, -1, -1):
        unit, scale = units[index]
        if bits_per_second >= scale or scale == 1.0:
            return "%.2f %s" % (bits_per_second / scale, unit)
    return "0.00 bit/s"


def maybe_reexec_in_netns(netem_delay: Optional[str]) -> None:
    if not netem_delay or os.environ.get(BENCH_NETNS_ENV) == "1":
        return
    command = [
        "unshare",
        "--user",
        "--net",
        "--map-root-user",
        "--",
        "env",
        "%s=1" % BENCH_NETNS_ENV,
        *sys.argv,
    ]
    os.execvp(command[0], command)


def configure_netem(netem_delay: Optional[str]) -> None:
    if not netem_delay:
        return
    run_command(["ip", "link", "set", "lo", "up"], cwd=ROOT)
    run_command(
        [
            "tc",
            "qdisc",
            "add",
            "dev",
            "lo",
            "root",
            "handle",
            "1:",
            "prio",
            "bands",
            "2",
            "priomap",
            "1",
            "1",
            "1",
            "1",
            "1",
            "1",
            "1",
            "1",
            "1",
            "1",
            "1",
            "1",
            "1",
            "1",
            "1",
            "1",
        ],
        cwd=ROOT,
    )
    run_command(
        [
            "tc",
            "qdisc",
            "add",
            "dev",
            "lo",
            "parent",
            "1:1",
            "handle",
            "10:",
            "netem",
            "delay",
            netem_delay,
        ],
        cwd=ROOT,
    )
    for field, port in (("dport", str(KCP_PORT)), ("sport", str(KCP_PORT))):
        run_command(
            [
                "tc",
                "filter",
                "add",
                "dev",
                "lo",
                "protocol",
                "ip",
                "parent",
                "1:0",
                "prio",
                "1",
                "u32",
                "match",
                "ip",
                "protocol",
                "17",
                "0xff",
                "match",
                "ip",
                field,
                port,
                "0xffff",
                "flowid",
                "1:1",
            ],
            cwd=ROOT,
        )


def render_markdown_report(
        results: Sequence[ScenarioResult],
        *,
        output_path: Path,
        binary_path: Path,
        duration: int,
        parallel: int,
        netem_delay: Optional[str],
    use_crypto: bool,
    command_timeout_seconds: float,
    shutdown_budget: ProcessShutdownBudget,
) -> str:
    output_dir = output_path.parent
    lines = [
        "# Benchmark Summary",
        "",
        "| Field | Value |",
        "| --- | --- |",
        "| Project root | %s |" % relative_path(ROOT),
        "| Binary | %s |" % relative_path(binary_path),
        "| Duration per run | %d s |" % duration,
        "| Parallel streams | %d |" % parallel,
        "| Crypto | %s |" % ("on" if use_crypto else "off"),
        "| Netem delay | %s |" % (netem_delay or "off"),
        "| Benchmark timeout | %.1f s per scenario |" % command_timeout_seconds,
        "| Shutdown grace | SIGINT %.1f s, terminate %.1f s |"
        % (
            shutdown_budget.sigint_wait_seconds,
            shutdown_budget.terminate_wait_seconds,
        ),
        "| Bidirectional method | iperf3 --bidir single run |",
        "",
        "## Throughput",
        "",
        "| Scenario | Total Throughput | Sent | Received | Duration | Logs |",
        "| --- | ---: | ---: | ---: | ---: | --- |",
    ]
    for result in results:
        log_parts: List[str] = []
        for path in result.log_paths:
            log_parts.append(
                "[json:%s](%s)"
                % (
                    relative_path(path),
                    os.path.relpath(path, start=output_dir).replace(
                        os.sep, "/"
                    ),
                )
            )
        for path in result.stderr_paths:
            log_parts.append(
                "[stderr:%s](%s)"
                % (
                    relative_path(path),
                    os.path.relpath(path, start=output_dir).replace(
                        os.sep, "/"
                    ),
                )
            )
        log_text = ", ".join(log_parts)
        lines.append(
            "| %s | %s | %s | %s | %.2f s | %s |"
            % (
                result.scenario.label,
                format_bits_per_second(result.total_bits_per_second),
                format_bits_per_second(result.sent_bits_per_second),
                format_bits_per_second(result.received_bits_per_second),
                result.duration_seconds,
                log_text,
            )
        )
    lines.extend(["", "## Commands", ""])
    for result in results:
        lines.append("- %s: `%s`" %
                     (result.scenario.label, " ; ".join(result.command_texts)))
    return "\n".join(lines) + "\n"


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the kcptun-libev benchmark suite and write build/bench.md."
    )
    parser.add_argument(
        "--build-dir",
        default="build",
        help="build directory containing bin/kcptun-libev (default: build)",
    )
    parser.add_argument(
        "--output",
        help="Markdown output path (default: build/bench.md)",
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=30,
        help="iperf3 test duration in seconds (default: 30)",
    )
    parser.add_argument(
        "--parallel",
        type=int,
        default=10,
        help="parallel stream count for the parallel scenario (default: 10)",
    )
    parser.add_argument(
        "--startup-wait",
        type=float,
        default=1.0,
        help="seconds to wait after starting services before running iperf3",
    )
    parser.add_argument(
        "--crypto",
        action="store_true",
        help="enable crypto (method + password) for the KCP tunnel (default: off)",
    )
    parser.add_argument(
        "--netem-delay",
        help="optional tc netem delay applied to the KCP tunnel, for example 100ms",
    )
    parser.add_argument("--iperf3", default="iperf3",
                        help="iperf3 executable name")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    ensure_project_root(ROOT)
    maybe_reexec_in_netns(args.netem_delay)
    iperf3 = ensure_tool(args.iperf3)
    build_dir = resolve_path(ROOT, args.build_dir)
    build_cache = parse_cmake_cache(build_dir / "CMakeCache.txt")
    build_dir.mkdir(parents=True, exist_ok=True)
    binary_path = build_dir / "bin" / "kcptun-libev"
    if not binary_path.exists():
        raise SystemExit("expected binary not found: %s" % binary_path)
    server_config_path, client_config_path = prepare_runtime_assets(
        build_dir,
        use_crypto=args.crypto,
    )
    configure_netem(args.netem_delay)
    command_timeout_seconds = compute_command_timeout_seconds(
        args.duration,
        args.startup_wait,
    )
    shutdown_budget = compute_process_shutdown_budget(
        args.duration,
        args.startup_wait,
        scenario_count=len(SCENARIOS),
    )

    output_path = resolve_path(
        ROOT, args.output) if args.output else DEFAULT_OUTPUT

    results: List[ScenarioResult] = []
    server_proc: Optional[subprocess.Popen[str]] = None
    client_proc: Optional[subprocess.Popen[str]] = None
    iperf_server_proc: Optional[subprocess.Popen[str]] = None
    server_log: Optional[TextIO] = None
    client_log: Optional[TextIO] = None
    iperf_server_log: Optional[TextIO] = None

    try:
        server_log = open_log(build_dir / "kcptun-libev-server.log")
        client_log = open_log(build_dir / "kcptun-libev-client.log")
        iperf_server_log = open_log(build_dir / "iperf3-server.log")

        log("+ %s" % quote_command([iperf3, "-s", "-p", "5201"]))
        iperf_server_proc = subprocess.Popen(
            [iperf3, "-s", "-p", "5201"],
            cwd=str(build_dir),
            stdout=iperf_server_log,
            stderr=subprocess.STDOUT,
            text=True,
        )

        log("+ %s" %
            quote_command([str(binary_path), "-c", str(server_config_path)]))
        server_proc = subprocess.Popen(
            [str(binary_path), "-c", str(server_config_path)],
            cwd=str(build_dir),
            stdout=server_log,
            stderr=subprocess.STDOUT,
            text=True,
        )

        log("+ %s" %
            quote_command([str(binary_path), "-c", str(client_config_path)]))
        client_proc = subprocess.Popen(
            [str(binary_path), "-c", str(client_config_path)],
            cwd=str(build_dir),
            stdout=client_log,
            stderr=subprocess.STDOUT,
            text=True,
        )

        time.sleep(args.startup_wait)

        for scenario in SCENARIOS:
            commands = build_scenario_commands(
                iperf3, scenario, args.duration, args.parallel)
            log_paths = [
                build_dir / ("iperf3-%s-%02d.json" % (scenario.name, index))
                for index in range(1, len(commands) + 1)
            ]
            stderr_paths = [
                build_dir / ("iperf3-%s-%02d.stderr" % (scenario.name, index))
                for index in range(1, len(commands) + 1)
            ]
            if len(commands) == 1:
                reports = [
                    run_json_command(
                        commands[0],
                        cwd=ROOT,
                        log_path=log_paths[0],
                        stderr_path=stderr_paths[0],
                        timeout_seconds=command_timeout_seconds,
                    )
                ]
            else:
                reports = [
                    run_json_command(
                        command,
                        cwd=ROOT,
                        log_path=log_path,
                        stderr_path=stderr_path,
                        timeout_seconds=command_timeout_seconds,
                    )
                    for command, log_path, stderr_path in zip(
                        commands, log_paths, stderr_paths
                    )
                ]
            total, sent, received, seconds = combine_throughput(
                reports, scenario)
            results.append(
                ScenarioResult(
                    scenario=scenario,
                    command_texts=[quote_command(command)
                                   for command in commands],
                    log_paths=log_paths,
                    stderr_paths=stderr_paths,
                    total_bits_per_second=total,
                    sent_bits_per_second=sent,
                    received_bits_per_second=received,
                    duration_seconds=seconds,
                )
            )
    finally:
        if client_proc is not None:
            terminate_process(
                client_proc,
                "kcptun-libev client",
                shutdown_budget=shutdown_budget,
            )
        if server_proc is not None:
            terminate_process(
                server_proc,
                "kcptun-libev server",
                shutdown_budget=shutdown_budget,
            )
        if iperf_server_proc is not None:
            terminate_process(
                iperf_server_proc,
                "iperf3 server",
                shutdown_budget=shutdown_budget,
            )
        for handle in (iperf_server_log, client_log, server_log):
            if handle is not None:
                handle.close()

    report = render_markdown_report(
        results,
        output_path=output_path,
        binary_path=binary_path,
        duration=args.duration,
        parallel=args.parallel,
        netem_delay=args.netem_delay,
        use_crypto=args.crypto,
        command_timeout_seconds=command_timeout_seconds,
        shutdown_budget=shutdown_budget,
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(report, encoding="utf-8")
    log("wrote %s" % output_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
