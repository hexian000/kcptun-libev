#!/usr/bin/env python3

"""Build gprof data from a focused iperf3 benchmark and write Markdown."""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import shutil
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Sequence


ROOT = Path.cwd().resolve()
DEFAULT_BUILD_DIR = ROOT / "build"
DEFAULT_PROFILE_BUILD_DIR = DEFAULT_BUILD_DIR / "gprof"
DEFAULT_MARKDOWN_OUTPUT = DEFAULT_BUILD_DIR / "gprof.md"
KNOWN_BOOL_OPTIONS = {
	"BUILD_STATIC": "OFF",
	"BUILD_PIE": "OFF",
	"FORCE_POSIX": "OFF",
	"LINK_STATIC_LIBS": "OFF",
	"ENABLE_SYSTEMD": "OFF",
}
CACHE_LINE_RE = re.compile(r"^([A-Za-z0-9_]+):[^=]+=(.*)$")


@dataclass
class FlatProfileRow:
	percent: float
	cumulative_seconds: float
	self_seconds: float
	calls: Optional[int]
	self_us_per_call: Optional[float]
	total_us_per_call: Optional[float]
	name: str


@dataclass(frozen=True)
class ProcessShutdownBudget:
	sigint_wait_seconds: float
	terminate_wait_seconds: float


def log(message: str) -> None:
	print(message, file=sys.stderr)


def quote_command(command: Sequence[str]) -> str:
	return " ".join(shlex.quote(part) for part in command)


def run_command(
	command: Sequence[str],
	*,
	cwd: Optional[Path] = None,
	env: Optional[Dict[str, str]] = None,
	check: bool = True,
	capture_output: bool = False,
	timeout: Optional[float] = None,
	log_command: bool = True,
) -> subprocess.CompletedProcess:
	if log_command:
		log("+ %s" % quote_command(command))
	proc = subprocess.run(
		list(command),
		cwd=str(cwd) if cwd is not None else None,
		env=env,
		text=True,
		stdout=subprocess.PIPE if capture_output else None,
		stderr=subprocess.PIPE if capture_output else None,
		timeout=timeout,
	)
	if check and proc.returncode != 0:
		if capture_output and proc.stdout:
			log(proc.stdout.rstrip())
		if capture_output and proc.stderr:
			log(proc.stderr.rstrip())
		raise SystemExit(proc.returncode)
	return proc


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
			match = CACHE_LINE_RE.match(line)
			if match is None:
				continue
			cache[match.group(1)] = match.group(2)
	return cache


def ensure_tool(name: str) -> str:
	path = shutil.which(name)
	if path is None:
		raise SystemExit("required tool not found: %s" % name)
	return path


def ensure_project_root(root: Path) -> None:
	if not (root / "CMakeLists.txt").exists():
		raise SystemExit(
			"working directory does not look like the project root: %s" % root
		)


def build_server_config(use_crypto: bool) -> Dict[str, object]:
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


def build_client_config(use_crypto: bool) -> Dict[str, object]:
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


def build_configure_command(
	cmake: str,
	base_cache: Dict[str, str],
	profile_build_dir: Path,
	build_type: str,
) -> List[str]:
	command = [
		cmake,
		"-S",
		str(ROOT),
		"-B",
		str(profile_build_dir),
		"-DCMAKE_EXPORT_COMPILE_COMMANDS=ON",
		"-DBUILD_TESTING=OFF",
		"-DENABLE_SANITIZERS=OFF",
		"-DCMAKE_INTERPROCEDURAL_OPTIMIZATION=OFF",
		"-DCMAKE_C_FLAGS=-pg -fno-pie",
		"-DCMAKE_EXE_LINKER_FLAGS=-pg -no-pie",
		"-DCMAKE_SHARED_LINKER_FLAGS=-pg",
		"-DCMAKE_MODULE_LINKER_FLAGS=-pg",
		"-DCMAKE_BUILD_TYPE=%s" % build_type,
	]
	compiler = base_cache.get("CMAKE_C_COMPILER")
	if compiler:
		command.append("-DCMAKE_C_COMPILER=%s" % compiler)
	for key, default in KNOWN_BOOL_OPTIONS.items():
		command.append("-D%s=%s" % (key, base_cache.get(key, default)))
	return command


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


def prepare_runtime_assets(
	binary_path: Path,
	runtime_dir: Path,
	*,
	use_crypto: bool,
) -> tuple[Path, Path]:
	runtime_dir.mkdir(parents=True, exist_ok=True)
	server_config_path = runtime_dir / "server.json"
	client_config_path = runtime_dir / "client.json"
	write_config(
		server_config_path,
		build_server_config(use_crypto),
	)
	write_config(
		client_config_path,
		build_client_config(use_crypto),
	)
	return server_config_path, client_config_path


def remove_stale_profile_data(profile_build_dir: Path) -> int:
	removed = 0
	for pattern in ("gmon.out", "gmon.out.*", "server-gmon.*", "client-gmon.*"):
		for path in sorted(profile_build_dir.glob(pattern)):
			path.unlink()
			removed += 1
	for pattern in ("gmon.out", "gmon.out.*"):
		for path in sorted(ROOT.glob(pattern)):
			path.unlink()
			removed += 1
	return removed


def collect_profile_files(profile_build_dir: Path) -> List[Path]:
	paths: List[Path] = []
	for pattern in ("server-gmon.*", "client-gmon.*", "gmon.out", "gmon.out.*"):
		for path in sorted(profile_build_dir.glob(pattern)):
			if path.is_file():
				paths.append(path)
	for pattern in ("gmon.out", "gmon.out.*"):
		for path in sorted(ROOT.glob(pattern)):
			if path.is_file():
				paths.append(path)
	seen = set()
	unique_paths: List[Path] = []
	for path in paths:
		resolved = path.resolve()
		if resolved in seen:
			continue
		seen.add(resolved)
		unique_paths.append(resolved)
	return unique_paths


def extract_benchmark_tail(output: str, line_count: int = 16) -> List[str]:
	lines = [line.rstrip() for line in output.splitlines() if line.strip()]
	if not lines:
		return []
	return lines[-line_count:]


def run_benchmark(
	commands: Sequence[Sequence[str]],
	*,
	cwd: Path,
	stdout_log_path: Path,
	stderr_log_path: Path,
	timeout_seconds: float,
	shutdown_budget: ProcessShutdownBudget,
	) -> str:
	with stdout_log_path.open("w", encoding="utf-8") as stdout_handle, \
		stderr_log_path.open("w", encoding="utf-8") as stderr_handle:
		for command in commands:
			log("+ %s" % quote_command(command))
			stdout_handle.write("$ %s\n" % quote_command(command))
			stderr_handle.write("$ %s\n" % quote_command(command))
			stdout_handle.flush()
			stderr_handle.flush()
			proc = subprocess.Popen(
				list(command),
				cwd=str(cwd),
				stdout=stdout_handle,
				stderr=stderr_handle,
				text=True,
			)
			try:
				proc.wait(timeout=timeout_seconds)
			except subprocess.TimeoutExpired:
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
				stdout_handle.flush()
				stderr_handle.flush()
				raise SystemExit(
					"benchmark command timed out after %.1f seconds: %s"
					% (timeout_seconds, quote_command(command))
				)
			stdout_handle.flush()
			stderr_handle.flush()
			warning_line = find_iperf_warning_line(
				stdout_log_path.read_text(encoding="utf-8", errors="replace")
			)
			if warning_line is None:
				warning_line = find_iperf_warning_line(
					stderr_log_path.read_text(encoding="utf-8", errors="replace")
				)
			if warning_line is not None:
				raise SystemExit(
					"benchmark command emitted iperf3 warning: %s"
					% warning_line
				)
			if proc.returncode not in (0, None):
				raise SystemExit(
					"benchmark command failed with status %d: %s"
					% (proc.returncode, quote_command(command))
				)
			stdout_handle.write("\n")
			stderr_handle.write("\n")
	return stdout_log_path.read_text(encoding="utf-8", errors="replace")


def parse_flat_profile(gprof_output: str) -> List[FlatProfileRow]:
	rows: List[FlatProfileRow] = []
	in_table = False
	for raw_line in gprof_output.splitlines():
		line = raw_line.rstrip()
		if line.startswith("  %   cumulative"):
			in_table = True
			continue
		if not in_table:
			continue
		if not line.strip():
			if rows:
				break
			continue
		parts = line.split()
		if len(parts) < 4:
			continue
		try:
			percent = float(parts[0])
			cumulative = float(parts[1])
			self_seconds = float(parts[2])
		except ValueError:
			continue
		calls: Optional[int] = None
		self_us_per_call: Optional[float] = None
		total_us_per_call: Optional[float] = None
		name: str
		if len(parts) >= 7:
			try:
				calls = int(parts[3])
				self_us_per_call = float(parts[4])
				total_us_per_call = float(parts[5])
				name = parts[6]
			except ValueError:
				name = parts[3]
		else:
			name = parts[3]
		rows.append(
			FlatProfileRow(
				percent=percent,
				cumulative_seconds=cumulative,
				self_seconds=self_seconds,
				calls=calls,
				self_us_per_call=self_us_per_call,
				total_us_per_call=total_us_per_call,
				name=name,
			)
		)
	return rows


def relative_markdown_path(base_dir: Path, target: Path) -> str:
	return os.path.relpath(target, start=base_dir).replace(os.sep, "/")


def workspace_relative_path(path: Path) -> str:
	return os.path.relpath(path, start=ROOT).replace(os.sep, "/")


def format_command_for_report(command: Sequence[str]) -> str:
	parts: List[str] = []
	for part in command:
		path = Path(part)
		if path.is_absolute():
			if path == ROOT or ROOT in path.parents:
				parts.append(workspace_relative_path(path))
			else:
				parts.append(path.name or part)
			continue
		parts.append(part)
	return quote_command(parts)


def sanitize_report_text(text: str) -> str:
	root_prefix = str(ROOT) + os.sep
	return text.replace(root_prefix, "").replace(str(ROOT), ".")


def render_markdown_report(
	*,
	output_path: Path,
	profile_build_dir: Path,
	binary_path: Path,
	profile_files: Sequence[Path],
	benchmark_command_text: str,
	benchmark_output: str,
	gprof_text_path: Path,
	gprof_output: str,
	use_crypto: bool,
	command_timeout_seconds: float,
	shutdown_budget: ProcessShutdownBudget,
) -> str:
	output_dir = output_path.parent
	rows = parse_flat_profile(gprof_output)
	top_rows = rows[:15]
	profile_links = ", ".join(
		"[%s](%s)"
		% (
			workspace_relative_path(path),
			relative_markdown_path(output_dir, path),
		)
		for path in profile_files
	)
	profile_build_dir_text = workspace_relative_path(profile_build_dir)
	binary_path_text = workspace_relative_path(binary_path)
	raw_gprof_text = workspace_relative_path(gprof_text_path)
	raw_gprof_link = relative_markdown_path(output_dir, gprof_text_path)
	benchmark_stdout_path = profile_build_dir / "iperf3-parallel.stdout"
	benchmark_stdout_text = workspace_relative_path(benchmark_stdout_path)
	benchmark_stdout_link = relative_markdown_path(output_dir, benchmark_stdout_path)
	benchmark_stderr_path = profile_build_dir / "iperf3-parallel.stderr"
	benchmark_stderr_text = workspace_relative_path(benchmark_stderr_path)
	benchmark_stderr_link = relative_markdown_path(output_dir, benchmark_stderr_path)
	benchmark_output_text = sanitize_report_text(benchmark_output).rstrip()
	gprof_output_text = sanitize_report_text(gprof_output).rstrip()
	lines = [
		"# gprof Profile",
		"",
		"## Run",
		"",
		"| Field | Value |",
		"| --- | --- |",
		"| Profile build dir | %s |" % profile_build_dir_text,
		"| Binary | %s |" % binary_path_text,
		"| Crypto | %s |" % ("on" if use_crypto else "off"),
		"| Benchmark timeout | %.1f s |" % command_timeout_seconds,
		"| Shutdown grace | SIGINT %.1f s, terminate %.1f s |"
		% (
			shutdown_budget.sigint_wait_seconds,
			shutdown_budget.terminate_wait_seconds,
		),
		"| Benchmark command | `%s` |" % benchmark_command_text,
		"| Raw gprof output | [%s](%s) |" % (raw_gprof_text, raw_gprof_link),
		"| Benchmark stdout | [%s](%s) |" % (benchmark_stdout_text, benchmark_stdout_link),
		"| Benchmark stderr | [%s](%s) |" % (benchmark_stderr_text, benchmark_stderr_link),
		"| Profile data | %s |" % (profile_links or "none"),
	]
	lines.extend(
		[
			"",
			"## Hotspots",
			"",
			"| Function | Self % | Self Seconds | Calls | Total us/call |",
			"| --- | ---: | ---: | ---: | ---: |",
		]
	)
	for row in top_rows:
		calls_text = "-" if row.calls is None else str(row.calls)
		total_call_text = "-"
		if row.total_us_per_call is not None:
			total_call_text = "%.2f" % row.total_us_per_call
		lines.append(
			"| %s | %.2f | %.2f | %s | %s |"
			% (
				row.name,
				row.percent,
				row.self_seconds,
				calls_text,
				total_call_text,
			)
		)
	lines.extend(
		[
			"",
			"## Flat Profile",
			"",
			"| Function | Self % | Cumulative Seconds | Self Seconds | Calls | Self us/call | Total us/call |",
			"| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
		]
	)
	for row in rows:
		calls_text = "-" if row.calls is None else str(row.calls)
		self_call_text = "-"
		total_call_text = "-"
		if row.self_us_per_call is not None:
			self_call_text = "%.2f" % row.self_us_per_call
		if row.total_us_per_call is not None:
			total_call_text = "%.2f" % row.total_us_per_call
		lines.append(
			"| %s | %.2f | %.2f | %.2f | %s | %s | %s |"
			% (
				row.name,
				row.percent,
				row.cumulative_seconds,
				row.self_seconds,
				calls_text,
				self_call_text,
				total_call_text,
			)
		)
	if benchmark_output_text:
		lines.extend(["", "## Benchmark Output", "", "```text"])
		lines.append(benchmark_output_text)
		lines.append("```")
	if gprof_output_text:
		lines.extend(["", "## Raw gprof Output", "", "```text"])
		lines.append(gprof_output_text)
		lines.append("```")
	return "\n".join(lines) + "\n"


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
	parser = argparse.ArgumentParser(
		description="Run a focused gprof benchmark and write a Markdown report."
	)
	parser.add_argument(
		"--build-dir",
		default="build",
		help="existing build directory used as a source of cached CMake options",
	)
	parser.add_argument(
		"--profile-build-dir",
		default="build/gprof",
		help="build directory used for gprof-instrumented artifacts",
	)
	parser.add_argument(
		"--build-type",
		default="RelWithDebInfo",
		help="CMake build type for the profiling build (default: RelWithDebInfo)",
	)
	parser.add_argument(
		"--jobs",
		type=int,
		default=max(1, os.cpu_count() or 1),
		help="parallel job count for the build step",
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
		help="iperf3 parallel stream count (default: 10)",
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
		"--output",
		help="write Markdown output to this file (default: build/gprof.md)",
	)
	parser.add_argument(
		"--skip-configure",
		action="store_true",
		help="reuse an existing profiling build directory without re-running CMake",
	)
	parser.add_argument(
		"--skip-build",
		action="store_true",
		help="skip the build step",
	)
	parser.add_argument(
		"--skip-benchmark",
		action="store_true",
		help="skip the benchmark step and use existing profile data files",
	)
	parser.add_argument(
		"--keep-profile-data",
		action="store_true",
		help="do not delete existing gmon output files before running the benchmark",
	)
	parser.add_argument("--cmake", default="cmake", help="cmake executable name")
	parser.add_argument("--gprof", default="gprof", help="gprof executable name")
	parser.add_argument("--iperf3", default="iperf3", help="iperf3 executable name")
	return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
	args = parse_args(argv)
	cmake = ensure_tool(args.cmake)
	gprof = ensure_tool(args.gprof)
	iperf3 = ensure_tool(args.iperf3)
	ensure_project_root(ROOT)

	base_build_dir = resolve_path(ROOT, args.build_dir)
	profile_build_dir = resolve_path(ROOT, args.profile_build_dir)
	output_path = (
		resolve_path(ROOT, args.output)
		if args.output
		else DEFAULT_MARKDOWN_OUTPUT.resolve()
	)
	profile_build_dir.mkdir(parents=True, exist_ok=True)
	base_cache = parse_cmake_cache(base_build_dir / "CMakeCache.txt")

	if not args.skip_configure:
		run_command(
			build_configure_command(
				cmake,
				base_cache,
				profile_build_dir,
				args.build_type,
			),
			cwd=ROOT,
		)

	if not args.skip_build:
		run_command(
			[cmake, "--build", str(profile_build_dir), "-j%d" % args.jobs],
			cwd=ROOT,
		)

	binary_path = profile_build_dir / "bin" / "kcptun-libev"
	if not binary_path.exists():
		raise SystemExit("expected binary not found: %s" % binary_path)

	command_timeout_seconds = compute_command_timeout_seconds(
		args.duration,
		args.startup_wait,
	)
	shutdown_budget = compute_process_shutdown_budget(
		args.duration,
		args.startup_wait,
		scenario_count=1,
	)
	server_config_path, client_config_path = prepare_runtime_assets(
		binary_path,
		profile_build_dir,
		use_crypto=args.crypto,
	)
	benchmark_commands = [
		[
			iperf3,
			"-c",
			"127.0.0.1",
			"-p",
			"5202",
			"--bidir",
			"-P",
			str(args.parallel),
			"-t",
			str(args.duration),
		],
	]
	benchmark_output = ""
	server_proc: Optional[subprocess.Popen[str]] = None
	client_proc: Optional[subprocess.Popen[str]] = None
	iperf_server_proc: Optional[subprocess.Popen[str]] = None
	server_log = None
	client_log = None
	iperf_server_log = None

	try:
		if not args.skip_benchmark:
			if not args.keep_profile_data:
				removed = remove_stale_profile_data(profile_build_dir)
				log("removed %d stale gprof files" % removed)
			server_log = (profile_build_dir / "kcptun-libev-server.log").open("w", encoding="utf-8")
			client_log = (profile_build_dir / "kcptun-libev-client.log").open("w", encoding="utf-8")
			iperf_server_log = (profile_build_dir / "iperf3-server.log").open("w", encoding="utf-8")
			benchmark_stdout_path = profile_build_dir / "iperf3-parallel.stdout"
			benchmark_stderr_path = profile_build_dir / "iperf3-parallel.stderr"

			log("+ %s" % quote_command([iperf3, "-s", "-p", "5201"]))
			iperf_server_proc = subprocess.Popen(
				[iperf3, "-s", "-p", "5201"],
				cwd=str(profile_build_dir),
				stdout=iperf_server_log,
				stderr=subprocess.STDOUT,
				text=True,
			)

			server_env = os.environ.copy()
			server_env["GMON_OUT_PREFIX"] = str(profile_build_dir / "server-gmon")
			log("+ %s" % quote_command([str(binary_path), "-c", str(server_config_path)]))
			server_proc = subprocess.Popen(
				[str(binary_path), "-c", str(server_config_path)],
				cwd=str(profile_build_dir),
				env=server_env,
				stdout=server_log,
				stderr=subprocess.STDOUT,
				text=True,
			)

			client_env = os.environ.copy()
			client_env["GMON_OUT_PREFIX"] = str(profile_build_dir / "client-gmon")
			log("+ %s" % quote_command([str(binary_path), "-c", str(client_config_path)]))
			client_proc = subprocess.Popen(
				[str(binary_path), "-c", str(client_config_path)],
				cwd=str(profile_build_dir),
				env=client_env,
				stdout=client_log,
				stderr=subprocess.STDOUT,
				text=True,
			)

			time.sleep(args.startup_wait)
			benchmark_output = run_benchmark(
				benchmark_commands,
				cwd=profile_build_dir,
				stdout_log_path=benchmark_stdout_path,
				stderr_log_path=benchmark_stderr_path,
				timeout_seconds=command_timeout_seconds,
				shutdown_budget=shutdown_budget,
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

	profile_files = collect_profile_files(profile_build_dir)
	if not profile_files:
		raise SystemExit("no gprof data files found; expected gmon.out or GMON_OUT_PREFIX outputs")
	log("found %d gprof data files" % len(profile_files))
	benchmark_stdout_path = profile_build_dir / "iperf3-parallel.stdout"
	benchmark_command_text = " ; ".join(
		format_command_for_report(command) for command in benchmark_commands
	)
	if not benchmark_output and benchmark_stdout_path.exists():
		benchmark_output = benchmark_stdout_path.read_text(encoding="utf-8", errors="replace")
		if args.skip_benchmark:
			benchmark_command_text = "reused existing benchmark log from %s" % workspace_relative_path(
				benchmark_stdout_path
			)
	gprof_proc = run_command(
		[gprof, str(binary_path), *[str(path) for path in profile_files]],
		cwd=ROOT,
		capture_output=True,
	)
	gprof_output = gprof_proc.stdout or ""
	gprof_text_path = profile_build_dir / "gprof.txt"
	gprof_text_path.write_text(gprof_output, encoding="utf-8")

	report = render_markdown_report(
		output_path=output_path,
		profile_build_dir=profile_build_dir,
		binary_path=binary_path,
		profile_files=profile_files,
		benchmark_command_text=benchmark_command_text,
		benchmark_output=benchmark_output,
		gprof_text_path=gprof_text_path,
		gprof_output=gprof_output,
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