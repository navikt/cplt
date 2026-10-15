#!/usr/bin/env python3
"""Measure cplt release startup latency and parent-side subprocess spawns.

Runs in an isolated workspace under target/bench-startup-tmp (outside /tmp and
/var/folders, where the sandbox denies exec by design) with a synthetic HOME,
dead-end CPLT_CONFIG, throwaway git repo, and no-op copilot stand-in.

Usage:
  mise run bench:startup
  python3 hack/bench-startup.py [--runs 15] [--warmup 3] [--no-build]
  python3 hack/bench-startup.py --save before.json
  python3 hack/bench-startup.py --compare before.json
  python3 hack/bench-startup.py --check-spawns
"""

import argparse
import json
import os
from pathlib import Path
import platform
import shutil
import statistics
import subprocess
import sys
import time

sys.dont_write_bytecode = True

REPO_ROOT = Path(__file__).resolve().parent.parent

# Issue #666 baseline medians (ms) and #670 git spawn budgets on macOS arm64.
CASES = [
    ("--version", ["--version"], 4.4, 0),
    ("--print-profile", ["--print-profile"], None, 5),
    ("--no-proxy exec -- true", ["--no-proxy", "exec", "--", "/usr/bin/true"], None, 7),
    ("exec -- true", ["exec", "--", "/usr/bin/true"], 357.0, 7),
    ("--yes --quiet --no-audit --no-proxy", ["--yes", "--quiet", "--no-audit", "--no-proxy", "--", "--version"], 364.0, 7),
    ("--yes --quiet", ["--yes", "--quiet", "--", "--version"], 434.0, 7),
    ("--yes (full launch + audit)", ["--yes", "--", "--version"], 666.0, 14),
    ("doctor", ["doctor"], 327.0, 14),
    ("check", ["check"], 800.0, 8),
]

INTERPOSE_C = """\
#include <fcntl.h>
#include <spawn.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

typedef struct { void *replacement; void *original; } interpose_t;

static pid_t root_pid = 0;
static const char *log_path = NULL;
static _Thread_local int in_spawnp = 0;

__attribute__((constructor))
static void init_interpose(void) {
    root_pid = getpid();
    const char *env_log = getenv("CPLT_SPAWN_LOG");
    if (env_log) {
        log_path = strdup(env_log);
        int fd = open(log_path, O_WRONLY | O_CREAT | O_APPEND, 0600);
        if (fd >= 0) {
            (void)write(fd, "__init__\\n", 9);
            close(fd);
        }
    }
    unsetenv("DYLD_INSERT_LIBRARIES");
    unsetenv("CPLT_SPAWN_LOG");
}

static void record_spawn(const char *prog) {
    if (!log_path || !prog || getpid() != root_pid) return;
    int fd = open(log_path, O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (fd >= 0) {
        (void)write(fd, prog, strlen(prog));
        (void)write(fd, "\\n", 1);
        close(fd);
    }
}

static int wrap_spawn(pid_t *p, const char *path,
    const posix_spawn_file_actions_t *fa, const posix_spawnattr_t *attr,
    char *const argv[], char *const envp[]) {
    if (!in_spawnp) record_spawn(path);
    return posix_spawn(p, path, fa, attr, argv, envp);
}

static int wrap_spawnp(pid_t *p, const char *file,
    const posix_spawn_file_actions_t *fa, const posix_spawnattr_t *attr,
    char *const argv[], char *const envp[]) {
    record_spawn(file);
    in_spawnp = 1;
    int rc = posix_spawnp(p, file, fa, attr, argv, envp);
    in_spawnp = 0;
    return rc;
}

__attribute__((used)) static const interpose_t interposers[]
    __attribute__((section("__DATA,__interpose"))) = {
    { (void *)wrap_spawn, (void *)posix_spawn },
    { (void *)wrap_spawnp, (void *)posix_spawnp },
};
"""


def build_interpose_dylib(work_dir: Path) -> Path | None:
    if platform.system() != "Darwin" or not shutil.which("cc"):
        return None
    src = work_dir / "spawn_interpose.c"
    dylib = work_dir / "libspawn_interpose.dylib"
    src.write_text(INTERPOSE_C)
    res = subprocess.run(
        ["cc", "-dynamiclib", "-O2", str(src), "-o", str(dylib)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return dylib if res.returncode == 0 else None


def count_spawns(cplt: Path, args: list[str], cwd: Path, env: dict[str, str], dylib: Path | None) -> tuple[int | None, int | None]:
    if dylib is None:
        return None, None
    log_file = cwd.parent / "spawns.log"
    log_file.unlink(missing_ok=True)
    run_env = dict(env)
    run_env["DYLD_INSERT_LIBRARIES"] = str(dylib)
    run_env["CPLT_SPAWN_LOG"] = str(log_file)
    res = subprocess.run([str(cplt), *args], cwd=cwd, env=run_env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)
    if res.returncode != 0 or not log_file.is_file():
        return None, None
    raw_lines = [line.strip() for line in log_file.read_text().splitlines() if line.strip()]
    if "__init__" not in raw_lines:
        return None, None
    lines = [line for line in raw_lines if line != "__init__"]
    git_spawns = sum(1 for line in lines if os.path.basename(line) == "git")
    return git_spawns, len(lines)


def setup_workspace(work_dir: Path) -> tuple[Path, dict[str, str]]:
    if work_dir.exists():
        shutil.rmtree(work_dir)
    home = work_dir / "home"
    bin_dir = work_dir / "bin"
    repo = work_dir / "repo"
    for d in (home / ".copilot", home / ".config" / "cplt", bin_dir, repo):
        d.mkdir(parents=True, exist_ok=True)

    copilot = bin_dir / "copilot"
    copilot.write_text("#!/bin/sh\nexit 0\n")
    copilot.chmod(0o755)

    git_env = {
        "PATH": "/usr/bin:/bin",
        "HOME": str(home),
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_AUTHOR_NAME": "bench",
        "GIT_AUTHOR_EMAIL": "bench@example.invalid",
        "GIT_COMMITTER_NAME": "bench",
        "GIT_COMMITTER_EMAIL": "bench@example.invalid",
    }
    subprocess.run(["git", "init", "-q", "-b", "main", "."], cwd=repo, env=git_env, check=True)
    (repo / "README.md").write_text("bench\n")
    subprocess.run(["git", "add", "README.md"], cwd=repo, env=git_env, check=True)
    subprocess.run(["git", "-c", "commit.gpgsign=false", "commit", "-qm", "init"], cwd=repo, env=git_env, check=True)

    env = {
        "HOME": str(home),
        "PATH": f"{bin_dir}:/usr/bin:/bin:/usr/sbin:/sbin",
        "CPLT_CONFIG": str(home / "nonexistent-config.toml"),
        "COPILOT_GITHUB_TOKEN": "gho_bench_dummy_token",
        "TERM": "dumb",
        "NO_COLOR": "1",
    }
    return repo, env


def percentile(sorted_vals: list[float], pct: float) -> float:
    idx = min(len(sorted_vals) - 1, max(0, int(round((pct / 100.0) * (len(sorted_vals) - 1)))))
    return sorted_vals[idx]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs", type=int, default=15, help="Timed runs per command (default: 15)")
    parser.add_argument("--warmup", type=int, default=3, help="Warmup runs per command (default: 3)")
    parser.add_argument("--no-build", action="store_true", help="Skip cargo build --release")
    parser.add_argument("--save", type=Path, help="Write JSON results to path")
    parser.add_argument("--compare", type=Path, help="Compare against a saved JSON baseline")
    parser.add_argument("--check-spawns", action="store_true", help="Fail if parent git spawns exceed #670 budgets")
    args = parser.parse_args()

    cplt = REPO_ROOT / "target" / "release" / "cplt"
    if not args.no_build or not cplt.is_file():
        subprocess.run(["cargo", "build", "--release", "--quiet"], cwd=REPO_ROOT, check=True)

    work_dir = REPO_ROOT / "target" / "bench-startup-tmp"
    repo, env = setup_workspace(work_dir)
    dylib = build_interpose_dylib(work_dir)

    load_start = os.getloadavg()[0] if hasattr(os, "getloadavg") else 0.0
    prior = json.loads(args.compare.read_text()).get("results", {}) if args.compare else {}

    results: dict[str, dict] = {}
    spawn_failures: list[str] = []

    try:
        for label, cmd_args, issue_666_ms, git_budget in CASES:
            for _ in range(args.warmup):
                subprocess.run([str(cplt), *cmd_args], cwd=repo, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL, check=True)

            git_spawns, posix_spawns = count_spawns(cplt, cmd_args, repo, env, dylib)
            if git_spawns is None:
                if args.check_spawns:
                    spawn_failures.append(f"{label}: spawn instrumentation unavailable or failed")
            elif git_spawns > git_budget:
                spawn_failures.append(f"{label}: spawned git {git_spawns} times (budget <= {git_budget})")

            samples: list[float] = []
            for _ in range(args.runs):
                t0 = time.perf_counter()
                subprocess.run([str(cplt), *cmd_args], cwd=repo, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL, check=True)
                samples.append((time.perf_counter() - t0) * 1000.0)

            samples.sort()
            results[label] = {
                "median_ms": round(statistics.median(samples), 1),
                "min_ms": round(samples[0], 1),
                "p95_ms": round(percentile(samples, 95), 1),
                "stdev_ms": round(statistics.stdev(samples), 1) if len(samples) > 1 else 0.0,
                "git_spawns": git_spawns,
                "posix_spawns": posix_spawns,
                "git_budget": git_budget,
                "issue_666_ms": issue_666_ms,
            }
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)

    load_end = os.getloadavg()[0] if hasattr(os, "getloadavg") else 0.0
    print(f"cplt startup benchmark ({args.runs} runs, {args.warmup} warmup, 1-min load {load_start:.2f} -> {load_end:.2f})\n")
    if load_start >= 4.0 or load_end >= 4.0:
        print("Note: 1-min load >= 4.0; wall-clock timings are noisy under load (spawn counts remain exact).\n")

    ref_col = "Saved baseline" if prior else "#666 baseline"
    print(f"| Command | Median | Min | p95 | {ref_col} | Delta | Parent git spawns (budget) |")
    print("|---|---:|---:|---:|---:|---:|---:|")
    for label, _, issue_666_ms, git_budget in CASES:
        r = results[label]
        ref_ms = prior.get(label, {}).get("median_ms") if prior else issue_666_ms
        ref_str = f"{ref_ms:.1f} ms" if ref_ms is not None else "n/a"
        if ref_ms:
            pct = ((r["median_ms"] - ref_ms) / ref_ms) * 100.0
            delta_str = f"{pct:+.0f}%"
        else:
            delta_str = "n/a"
        spawns_str = f"{r['git_spawns']} (<= {git_budget})" if r["git_spawns"] is not None else f"n/a (<= {git_budget})"
        print(f"| `cplt {label}` | {r['median_ms']:.1f} ms | {r['min_ms']:.1f} ms | {r['p95_ms']:.1f} ms | {ref_str} | {delta_str} | {spawns_str} |")

    if args.save:
        args.save.write_text(json.dumps({"load": [load_start, load_end], "results": results}, indent=2) + "\n")
        print(f"\nSaved results to {args.save}")

    if spawn_failures:
        print("\nParent git spawn check failed:", file=sys.stderr)
        for msg in spawn_failures:
            print(f"  - {msg}", file=sys.stderr)
        if args.check_spawns:
            return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
