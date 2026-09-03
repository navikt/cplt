#!/usr/bin/env python3
"""Temporary model-free Playwright MCP smoke for the macOS CI job."""

import argparse
import json
import os
from pathlib import Path
import queue
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unicodedata
from typing import Any, Dict, List, Optional, Tuple


MCP_PACKAGE_VERSION = "0.0.80"
PLAYWRIGHT_CORE_VERSION = "1.63.0-alpha-2026-08-31"
CHROMIUM_REVISION = "1243"
MCP_PROTOCOL_VERSION = "2025-06-18"
INITIALIZE_TIMEOUT_SECONDS = 5.0
TOOLS_LIST_TIMEOUT_SECONDS = 5.0
NAVIGATE_TIMEOUT_SECONDS = 20.0
STDOUT_LINE_LIMIT = 1024 * 1024
STDOUT_QUEUE_LIMIT = 256
STDERR_CAPTURE_LIMIT = 64 * 1024
TOOL_RESULT_TEXT_INSPECT_LIMIT = 8 * 1024
TOOL_RESULT_DIAGNOSTIC_LIMIT = 2 * 1024
GRACEFUL_EXIT_SECONDS = 3.0
SIGNAL_EXIT_SECONDS = 3.0
PLAYWRIGHT_SOCKET_DIRECTORY_NAME = ".pws"
PLAYWRIGHT_SOCKET_CLEANUP_FAILURE = (
    "reserved Playwright socket directory cleanup failed"
)


class SmokeFailure(Exception):
    """A bounded, user-safe smoke failure."""


class NaturalProcessExitFailure(SmokeFailure):
    """A generic process-exit failure that must not include child diagnostics."""


class NavigationToolResultFailure(SmokeFailure):
    """A navigation result failure that must not expose child stderr."""


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def _resolve_dir(path: Path, label: str) -> Path:
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise SmokeFailure("{} directory is unavailable".format(label)) from error
    if not resolved.is_dir():
        raise SmokeFailure("{} must be a directory".format(label))
    return resolved


def _resolve_executable(path: Path, label: str) -> Path:
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise SmokeFailure("{} executable is unavailable".format(label)) from error
    if not resolved.is_file() or not os.access(str(resolved), os.X_OK):
        raise SmokeFailure("{} must be an executable file".format(label))
    return resolved


def _read_json_object(path: Path, label: str) -> Dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as handle:
            value = json.load(handle)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise SmokeFailure("{} metadata is unreadable".format(label)) from error
    if not isinstance(value, dict):
        raise SmokeFailure("{} metadata must be a JSON object".format(label))
    return value


def _resolve_node_package(package_name: str, start: Path, prefix: Path) -> Path:
    current = start
    while _is_relative_to(current, prefix):
        candidate = current / "node_modules" / package_name / "package.json"
        if candidate.is_file():
            try:
                resolved = candidate.resolve(strict=True)
            except OSError as error:
                raise SmokeFailure(
                    "{} package metadata is unavailable".format(package_name)
                ) from error
            if not _is_relative_to(resolved, prefix):
                raise SmokeFailure(
                    "{} package resolves outside the pinned prefix".format(package_name)
                )
            return resolved
        if current == prefix:
            break
        current = current.parent
    raise SmokeFailure("{} package is missing".format(package_name))


def _installed_identity(prefix: Path) -> Tuple[Path, str]:
    try:
        mcp_package_path = (
            prefix / "node_modules/@playwright/mcp/package.json"
        ).resolve(strict=True)
    except OSError as error:
        raise SmokeFailure("Playwright MCP package metadata is unavailable") from error
    if not _is_relative_to(mcp_package_path, prefix):
        raise SmokeFailure("Playwright MCP package resolves outside the pinned prefix")
    mcp_package = _read_json_object(mcp_package_path, "Playwright MCP")
    if mcp_package.get("version") != MCP_PACKAGE_VERSION:
        raise SmokeFailure("Playwright MCP package version is not exactly pinned")

    try:
        mcp_dir = mcp_package_path.parent.resolve(strict=True)
    except OSError as error:
        raise SmokeFailure("Playwright MCP package directory is unavailable") from error
    if not _is_relative_to(mcp_dir, prefix):
        raise SmokeFailure("Playwright MCP package resolves outside the pinned prefix")

    package_bin = mcp_package.get("bin")
    if isinstance(package_bin, str):
        cli_relative = package_bin
    elif isinstance(package_bin, dict):
        named_cli = package_bin.get("mcp-server-playwright")
        if isinstance(named_cli, str):
            cli_relative = named_cli
        elif len(package_bin) == 1 and isinstance(next(iter(package_bin.values())), str):
            cli_relative = next(iter(package_bin.values()))
        else:
            raise SmokeFailure("Playwright MCP package has no unambiguous CLI")
    else:
        raise SmokeFailure("Playwright MCP package has no CLI metadata")

    try:
        cli_path = (mcp_dir / cli_relative).resolve(strict=True)
    except OSError as error:
        raise SmokeFailure("Playwright MCP CLI is unavailable") from error
    if not cli_path.is_file() or not _is_relative_to(cli_path, mcp_dir):
        raise SmokeFailure("Playwright MCP CLI resolves outside its package")

    core_package_path = _resolve_node_package("playwright-core", mcp_dir, prefix)
    core_package = _read_json_object(core_package_path, "playwright-core")
    if core_package.get("version") != PLAYWRIGHT_CORE_VERSION:
        raise SmokeFailure("playwright-core version is not exactly pinned")

    try:
        browsers_path = (core_package_path.parent / "browsers.json").resolve(
            strict=True
        )
    except OSError as error:
        raise SmokeFailure("playwright-core browsers metadata is unavailable") from error
    if not _is_relative_to(browsers_path, prefix):
        raise SmokeFailure(
            "playwright-core browsers metadata resolves outside the pinned prefix"
        )
    browsers = _read_json_object(browsers_path, "playwright-core browsers")
    browser_entries = browsers.get("browsers")
    if not isinstance(browser_entries, list):
        raise SmokeFailure("playwright-core browsers metadata has no browser list")
    chromium_entries = [
        entry
        for entry in browser_entries
        if isinstance(entry, dict) and entry.get("name") == "chromium"
    ]
    if len(chromium_entries) != 1:
        raise SmokeFailure(
            "playwright-core must declare exactly one Chromium revision"
        )
    if str(chromium_entries[0].get("revision")) != CHROMIUM_REVISION:
        raise SmokeFailure("playwright-core Chromium revision is not exactly pinned")

    return cli_path, "chromium/Chrome-for-Testing"


def _validate_paths(
    runner_temp_arg: Path,
    project_arg: Path,
    prefix_arg: Path,
    cplt_arg: Path,
    node_arg: Path,
    chrome_arg: Path,
) -> Tuple[Path, Path, Path, Path, Path, Path]:
    runner_temp = _resolve_dir(runner_temp_arg, "runner temp")
    project = _resolve_dir(project_arg, "project")
    prefix = _resolve_dir(prefix_arg, "MCP prefix")
    cplt = _resolve_executable(cplt_arg, "cplt")
    node = _resolve_executable(node_arg, "Node")
    chrome = _resolve_executable(chrome_arg, "Chrome for Testing")

    if prefix == runner_temp or not _is_relative_to(prefix, runner_temp):
        raise SmokeFailure("MCP prefix must be a dedicated runner-temp subdirectory")
    if _is_relative_to(prefix, project) or _is_relative_to(project, prefix):
        raise SmokeFailure("MCP prefix and project directory must be separate")

    try:
        expected_cplt = (project / "target/debug/cplt").resolve(strict=True)
    except OSError as error:
        raise SmokeFailure("current checkout's cplt binary is unavailable") from error
    if cplt != expected_cplt:
        raise SmokeFailure("cplt must be the current checkout's debug binary")
    if _is_relative_to(node, runner_temp) or _is_relative_to(node, project):
        raise SmokeFailure(
            "Node must be a trusted executable outside runner temp and the project"
        )

    browser_cache = _resolve_dir(
        Path.home() / "Library/Caches/ms-playwright", "ms-playwright cache"
    )
    pinned_browser_root = _resolve_dir(
        browser_cache / "cplt-ci-{}".format(PLAYWRIGHT_CORE_VERSION),
        "pinned Playwright browser root",
    )
    if not _is_relative_to(chrome, pinned_browser_root):
        raise SmokeFailure(
            "Chrome for Testing must come from the pinned Playwright browser root"
        )
    if "chromium-{}".format(CHROMIUM_REVISION) not in chrome.parts:
        raise SmokeFailure("Chrome for Testing path does not identify pinned Chromium")
    expected_suffix = (
        "Google Chrome for Testing.app",
        "Contents",
        "MacOS",
        "Google Chrome for Testing",
    )
    if chrome.parts[-len(expected_suffix) :] != expected_suffix:
        raise SmokeFailure("Chrome for Testing executable identity is unexpected")

    return runner_temp, project, prefix, cplt, node, chrome


def _cleanup_socket_directory(
    owned_directory: Tuple[Path, int, int]
) -> Optional[str]:
    socket_directory, expected_device, expected_inode = owned_directory
    try:
        current = socket_directory.lstat()
    except OSError:
        return PLAYWRIGHT_SOCKET_CLEANUP_FAILURE
    if (
        not stat.S_ISDIR(current.st_mode)
        or current.st_dev != expected_device
        or current.st_ino != expected_inode
    ):
        return PLAYWRIGHT_SOCKET_CLEANUP_FAILURE
    try:
        resolved = socket_directory.resolve(strict=True)
    except OSError:
        return PLAYWRIGHT_SOCKET_CLEANUP_FAILURE
    if resolved != socket_directory:
        return PLAYWRIGHT_SOCKET_CLEANUP_FAILURE

    try:
        shutil.rmtree(str(socket_directory))
    except OSError:
        return PLAYWRIGHT_SOCKET_CLEANUP_FAILURE
    try:
        socket_directory.lstat()
    except FileNotFoundError:
        return None
    except OSError:
        return PLAYWRIGHT_SOCKET_CLEANUP_FAILURE
    return PLAYWRIGHT_SOCKET_CLEANUP_FAILURE


def _create_socket_directory(project: Path) -> Tuple[Path, int, int]:
    socket_directory = project / PLAYWRIGHT_SOCKET_DIRECTORY_NAME
    try:
        socket_directory.mkdir(mode=0o700)
    except FileExistsError as error:
        raise SmokeFailure(
            "reserved Playwright socket directory already exists"
        ) from error
    except OSError as error:
        raise SmokeFailure(
            "could not create reserved Playwright socket directory"
        ) from error

    owned_directory = None  # type: Optional[Tuple[Path, int, int]]
    try:
        created = socket_directory.lstat()
        owned_directory = (socket_directory, created.st_dev, created.st_ino)
        if not stat.S_ISDIR(created.st_mode):
            raise OSError
        if socket_directory.resolve(strict=True) != socket_directory:
            raise OSError
    except OSError as error:
        if owned_directory is not None:
            _cleanup_socket_directory(owned_directory)
        raise SmokeFailure(
            "reserved Playwright socket directory setup failed"
        ) from error
    return owned_directory


def _build_command(
    cplt: Path,
    project: Path,
    prefix: Path,
    node: Path,
    cli_path: Path,
    chrome: Path,
) -> List[str]:
    return [
        str(cplt),
        "--project-dir",
        str(project),
        "--preset",
        "standard",
        "--allow-cache-exec",
        "ms-playwright",
        "--allow-read",
        str(prefix),
        "--no-proxy",
        "--no-allow-env-files",
        "--no-allow-localhost-any",
        "--no-allow-lifecycle-scripts",
        "--no-allow-docker",
        "--no-allow-tmp-exec",
        "--deny-clipboard",
        "--pass-env",
        "PWTEST_SOCKETS_DIR",
        "exec",
        "--",
        str(node),
        str(cli_path),
        "--browser",
        "chromium",
        "--executable-path",
        str(chrome),
        "--headless",
        "--no-sandbox",
        "--isolated",
    ]


def _parse_stdout_line(line: bytes) -> Dict[str, Any]:
    if line.endswith(b"\r"):
        line = line[:-1]
    if not line:
        raise SmokeFailure("MCP stdout contained an empty non-JSON line")
    try:
        decoded = line.decode("utf-8")
        value = json.loads(decoded)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise SmokeFailure("MCP stdout contained a non-JSON line") from error
    if not isinstance(value, dict):
        raise SmokeFailure("MCP stdout JSON-RPC frame was not an object")
    return value


class StdoutReader:
    """Drain bounded JSON-lines stdout without letting notifications grow memory."""

    def __init__(self, stream: Any) -> None:
        self._stream = stream
        self._messages = queue.Queue(maxsize=STDOUT_QUEUE_LIMIT)
        self._failure = None  # type: Optional[SmokeFailure]
        self._failure_lock = threading.Lock()
        self._eof = threading.Event()
        self._thread = threading.Thread(
            target=self._run, name="mcp-stdout-drain", daemon=True
        )

    def start(self) -> None:
        self._thread.start()

    def _set_failure(self, failure: SmokeFailure) -> None:
        with self._failure_lock:
            if self._failure is None:
                self._failure = failure

    def failure(self) -> Optional[SmokeFailure]:
        with self._failure_lock:
            return self._failure

    def _offer(self, message: Dict[str, Any]) -> None:
        try:
            self._messages.put_nowait(message)
        except queue.Full:
            self._set_failure(SmokeFailure("MCP stdout notification queue overflowed"))

    def _run(self) -> None:
        buffer = bytearray()
        discard_until_newline = False
        try:
            while True:
                chunk = os.read(self._stream.fileno(), 4096)
                if not chunk:
                    if buffer and not discard_until_newline:
                        self._set_failure(
                            SmokeFailure(
                                "MCP stdout ended without a newline-delimited frame"
                            )
                        )
                    break
                for byte in chunk:
                    if discard_until_newline:
                        if byte == 0x0A:
                            discard_until_newline = False
                        continue
                    if byte == 0x0A:
                        try:
                            self._offer(_parse_stdout_line(bytes(buffer)))
                        except SmokeFailure as failure:
                            self._set_failure(failure)
                        buffer.clear()
                    else:
                        buffer.append(byte)
                        if len(buffer) > STDOUT_LINE_LIMIT:
                            buffer.clear()
                            discard_until_newline = True
                            self._set_failure(
                                SmokeFailure("MCP stdout JSON-RPC frame was too large")
                            )
        except OSError:
            self._set_failure(SmokeFailure("MCP stdout drain failed"))
        finally:
            self._eof.set()

    def next_message(self, deadline: float) -> Dict[str, Any]:
        while True:
            failure = self.failure()
            if failure is not None:
                raise failure
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise SmokeFailure("MCP response timed out")
            try:
                message = self._messages.get(timeout=min(remaining, 0.1))
            except queue.Empty:
                if self._eof.is_set() and self._messages.empty():
                    failure = self.failure()
                    if failure is not None:
                        raise failure
                    raise SmokeFailure("MCP stdout reached premature EOF")
                continue
            failure = self.failure()
            if failure is not None:
                raise failure
            return message

    def join(self) -> bool:
        self._thread.join(timeout=1.0)
        return not self._thread.is_alive()


class StderrCapture:
    """Drain all stderr while retaining only a bounded diagnostic prefix."""

    def __init__(self, stream: Any) -> None:
        self._stream = stream
        self._buffer = bytearray()
        self._truncated = False
        self._lock = threading.Lock()
        self._thread = threading.Thread(
            target=self._run, name="mcp-stderr-drain", daemon=True
        )

    def start(self) -> None:
        self._thread.start()

    def _run(self) -> None:
        try:
            while True:
                chunk = os.read(self._stream.fileno(), 4096)
                if not chunk:
                    return
                with self._lock:
                    remaining = STDERR_CAPTURE_LIMIT - len(self._buffer)
                    if remaining > 0:
                        self._buffer.extend(chunk[:remaining])
                    if len(chunk) > remaining:
                        self._truncated = True
        except OSError:
            return

    def diagnostic(self) -> str:
        with self._lock:
            text = bytes(self._buffer).decode("utf-8", errors="replace")
            truncated = self._truncated
        text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)
        text = "".join(
            character
            for character in text
            if character in "\n\r\t" or ord(character) >= 0x20
        )
        sensitive_line = re.compile(
            r"(?i)(authorization|bearer|cookie|credential|password|"
            r"secret|session|token|api[_ -]?key)"
        )
        text = "\n".join(
            "[redacted sensitive stderr line]"
            if sensitive_line.search(line)
            else line
            for line in text.splitlines()
        )
        text = re.sub(r"https?://\S+\?\S+", "<redacted-url-query>", text)
        text = text.strip()
        if truncated:
            text = "{}\n[stderr truncated]".format(text)
        return text

    def join(self) -> bool:
        self._thread.join(timeout=1.0)
        return not self._thread.is_alive()


def _send(process: subprocess.Popen, message: Dict[str, Any]) -> None:
    if process.stdin is None:
        raise SmokeFailure("MCP stdin is unavailable")
    payload = (
        json.dumps(message, separators=(",", ":"), ensure_ascii=True) + "\n"
    ).encode("utf-8")
    try:
        process.stdin.write(payload)
        process.stdin.flush()
    except (BrokenPipeError, OSError) as error:
        raise SmokeFailure("MCP stdin closed prematurely") from error


def _request(
    process: subprocess.Popen,
    stdout_reader: StdoutReader,
    request_id: int,
    method: str,
    params: Dict[str, Any],
    timeout_seconds: float,
) -> Dict[str, Any]:
    _send(
        process,
        {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": params,
        },
    )
    deadline = time.monotonic() + timeout_seconds
    while True:
        message = stdout_reader.next_message(deadline)
        if message.get("jsonrpc") != "2.0":
            raise SmokeFailure("MCP emitted a frame without JSON-RPC 2.0")
        if "id" not in message:
            if isinstance(message.get("method"), str):
                continue
            raise SmokeFailure("MCP emitted an invalid notification")
        response_id = message.get("id")
        if type(response_id) is not int or response_id != request_id:
            raise SmokeFailure("MCP response had an unexpected JSON-RPC id")
        if "error" in message:
            raise SmokeFailure("MCP returned a JSON-RPC error")
        if "result" not in message:
            raise SmokeFailure("MCP response was missing its result")
        result = message["result"]
        if not isinstance(result, dict):
            raise SmokeFailure("MCP response result was not an object")
        return result


def _validate_initialize(result: Dict[str, Any]) -> None:
    if result.get("protocolVersion") != MCP_PROTOCOL_VERSION:
        raise SmokeFailure("MCP negotiated an unsupported protocol version")


def _validate_navigate_tool(result: Dict[str, Any]) -> None:
    tools = result.get("tools")
    if not isinstance(tools, list):
        raise SmokeFailure("tools/list result was missing its tools")
    matches = [
        tool
        for tool in tools
        if isinstance(tool, dict) and tool.get("name") == "browser_navigate"
    ]
    if len(matches) != 1:
        raise SmokeFailure("tools/list did not contain one browser_navigate tool")
    schema = matches[0].get("inputSchema")
    if not isinstance(schema, dict):
        raise SmokeFailure("browser_navigate had no input schema")
    if schema.get("type") != "object":
        raise SmokeFailure("browser_navigate input schema was not an object")
    required = schema.get("required")
    properties = schema.get("properties")
    if not isinstance(required, list) or "url" not in required:
        raise SmokeFailure("browser_navigate schema did not require url")
    if not isinstance(properties, dict):
        raise SmokeFailure("browser_navigate schema had no properties")
    url_schema = properties.get("url")
    if not isinstance(url_schema, dict) or url_schema.get("type") != "string":
        raise SmokeFailure("browser_navigate url was not a string schema")


ABOUT_BLANK_CONFIRMATION = re.compile(
    r"(?m)^\s*-\s*Page URL:\s*about:blank\s*$"
)

ANSI_ESCAPE = re.compile(
    r"\x1b(?:"
    r"\][^\x07\x1b]*(?:\x07|\x1b\\)"
    r"|P[^\x1b]*(?:\x1b\\)"
    r"|\[[0-?]*[ -/]*[@-~]"
    r"|[@-Z\\-_]"
    r")"
)
SENSITIVE_TOOL_RESULT_LINE = re.compile(
    r"(?i)(?:"
    r"authori[sz]ation|bearer|cookie|credential|pass(?:word|wd)|"
    r"secret|session|token|api[\s_-]*key|access[\s_-]*key|"
    r"private[\s_-]*key"
    r")"
)
SECRET_ASSIGNMENT = re.compile(
    r"(?i)(?:^|[\s,;{])"
    r"[a-z0-9_.-]*(?:key|auth|pwd|password|secret|token|credential|"
    r"cookie|session|signature)\s*[:=]\s*\S"
)
ENV_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{1,63}\s*=\s*\S")
ENVIRONMENT_LABEL = re.compile(r"(?i)(?:^|\s)(?:env|environment)\s*[:=]")
HEADER_LINE = re.compile(r"^[A-Za-z][A-Za-z0-9-]{0,63}\s*:\s*\S")
SAFE_DIAGNOSTIC_HEADER = re.compile(
    r"(?i)^(?:error|failure|failed|exception|cause|message|errno|code)\s*:"
)
FILE_URL_PREFIX = re.compile(r"(?i)\bfile://[^/\s]*")
SCHEME_URL = re.compile(r"(?i)\b[a-z][a-z0-9+.-]*://[^\s<>\"']+")
QUERY_OR_FRAGMENT_MATERIAL = re.compile(r"(?<=\S)[?#][^\s]*")
ABSOLUTE_OR_PRIVATE_PATH_START = re.compile(
    r"(?<![A-Za-z0-9_])/(?![/\s])"
    r"|(?<![A-Za-z0-9_])(?:~|\$(?:HOME|RUNNER_TEMP|GITHUB_WORKSPACE))/"
    r"(?!\s)"
)
SAFE_PATH_SUFFIX_SIGNAL = re.compile(
    r"(?i)(?:"
    r"\b(?:EACCES|EPERM|ENOENT|ENOTDIR|EISDIR|EIO|ENOMEM|EAGAIN|"
    r"EMFILE|ENFILE|EBUSY|EEXIST|ENOSPC|EROFS|ENOSYS|EINVAL|"
    r"ETIMEDOUT|ECONNREFUSED|ECONNRESET|EPIPE)\b|"
    r"\berrno\s*(?::|=)?\s*-?\d+\b|"
    r"\b(?:permission denied|operation not permitted|"
    r"no such file or directory)\b|"
    r"\b[A-Za-z][A-Za-z0-9_.-]{0,40}(?:Error|Exception)(?:Domain)?\b|"
    r"\b(?:[a-z][a-z0-9_-]*\.){2,}[a-z][a-z0-9_-]*\b"
    r")"
)
PLAYWRIGHT_DIAGNOSTIC_TAG = re.compile(
    r"(?i)<((?:launch(?:ed|ing)?|process\b|gracefully close\b)[^>]*)>"
)
HTML_LINE = re.compile(r"(?i)<\s*!|<\s*/?\s*[a-z][^>]*>")
JSON_LIKE_LINE = re.compile(r"^\s*[\[{].*[\]}]\s*$")
JSON_FIELD_LINE = re.compile(r'^"[^"]+"\s*:')
TOOL_DIAGNOSTIC_SIGNAL = re.compile(
    r"(?i)(?:"
    r"\b[A-Za-z][A-Za-z0-9_.-]{0,40}(?:Error|Exception)(?:Domain)?\b|"
    r"\berror\b|\bfail(?:ed|ure|ing)?\b|\bexception\b|"
    r"\blaunch(?:ed|ing)?\b|\bspawn(?:ed|ing)?\b|\bexec(?:ve)?\b|"
    r"\bbootstrap\b|\bmach\b|\bservice\b|\bsandbox\b|\bprocess\b|"
    r"\bcrash(?:ed|ing)?\b|\bpermission denied\b|"
    r"\boperation not permitted\b|\berrno\b|"
    r"\b(?:EACCES|EPERM|ENOENT|ENOTDIR|EISDIR|EIO|ENOMEM|EAGAIN|"
    r"EMFILE|ENFILE|EBUSY|EEXIST|ENOSPC|EROFS|ENOSYS|EINVAL|"
    r"ETIMEDOUT|ECONNREFUSED|ECONNRESET|EPIPE)\b|"
    r"\b(?:[a-z][a-z0-9_-]*\.){2,}[a-z][a-z0-9_-]*\b"
    r")"
)


def _bounded_tool_result_text(result: Dict[str, Any]) -> str:
    content = result.get("content")
    if not isinstance(content, list):
        return ""

    remaining = TOOL_RESULT_TEXT_INSPECT_LIMIT
    text_items = []
    for item in content:
        if (
            not isinstance(item, dict)
            or item.get("type") != "text"
            or not isinstance(item.get("text"), str)
        ):
            continue
        text = item["text"]
        if not text:
            continue
        encoded = text[:remaining].encode("utf-8")
        consumed = min(len(encoded), remaining)
        bounded = encoded[:remaining].decode("utf-8", errors="ignore")
        if bounded:
            text_items.append(bounded)
        remaining -= consumed
        if remaining == 0:
            break
    return "\n".join(text_items)


def _strip_ansi_and_controls(text: str) -> str:
    text = ANSI_ESCAPE.sub("", text.replace("\r\n", "\n").replace("\r", "\n"))
    return "".join(
        character
        for character in text
        if character in "\n\t"
        or not unicodedata.category(character).startswith("C")
    )


def _redact_path_tail(line: str) -> str:
    match = ABSOLUTE_OR_PRIVATE_PATH_START.search(line)
    if match is None:
        return line

    prefix = line[: match.start()].rstrip("\"'")
    suffix = line[match.start() :]
    safe_signals = []
    for signal_match in SAFE_PATH_SUFFIX_SIGNAL.finditer(suffix):
        signal_text = re.sub(r"\s+", " ", signal_match.group(0)).strip()
        if signal_text not in safe_signals:
            safe_signals.append(signal_text)
        if len(safe_signals) == 4:
            break
    if safe_signals:
        return "{}<path> {}".format(prefix, " ".join(safe_signals))
    return "{}<path>".format(prefix)


def _truncate_utf8(text: str, limit: int) -> str:
    encoded = text.encode("utf-8")
    if len(encoded) <= limit:
        return text
    suffix = " [truncated]"
    prefix_limit = limit - len(suffix.encode("utf-8"))
    prefix = encoded[:prefix_limit].decode("utf-8", errors="ignore").rstrip()
    return "{}{}".format(prefix, suffix)


def _safe_tool_result_diagnostic(text: str) -> str:
    text = _strip_ansi_and_controls(text)
    safe_lines = []
    skip_section = False
    for raw_line in text.splitlines():
        line = re.sub(r"\s+", " ", raw_line).strip()
        if not line:
            continue

        heading = re.match(r"^#{1,6}\s*(.*)$", line)
        if heading is not None:
            heading_text = heading.group(1).strip()
            if re.search(
                r"(?i)\b(?:page state|(?:page )?snapshot|ran playwright code)\b",
                heading_text,
            ):
                skip_section = True
                continue
            skip_section = False
            line = heading_text
        if skip_section:
            continue
        if re.match(r"(?i)^-\s*Page (?:URL|Title|Snapshot)\s*:", line):
            if re.search(r"(?i)Snapshot", line):
                skip_section = True
            continue
        if SENSITIVE_TOOL_RESULT_LINE.search(line) or SECRET_ASSIGNMENT.search(line):
            continue
        unbulleted_line = re.sub(r"^(?:[-*]|\d+\.)\s+", "", line)
        if ENV_ASSIGNMENT.match(unbulleted_line) or ENVIRONMENT_LABEL.search(line):
            continue
        if HEADER_LINE.match(unbulleted_line) and not SAFE_DIAGNOSTIC_HEADER.match(
            unbulleted_line
        ):
            continue
        line = PLAYWRIGHT_DIAGNOSTIC_TAG.sub(r"\1", line)
        if HTML_LINE.search(line):
            continue
        if JSON_LIKE_LINE.match(line) or JSON_FIELD_LINE.match(line):
            continue

        line = FILE_URL_PREFIX.sub("", line)
        line = SCHEME_URL.sub("<url>", line)
        line = QUERY_OR_FRAGMENT_MATERIAL.sub("<url-material>", line)
        line = _redact_path_tail(line)
        line = re.sub(r"\s+", " ", line).strip()
        if line and TOOL_DIAGNOSTIC_SIGNAL.search(line):
            safe_lines.append(line)

    diagnostic = " | ".join(safe_lines)
    return _truncate_utf8(diagnostic, TOOL_RESULT_DIAGNOSTIC_LIMIT)


def _navigation_result_failure(reason: str, text: str) -> NavigationToolResultFailure:
    diagnostic = _safe_tool_result_diagnostic(text)
    if not diagnostic:
        return NavigationToolResultFailure(reason)
    message = "{}: {}".format(reason, diagnostic)
    return NavigationToolResultFailure(
        _truncate_utf8(message, TOOL_RESULT_DIAGNOSTIC_LIMIT)
    )


def _validate_navigation_result(result: Dict[str, Any]) -> None:
    text = _bounded_tool_result_text(result)
    if result.get("isError") is True:
        raise _navigation_result_failure(
            "browser_navigate returned isError true", text
        )
    content = result.get("content")
    if not isinstance(content, list):
        raise SmokeFailure("browser_navigate returned no content")
    if not text:
        raise SmokeFailure("browser_navigate returned no text content")
    if not ABOUT_BLANK_CONFIRMATION.search(text):
        raise _navigation_result_failure(
            "browser_navigate did not confirm the about:blank URL", text
        )


def _process_group_exists(process_group_id: int) -> bool:
    try:
        os.killpg(process_group_id, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError as error:
        raise SmokeFailure("cannot inspect the dedicated process group") from error


def _wait_for_group_exit(
    process: subprocess.Popen, process_group_id: int, timeout_seconds: float
) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        process.poll()
        if not _process_group_exists(process_group_id):
            return True
        time.sleep(0.05)
    process.poll()
    return not _process_group_exists(process_group_id)


def _signal_process_group(process_group_id: int, signal_number: int) -> bool:
    try:
        os.killpg(process_group_id, signal_number)
        return True
    except ProcessLookupError:
        return False


def _cleanup_process_group(
    process: subprocess.Popen, process_group_id: int
) -> Tuple[Optional[str], Optional[SmokeFailure]]:
    if process.stdin is not None:
        try:
            process.stdin.close()
        except OSError:
            pass

    harness_signals = set()
    natural_exit_failure = None  # type: Optional[SmokeFailure]

    def remember_natural_nonzero(returncode: Optional[int]) -> None:
        nonlocal natural_exit_failure
        if returncode is None or returncode == 0 or natural_exit_failure is not None:
            return
        if returncode < 0 and -returncode in harness_signals:
            return
        natural_exit_failure = NaturalProcessExitFailure(
            "cplt exited unsuccessfully after the protocol exchange"
        )

    try:
        exited = _wait_for_group_exit(
            process, process_group_id, GRACEFUL_EXIT_SECONDS
        )
        remember_natural_nonzero(process.poll())
        if not exited:
            if _signal_process_group(process_group_id, signal.SIGTERM):
                harness_signals.add(signal.SIGTERM)
            exited = _wait_for_group_exit(
                process, process_group_id, SIGNAL_EXIT_SECONDS
            )
            remember_natural_nonzero(process.poll())
        if not exited:
            if _signal_process_group(process_group_id, signal.SIGKILL):
                harness_signals.add(signal.SIGKILL)
            exited = _wait_for_group_exit(
                process, process_group_id, SIGNAL_EXIT_SECONDS
            )
            remember_natural_nonzero(process.poll())
        try:
            process.wait(timeout=0.5)
        except subprocess.TimeoutExpired:
            if _process_group_exists(process_group_id):
                if _signal_process_group(process_group_id, signal.SIGKILL):
                    harness_signals.add(signal.SIGKILL)
            process.wait(timeout=SIGNAL_EXIT_SECONDS)
        remember_natural_nonzero(process.returncode)
        if not exited or _process_group_exists(process_group_id):
            return (
                "dedicated process group did not exit after SIGKILL",
                natural_exit_failure,
            )
    except (OSError, SmokeFailure, subprocess.TimeoutExpired):
        return "dedicated process-group cleanup failed", natural_exit_failure
    return None, natural_exit_failure


def _start_self_test_exit_process(returncode: int) -> subprocess.Popen:
    return subprocess.Popen(
        [
            sys.executable,
            "-c",
            "import sys; sys.stdin.buffer.read(); sys.exit(int(sys.argv[1]))",
            str(returncode),
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )


def _self_test_natural_nonzero_exit() -> None:
    process = _start_self_test_exit_process(7)
    assert os.getpgid(process.pid) == process.pid
    cleanup_error, natural_exit_failure = _cleanup_process_group(process, process.pid)
    assert cleanup_error is None
    assert isinstance(natural_exit_failure, NaturalProcessExitFailure)
    assert str(natural_exit_failure) == (
        "cplt exited unsuccessfully after the protocol exchange"
    )


def _self_test_natural_zero_exit() -> None:
    process = _start_self_test_exit_process(0)
    assert os.getpgid(process.pid) == process.pid
    cleanup_error, natural_exit_failure = _cleanup_process_group(process, process.pid)
    assert cleanup_error is None
    assert natural_exit_failure is None


def _self_test_navigation_diagnostic() -> None:
    harmless_marker = "HarmlessBrowserLaunchErrorMarker"
    hostile_text = (
        "\x1b[31mError: {} spawn "
        "/Users/runner/Library/Caches/ms-playwright/chromium-1243/"
        "chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/"
        "Google Chrome for Testing EACCES\x1b[0m\n"
        "browser launch request "
        "https://example.invalid/start?private-query-value#private-fragment-value\n"
        "Authorization: Bearer private-bearer-value\n"
        "token=private-token-value\n"
        "apiKey=private-api-key-value\n"
        "Cookie: private-cookie-value\n"
        "browser launch control\x00marker\n"
    ).format(harmless_marker)
    content = [
        {"type": "image", "text": "private-non-text-value"},
        {"type": "text", "text": hostile_text},
    ]

    for result, expected_reason in (
        (
            {"isError": True, "content": content},
            "browser_navigate returned isError true",
        ),
        (
            {"content": content},
            "browser_navigate did not confirm the about:blank URL",
        ),
    ):
        try:
            _validate_navigation_result(result)
        except NavigationToolResultFailure as failure:
            diagnostic = str(failure)
        else:
            raise AssertionError("hostile navigation result unexpectedly passed")

        assert diagnostic.startswith(expected_reason)
        assert harmless_marker in diagnostic
        assert "EACCES" in diagnostic
        assert "<path>" in diagnostic
        assert "<url>" in diagnostic
        assert len(diagnostic.encode("utf-8")) <= TOOL_RESULT_DIAGNOSTIC_LIMIT
        for private_value in (
            "/Users/runner",
            "Library/Caches",
            "ms-playwright",
            "Google Chrome",
            "private-query-value",
            "private-fragment-value",
            "private-bearer-value",
            "private-token-value",
            "private-api-key-value",
            "private-cookie-value",
            "private-non-text-value",
        ):
            assert private_value not in diagnostic
        assert "\x1b" not in diagnostic
        assert "\x00" not in diagnostic

    try:
        _validate_navigation_result(
            {
                "isError": True,
                "content": [
                    {"type": "text", "text": "Authorization: Bearer private-value"}
                ],
            }
        )
    except NavigationToolResultFailure as failure:
        assert str(failure) == "browser_navigate returned isError true"
    else:
        raise AssertionError("sensitive-only navigation result unexpectedly passed")


def _self_test_socket_directory_lifecycle() -> None:
    with tempfile.TemporaryDirectory(prefix="cplt-playwright-sockets-") as temporary:
        project = Path(temporary).resolve(strict=True)
        owned_directory = _create_socket_directory(project)
        socket_directory = owned_directory[0]
        assert socket_directory == project / PLAYWRIGHT_SOCKET_DIRECTORY_NAME
        assert socket_directory.is_dir()
        assert not socket_directory.is_symlink()
        assert _cleanup_socket_directory(owned_directory) is None
        assert not socket_directory.exists()
        assert not socket_directory.is_symlink()

        socket_directory.mkdir()
        try:
            _create_socket_directory(project)
        except SmokeFailure as failure:
            assert str(failure) == (
                "reserved Playwright socket directory already exists"
            )
        else:
            raise AssertionError("pre-existing socket directory was accepted")
        assert socket_directory.is_dir()


def _self_test_socket_directory_symlink_replacement() -> None:
    with tempfile.TemporaryDirectory(prefix="cplt-playwright-sockets-") as temporary:
        project = Path(temporary).resolve(strict=True)
        owned_directory = _create_socket_directory(project)
        socket_directory = owned_directory[0]
        original_directory = project / "original-pws"
        socket_directory.rename(original_directory)
        socket_directory.symlink_to(original_directory, target_is_directory=True)

        assert _cleanup_socket_directory(owned_directory) == (
            "reserved Playwright socket directory cleanup failed"
        )
        assert socket_directory.is_symlink()
        assert original_directory.is_dir()


def _self_test_socket_directory_popen_failure() -> None:
    with tempfile.TemporaryDirectory(prefix="cplt-playwright-sockets-") as temporary:
        root = Path(temporary).resolve(strict=True)
        project = root / "project"
        runner_temp = root / "runner-temp"
        project.mkdir()
        runner_temp.mkdir()

        try:
            _run_protocol_smoke(
                [str(root / "missing-cplt")], project, runner_temp
            )
        except SmokeFailure as failure:
            assert str(failure) == "could not start the current cplt binary"
        else:
            raise AssertionError("missing cplt executable unexpectedly started")

        socket_directory = project / PLAYWRIGHT_SOCKET_DIRECTORY_NAME
        assert not socket_directory.exists()
        assert not socket_directory.is_symlink()


def _run_protocol_smoke(
    command: List[str], project: Path, runner_temp: Path
) -> Tuple[
    float,
    StderrCapture,
    StdoutReader,
    Optional[str],
    Optional[SmokeFailure],
]:
    child_env = {
        name: os.environ[name]
        for name in (
            "CI",
            "HOME",
            "LANG",
            "LC_ALL",
            "LC_CTYPE",
            "LOGNAME",
            "PATH",
            "SHELL",
            "TERM",
            "TMPDIR",
            "USER",
        )
        if name in os.environ
    }
    empty_config = runner_temp / "playwright-mcp-no-global-config.toml"
    if empty_config.exists():
        raise SmokeFailure("reserved empty cplt config path already exists")
    child_env["CPLT_CONFIG"] = str(empty_config)

    owned_socket_directory = _create_socket_directory(project)
    child_env["PWTEST_SOCKETS_DIR"] = str(owned_socket_directory[0])
    try:
        process = subprocess.Popen(
            command,
            cwd=str(project),
            env=child_env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
    except BaseException as error:
        socket_cleanup_error = _cleanup_socket_directory(owned_socket_directory)
        if socket_cleanup_error is not None:
            raise SmokeFailure(socket_cleanup_error) from error
        if isinstance(error, OSError):
            raise SmokeFailure("could not start the current cplt binary") from error
        raise

    process_group_id = process.pid
    cleanup_error = None
    navigation_elapsed = 0.0
    failure = None  # type: Optional[SmokeFailure]
    stdout_reader = None  # type: Optional[StdoutReader]
    stderr_capture = None  # type: Optional[StderrCapture]
    stdout_started = False
    stderr_started = False
    try:
        if process.stdout is None or process.stderr is None:
            raise SmokeFailure("cplt did not provide all stdio pipes")
        stdout_reader = StdoutReader(process.stdout)
        stderr_capture = StderrCapture(process.stderr)
        stdout_reader.start()
        stdout_started = True
        stderr_capture.start()
        stderr_started = True

        try:
            actual_group_id = os.getpgid(process.pid)
        except ProcessLookupError:
            actual_group_id = process_group_id
        if actual_group_id != process_group_id:
            raise SmokeFailure("cplt did not start in its dedicated process group")

        initialize = _request(
            process,
            stdout_reader,
            1,
            "initialize",
            {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "cplt-ci-smoke", "version": "1.0"},
            },
            INITIALIZE_TIMEOUT_SECONDS,
        )
        _validate_initialize(initialize)

        _send(
            process,
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
        )

        tools = _request(
            process,
            stdout_reader,
            2,
            "tools/list",
            {},
            TOOLS_LIST_TIMEOUT_SECONDS,
        )
        _validate_navigate_tool(tools)

        navigation_started = time.monotonic()
        navigation = _request(
            process,
            stdout_reader,
            3,
            "tools/call",
            {
                "name": "browser_navigate",
                "arguments": {"url": "about:blank"},
            },
            NAVIGATE_TIMEOUT_SECONDS,
        )
        navigation_elapsed = time.monotonic() - navigation_started
        _validate_navigation_result(navigation)
    except SmokeFailure as error:
        failure = error
    except Exception:
        failure = SmokeFailure("unexpected local protocol error")
    finally:
        try:
            cleanup_error, natural_exit_failure = _cleanup_process_group(
                process, process_group_id
            )
            if failure is None and natural_exit_failure is not None:
                failure = natural_exit_failure
            stdout_stopped = not stdout_started or stdout_reader.join()
            stderr_stopped = not stderr_started or stderr_capture.join()
            if not stdout_stopped or not stderr_stopped:
                cleanup_error = (
                    cleanup_error
                    or "stdio drains remained open after process-group cleanup"
                )
        finally:
            socket_cleanup_error = _cleanup_socket_directory(
                owned_socket_directory
            )
            cleanup_error = cleanup_error or socket_cleanup_error

    if stdout_reader is None or stderr_capture is None:
        if failure is not None:
            raise failure
        raise SmokeFailure("cplt stdio setup failed")

    return (
        navigation_elapsed,
        stderr_capture,
        stdout_reader,
        cleanup_error,
        failure,
    )


def _run_self_test() -> None:
    _self_test_natural_nonzero_exit()
    _self_test_natural_zero_exit()
    _self_test_navigation_diagnostic()

    root = Path("/ci/project")
    prefix = Path("/ci/runner-temp/playwright-mcp-0.0.80")
    command = _build_command(
        root / "target/debug/cplt",
        root,
        prefix,
        Path("/usr/local/bin/node"),
        prefix / "node_modules/@playwright/mcp/cli.js",
        Path(
            "/Users/runner/Library/Caches/ms-playwright/"
            "chromium-1243/chrome-mac-arm64/"
            "Google Chrome for Testing.app/Contents/MacOS/"
            "Google Chrome for Testing"
        ),
    )
    exec_index = command.index("exec")
    grant_flags = [
        value
        for value in command[:exec_index]
        if value.startswith("--allow-")
    ]
    assert grant_flags == ["--allow-cache-exec", "--allow-read"]
    assert command[:exec_index].count("--allow-cache-exec") == 1
    assert command[command.index("--allow-cache-exec") + 1] == "ms-playwright"
    assert command[:exec_index].count("--allow-read") == 1
    assert command[command.index("--allow-read") + 1] == str(prefix)
    assert "--allow-write" not in command
    assert "--allow-socket" not in command
    assert command.count("--pass-env") == 1
    pass_env_index = command.index("--pass-env")
    assert pass_env_index < exec_index
    assert command[pass_env_index + 1] == "PWTEST_SOCKETS_DIR"
    assert command.count("PWTEST_SOCKETS_DIR") == 1
    assert command[exec_index + 1] == "--"
    assert command[exec_index + 2] == "/usr/local/bin/node"
    assert "--isolated" in command
    _self_test_socket_directory_lifecycle()
    _self_test_socket_directory_symlink_replacement()
    _self_test_socket_directory_popen_failure()

    valid_tool = {
        "tools": [
            {
                "name": "browser_navigate",
                "inputSchema": {
                    "type": "object",
                    "required": ["url"],
                    "properties": {"url": {"type": "string"}},
                },
            }
        ]
    }
    _validate_navigate_tool(valid_tool)
    _validate_navigation_result(
        {
            "content": [
                {
                    "type": "text",
                    "text": "### Page state\n- Page URL: about:blank\n",
                }
            ]
        }
    )
    parsed = _parse_stdout_line(b'{"jsonrpc":"2.0","id":1,"result":{}}')
    assert parsed["id"] == 1
    print("playwright MCP smoke self-test: ok")


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--runner-temp", type=Path)
    parser.add_argument("--project-dir", type=Path)
    parser.add_argument("--mcp-prefix", type=Path)
    parser.add_argument("--cplt-binary", type=Path)
    parser.add_argument("--node-binary", type=Path)
    parser.add_argument("--chrome-binary", type=Path)
    args = parser.parse_args()
    if not args.self_test:
        required = (
            "runner_temp",
            "project_dir",
            "mcp_prefix",
            "cplt_binary",
            "node_binary",
            "chrome_binary",
        )
        missing = [name.replace("_", "-") for name in required if getattr(args, name) is None]
        if missing:
            parser.error("missing required arguments: {}".format(", ".join(missing)))
    return args


def main() -> int:
    args = _parse_args()
    if args.self_test:
        _run_self_test()
        return 0

    stderr_capture = None  # type: Optional[StderrCapture]
    try:
        (
            runner_temp,
            project,
            prefix,
            cplt,
            node,
            chrome,
        ) = _validate_paths(
            args.runner_temp,
            args.project_dir,
            args.mcp_prefix,
            args.cplt_binary,
            args.node_binary,
            args.chrome_binary,
        )
        cli_path, browser_identity = _installed_identity(prefix)
        command = _build_command(cplt, project, prefix, node, cli_path, chrome)
        (
            navigation_elapsed,
            stderr_capture,
            stdout_reader,
            cleanup_error,
            protocol_failure,
        ) = _run_protocol_smoke(command, project, runner_temp)
        if protocol_failure is not None:
            raise protocol_failure
        reader_failure = stdout_reader.failure()
        if reader_failure is not None:
            raise reader_failure
        if cleanup_error is not None:
            raise SmokeFailure(cleanup_error)
    except SmokeFailure as failure:
        print("playwright MCP smoke failed: {}".format(failure), file=sys.stderr)
        if stderr_capture is not None and not isinstance(
            failure, (NaturalProcessExitFailure, NavigationToolResultFailure)
        ):
            diagnostic = stderr_capture.diagnostic()
            if diagnostic:
                print("bounded stderr:\n{}".format(diagnostic), file=sys.stderr)
        return 1
    except Exception:
        print("playwright MCP smoke failed: unexpected local error", file=sys.stderr)
        if stderr_capture is not None:
            diagnostic = stderr_capture.diagnostic()
            if diagnostic:
                print("bounded stderr:\n{}".format(diagnostic), file=sys.stderr)
        return 1

    print(
        "playwright-mcp={} playwright-core={} chromium-revision={} "
        "browser={} about:blank navigation={:.3f}s".format(
            MCP_PACKAGE_VERSION,
            PLAYWRIGHT_CORE_VERSION,
            CHROMIUM_REVISION,
            browser_identity,
            navigation_elapsed,
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
