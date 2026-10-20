"""GitHub Releases updater helpers for the frozen Windows desktop build."""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

OWNER = "TokenScience01"
REPOSITORY = "tabbyShop"
RELEASES_API = f"https://api.github.com/repos/{OWNER}/{REPOSITORY}/releases/latest"
RELEASES_PAGE = f"https://github.com/{OWNER}/{REPOSITORY}/releases/latest"
APP_VERSION = "1.2.10"
ASSET_NAME = "TabbyDesktop-windows-x64.zip"


def github_headers() -> dict[str, str]:
    """Use an existing GitHub CLI login when available; never persist its token."""
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "TabbyDesktop-Updater"}
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if not token and shutil.which("gh"):
        try:
            result = subprocess.run(
                ["gh", "auth", "token", "--hostname", "github.com"],
                capture_output=True, text=True, timeout=5, check=True,
            )
            token = result.stdout.strip()
        except (OSError, subprocess.SubprocessError):
            token = ""
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def version_tuple(value: str) -> tuple[int, ...]:
    numbers = re.findall(r"\d+", value)
    if not numbers:
        raise ValueError("GitHub Release 标签中没有有效版本号")
    parts = [int(number) for number in numbers[:4]]
    return tuple(parts + [0] * (4 - len(parts)))


def fetch_latest_release(timeout: int = 15) -> dict:
    headers = github_headers()
    request = urllib.request.Request(RELEASES_API, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            release = json.load(response)
    except urllib.error.HTTPError as exc:
        if exc.code != 404:
            raise
        # GitHub's /releases/latest returns 404 until a non-draft stable
        # release exists. Query the collection to distinguish that normal
        # first-install state from an inaccessible repository.
        listing_request = urllib.request.Request(
            f"https://api.github.com/repos/{OWNER}/{REPOSITORY}/releases?per_page=10",
            headers=headers,
        )
        try:
            with urllib.request.urlopen(listing_request, timeout=timeout) as response:
                releases = json.load(response)
        except urllib.error.HTTPError as listing_error:
            if listing_error.code == 404:
                return {"repository_unavailable": True, "is_newer": False,
                        "version": None, "asset": None}
            raise
        release = next((item for item in releases
                        if not item.get("draft") and not item.get("prerelease")), None)
        if release is None:
            return {"no_release": True, "is_newer": False, "version": None, "asset": None}
    tag = str(release.get("tag_name", ""))
    release["version"] = tag.lstrip("vV")
    release["is_newer"] = version_tuple(release["version"]) > version_tuple(APP_VERSION)
    release["asset"] = next(
        (asset for asset in release.get("assets", []) if asset.get("name") == ASSET_NAME), None
    )
    return release


def download_asset(asset: dict, destination: Path, timeout: int = 60) -> Path:
    """Download a private release asset through its authenticated API endpoint."""
    url = str(asset.get("url", ""))
    if not url.startswith("https://"):
        raise ValueError("更新包地址不是安全的 HTTPS 地址")
    headers = github_headers()
    headers["Accept"] = "application/octet-stream"
    request = urllib.request.Request(url, headers=headers)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(request, timeout=timeout) as response, destination.open("wb") as output:
        shutil.copyfileobj(response, output)
    if not zipfile.is_zipfile(destination):
        destination.unlink(missing_ok=True)
        raise ValueError("GitHub 下载内容不是有效的更新压缩包")
    return destination


def prepare_windows_update(archive: Path, install_dir: Path) -> Path:
    """Extract a verified-layout release and create a detached replace/relaunch script."""
    if os.name != "nt":
        raise RuntimeError("自动替换目前只支持 Windows 桌面版")
    install_dir = install_dir.resolve()
    # Stage beside the installation so the directory swap stays on the same
    # volume. Windows' move command cannot reliably rename across drives.
    stage = Path(tempfile.mkdtemp(prefix=".tabby-update-", dir=install_dir.parent))
    try:
        with zipfile.ZipFile(archive) as bundle:
            names = bundle.namelist()
            if not names or any(Path(name).is_absolute() or ".." in Path(name).parts for name in names):
                raise ValueError("更新包包含无效路径")
            expected = "TabbyDesktop/TabbyDesktop.exe"
            if expected not in names:
                raise ValueError("更新包内找不到 TabbyDesktop.exe")
            bundle.extractall(stage)
        staged_app = stage / "TabbyDesktop"
        if not (staged_app / "TabbyDesktop.exe").is_file():
            raise ValueError("更新包结构不完整")

        script = stage / "install-update.bat"
        backup = install_dir.with_name(install_dir.name + ".previous")
        script.write_text(
            _windows_update_script(stage, staged_app, install_dir, backup, os.getpid()),
            encoding="utf-8",
        )
        return script
    except Exception:
        shutil.rmtree(stage, ignore_errors=True)
        raise


def _windows_update_script(stage: Path, staged_app: Path, install_dir: Path,
                           backup: Path, app_pid: int) -> str:
    """Build a logged, rollback-capable same-volume Windows directory swap."""
    exe = install_dir / "TabbyDesktop.exe"
    stage = Path(stage)
    return (
        "@echo off\r\nsetlocal EnableExtensions\r\n"
        "set \"TARGET=" + str(install_dir) + "\"\r\n"
        "set \"STAGED=" + str(staged_app) + "\"\r\n"
        "set \"STAGE=" + str(stage) + "\"\r\n"
        "set \"BACKUP=" + str(backup) + "\"\r\n"
        "set \"EXE=" + str(exe) + "\"\r\n"
        "set \"APP_PID=" + str(app_pid) + "\"\r\n"
        "set \"LOG=%LOCALAPPDATA%\\TabbyDesktop\\update.log\"\r\n"
        "if not exist \"%LOCALAPPDATA%\\TabbyDesktop\" mkdir \"%LOCALAPPDATA%\\TabbyDesktop\" >nul 2>&1\r\n"
        ">\"%LOG%\" echo Tabby update started.\r\n"
        ">>\"%LOG%\" echo Install directory: %TARGET%\r\n"
        ":wait\r\n"
        "tasklist /FI \"PID eq %APP_PID%\" | find \"%APP_PID%\" >nul\r\n"
        "if not errorlevel 1 (timeout /t 1 /nobreak >nul & goto wait)\r\n"
        "if exist \"%BACKUP%\" rmdir /s /q \"%BACKUP%\" >>\"%LOG%\" 2>&1\r\n"
        "if exist \"%BACKUP%\" goto failed\r\n"
        "if not exist \"%TARGET%\" goto install\r\n"
        "move \"%TARGET%\" \"%BACKUP%\" >>\"%LOG%\" 2>&1\r\n"
        "if errorlevel 1 goto failed\r\n"
        ":install\r\n"
        "move \"%STAGED%\" \"%TARGET%\" >>\"%LOG%\" 2>&1\r\n"
        "if errorlevel 1 goto rollback\r\n"
        "if not exist \"%EXE%\" goto rollback\r\n"
        "start \"\" \"%EXE%\"\r\n"
        "if errorlevel 1 goto rollback\r\n"
        ">>\"%LOG%\" echo Tabby update completed.\r\n"
        "rmdir /s /q \"%STAGE%\" >>\"%LOG%\" 2>&1\r\n"
        "exit /b 0\r\n"
        ":rollback\r\n"
        ">>\"%LOG%\" echo Update failed; restoring previous application.\r\n"
        "if exist \"%TARGET%\" rmdir /s /q \"%TARGET%\" >>\"%LOG%\" 2>&1\r\n"
        "if exist \"%BACKUP%\" move \"%BACKUP%\" \"%TARGET%\" >>\"%LOG%\" 2>&1\r\n"
        ":failed\r\n"
        ">>\"%LOG%\" echo Update did not complete.\r\n"
        "start \"\" powershell.exe -NoProfile -Command \"Add-Type -AssemblyName PresentationFramework; [System.Windows.MessageBox]::Show('Tabby update failed. See update.log in Local AppData.','Tabby updater')\"\r\n"
        "if exist \"%EXE%\" start \"\" \"%EXE%\"\r\n"
        "exit /b 1\r\n"
    )


def launch_update_script(script: Path) -> None:
    if os.name != "nt":
        raise RuntimeError("自动替换目前只支持 Windows 桌面版")
    flags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) | getattr(subprocess, "DETACHED_PROCESS", 0)
    command = f'"{os.environ.get("COMSPEC", "cmd.exe")}" /d /s /c ""{script.resolve()}""'
    subprocess.Popen(command, creationflags=flags, close_fds=True)


def is_frozen_windows() -> bool:
    return os.name == "nt" and bool(getattr(sys, "frozen", False))
