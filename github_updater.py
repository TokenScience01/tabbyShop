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
APP_VERSION = "1.2.21"
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

        script = stage / "install-update.ps1"
        backup = install_dir.with_name(install_dir.name + ".previous")
        script.write_text(
            _windows_update_script(stage, staged_app, install_dir, backup, os.getpid()),
            encoding="utf-8-sig",
        )
        return script
    except Exception:
        shutil.rmtree(stage, ignore_errors=True)
        raise


def _windows_update_script(stage: Path, staged_app: Path, install_dir: Path,
                           backup: Path, app_pid: int) -> str:
    """Build a Unicode-safe, logged, rollback-capable Windows directory swap."""
    exe = install_dir / "TabbyDesktop.exe"
    def ps_literal(path: Path | str) -> str:
        return "'" + str(path).replace("'", "''") + "'"

    return "\r\n".join((
        "$ErrorActionPreference = 'Stop'",
        f"$target = {ps_literal(install_dir)}",
        f"$staged = {ps_literal(staged_app)}",
        f"$stage = {ps_literal(stage)}",
        f"$backup = {ps_literal(backup)}",
        f"$exe = {ps_literal(exe)}",
        f"$appPid = {int(app_pid)}",
        "$appData = [Environment]::GetFolderPath('LocalApplicationData')",
        "$logDir = Join-Path $appData 'TabbyDesktop'",
        "$log = Join-Path $logDir 'update.log'",
        "$movedOld = $false",
        "$installedNew = $false",
        "function Write-UpdateLog([string]$message) {",
        "  try { Add-Content -LiteralPath $log -Encoding UTF8 -Value ('[{0}] {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $message) } catch { }",
        "}",
        "try {",
        "  New-Item -ItemType Directory -Path $logDir -Force | Out-Null",
        "  Write-UpdateLog 'Updater started.'",
        "  Write-UpdateLog ('Install directory: ' + $target)",
        "  Write-UpdateLog ('Waiting for application process ' + $appPid)",
        "  $deadline = (Get-Date).AddSeconds(300)",
        "  while (Get-Process -Id $appPid -ErrorAction SilentlyContinue) {",
        "    if ((Get-Date) -ge $deadline) { throw 'Timed out waiting for Tabby to exit.' }",
        "    Start-Sleep -Seconds 1",
        "  }",
        "  Write-UpdateLog 'Application exited; replacing files.'",
        "  if (Test-Path -LiteralPath $backup) { Remove-Item -LiteralPath $backup -Recurse -Force -ErrorAction SilentlyContinue }",
        "  if (Test-Path -LiteralPath $target) {",
        "    Move-Item -LiteralPath $target -Destination $backup",
        "    $movedOld = $true",
        "  }",
        "  Move-Item -LiteralPath $staged -Destination $target",
        "  $installedNew = $true",
        "  if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) { throw 'New executable is missing after install.' }",
        "  Write-UpdateLog 'New files installed; starting the updated application.'",
        "  $newProcess = Start-Process -FilePath $exe -PassThru",
        "  Start-Sleep -Seconds 5",
        "  $newProcess.Refresh()",
        "  if ($newProcess.HasExited) { throw ('Updated application exited during startup (code ' + $newProcess.ExitCode + ').') }",
        "  Write-UpdateLog ('Updated application started (PID ' + $newProcess.Id + ').')",
        "  if (Test-Path -LiteralPath $backup) { Remove-Item -LiteralPath $backup -Recurse -Force }",
        "  Write-UpdateLog 'Tabby update completed successfully.'",
        "  Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue",
        "  exit 0",
        "} catch {",
        "  $failure = $_.Exception.Message",
        "  Write-UpdateLog ('UPDATE FAILED: ' + $failure)",
        "  if ($installedNew -and (Test-Path -LiteralPath $target)) { Remove-Item -LiteralPath $target -Recurse -Force -ErrorAction SilentlyContinue }",
        "  if ($movedOld -and (Test-Path -LiteralPath $backup)) {",
        "    Move-Item -LiteralPath $backup -Destination $target -ErrorAction SilentlyContinue",
        "    Write-UpdateLog 'Previous application restored.'",
        "  }",
        "  if (Test-Path -LiteralPath $exe -PathType Leaf) { Start-Process -FilePath $exe -ErrorAction SilentlyContinue }",
        "  Add-Type -AssemblyName PresentationFramework",
        "  [System.Windows.MessageBox]::Show(('Tabby update failed: ' + $failure + [Environment]::NewLine + 'Details: ' + $log), 'Tabby updater') | Out-Null",
        "  exit 1",
        "}",
        "",
    ))


def launch_update_script(script: Path) -> None:
    if os.name != "nt":
        raise RuntimeError("自动替换目前只支持 Windows 桌面版")
    flags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) | getattr(subprocess, "DETACHED_PROCESS", 0)
    script_path = str(script.resolve())
    # PowerShell handles Unicode paths and paths containing spaces reliably;
    # unlike cmd.exe, it also gives us useful exceptions for the update log.
    command = ["powershell.exe", "-NoLogo", "-NoProfile", "-ExecutionPolicy", "Bypass",
               "-File", script_path]
    subprocess.Popen(command, creationflags=flags, close_fds=True,
                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                     stderr=subprocess.DEVNULL)


def is_frozen_windows() -> bool:
    return os.name == "nt" and bool(getattr(sys, "frozen", False))
