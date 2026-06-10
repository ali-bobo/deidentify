#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
setup_and_run.py — One-click launcher (checks environment → installs deps → runs de-identification)

General users only need to run this script:
    python setup_and_run.py <file> [options]

It will:
  1. Check Python version (requires 3.9+)
  2. Check whether presidio / spacy are already installed
  3. If missing → install latest versions from official PyPI
  4. After install, perform an actual import verification to confirm
     the latest versions are mutually compatible and load correctly
  5. Once ready, invoke deidentify.py for de-identification

Security design:
  - Only installs from official PyPI; never executes downloaded code
  - Lists packages to be installed and asks for confirmation before proceeding
    (unless --yes is passed)
  - Performs import verification after install; if latest versions are
    incompatible, the error is reported immediately rather than mid-processing

Supported options (passed through to deidentify.py):
  --keep-public-ip          Retain public IPs (useful for external C2 analysis)
  -w KEYWORD                Manually specify terms to redact (repeatable)
  --custom-id-pattern REGEX Register an extra regex as a custom ID entity (repeatable)
  --redact-uuid             Enable UUID redaction (off by default)
  --no-dedup                Disable duplicate event filtering for EDR-style CSVs
  --max-mb N                Per-file output size limit in MB (default: 10)
  --output-dir DIR          Output folder for de-identified files
  --mapping-dir DIR         Folder for reversal mapping files
  --yes                     Skip install confirmation prompt (for CI/automation)
"""

import sys
import subprocess
import importlib.metadata as md

# ---- 需要的套件（不鎖版本，安裝最新版）----
REQUIRED = ["presidio-analyzer", "presidio-anonymizer", "spacy", "click"]

MIN_PYTHON = (3, 9)


def check_python():
    if sys.version_info < MIN_PYTHON:
        print(f"[錯誤] 需要 Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]} 以上，"
              f"目前為 {sys.version_info[0]}.{sys.version_info[1]}")
        sys.exit(1)


def installed_version(pkg):
    try:
        return md.version(pkg)
    except md.PackageNotFoundError:
        return None


def find_missing():
    """回傳尚未安裝的套件清單。"""
    return [pkg for pkg in REQUIRED if installed_version(pkg) is None]


def confirm(prompt):
    try:
        ans = input(prompt + " [y/N] ").strip().lower()
    except EOFError:
        return False
    return ans in ("y", "yes")


def install(missing, auto_yes):
    print("-" * 60)
    print(" 需要安裝以下套件（將安裝最新版）：")
    for pkg in missing:
        print(f"   - {pkg}")
    print("-" * 60)

    if not auto_yes and not confirm("確認從官方 PyPI 安裝最新版？"):
        print("已取消。請手動安裝後再執行。")
        sys.exit(1)

    # 安裝最新版（不指定版本號），只用官方 PyPI（pip 預設來源）
    # --upgrade-strategy eager 強制重新解析傳遞依賴，防止半殘環境殘留舊版
    cmd = [sys.executable, "-m", "pip", "install", "--upgrade",
           "--upgrade-strategy", "eager", *missing]
    print(f"[執行] {' '.join(cmd)}")
    result = subprocess.run(cmd)
    if result.returncode != 0:
        print("[錯誤] 安裝失敗，請檢查網路或權限。")
        sys.exit(1)


def verify_imports():
    """實際 import 驗證：確認最新版彼此相容、能正常載入。"""
    try:
        import presidio_analyzer  # noqa: F401
        import presidio_anonymizer  # noqa: F401
        import spacy  # noqa: F401
        import click  # noqa: F401
        from presidio_analyzer import AnalyzerEngine  # noqa: F401
        from presidio_anonymizer import AnonymizerEngine  # noqa: F401
    except Exception as e:
        print("-" * 60)
        print("[錯誤] 套件已安裝，但 import 驗證失敗，可能是最新版之間不相容：")
        print(f"       {type(e).__name__}: {e}")
        print("  建議：改裝相容的版本，例如限制 spaCy 大版本")
        print('       pip install "spacy<4" presidio-analyzer presidio-anonymizer')
        print("-" * 60)
        sys.exit(1)
    print("[OK] 相依套件可正常載入。目前版本：")
    for pkg in REQUIRED:
        print(f"   - {pkg} {installed_version(pkg)}")


def main():
    check_python()

    passthrough = [a for a in sys.argv[1:] if a != "--yes"]
    auto_yes = "--yes" in sys.argv[1:]

    missing = find_missing()
    if missing:
        install(missing, auto_yes)
    verify_imports()

    if not passthrough:
        print("\n環境就緒。請帶入要處理的檔案，例如：")
        print("   python setup_and_run.py input.log")
        return

    from pathlib import Path
    main_py = Path(__file__).with_name("deidentify.py")
    if not main_py.exists():
        print(f"[錯誤] 找不到主程式 {main_py.name}，請確認與本啟動器放在同一資料夾。")
        sys.exit(1)

    print("\n環境就緒，開始去識別化…\n")
    subprocess.run([sys.executable, str(main_py), *passthrough])


if __name__ == "__main__":
    main()
