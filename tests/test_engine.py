"""
TDD tests for DeidentifyEngine — GUI 邏輯層

規格：
- DeidentifyEngine(exe_dir) 初始化，exe_dir 是程式所在目錄
- load_rules_if_present() 回傳 {"loaded": bool, "keywords": int, "patterns": int}
  - 若 exe_dir/rules.yaml 存在則載入，loaded=True
  - 若不存在則 loaded=False，keywords=0，patterns=0
- run(files, options) 對每個檔案執行去識別化，回傳 list[dict]
  - 每個 dict: {"file": Path, "success": bool, "output": Path|None, "error": str|None}
- options dict 支援: keep_public_ip, redact_uuid（兩者預設 False）
- 執行完成後 entity_mapping 跨檔案共用（同 session 內同一個 IP 得到同一個佔位符）
- 輸出放在 exe_dir/deidentified_output/
- mapping 放在 exe_dir/deidentify_mapping/
"""

import pytest
from pathlib import Path
from engine import DeidentifyEngine


# ===========================================================
# 初始化 & rules.yaml 自動載入
# ===========================================================

def test_engine_loads_rules_when_present(tmp_path):
    rules = tmp_path / "rules.yaml"
    rules.write_text("block:\n  - ProjectX\n  - SecretOps\n", encoding="utf-8")
    engine = DeidentifyEngine(exe_dir=tmp_path)
    info = engine.load_rules_if_present()
    assert info["loaded"] is True
    assert info["keywords"] == 2
    assert info["patterns"] == 0


def test_engine_no_rules_file_returns_not_loaded(tmp_path):
    engine = DeidentifyEngine(exe_dir=tmp_path)
    info = engine.load_rules_if_present()
    assert info["loaded"] is False
    assert info["keywords"] == 0
    assert info["patterns"] == 0


def test_engine_loads_block_patterns(tmp_path):
    rules = tmp_path / "rules.yaml"
    rules.write_text(
        "block:\n  - ProjectX\nblock_patterns:\n  - 'SRV\\d+'\n  - 'PROJ-\\d+'\n",
        encoding="utf-8",
    )
    engine = DeidentifyEngine(exe_dir=tmp_path)
    info = engine.load_rules_if_present()
    assert info["loaded"] is True
    assert info["keywords"] == 1
    assert info["patterns"] == 2


# ===========================================================
# run() — 基本執行
# ===========================================================

def test_run_returns_success_for_valid_text_file(tmp_path):
    log = tmp_path / "test.log"
    log.write_text("User john.smith logged in from 192.168.1.1\n", encoding="utf-8")
    engine = DeidentifyEngine(exe_dir=tmp_path)
    results = engine.run([log], options={})
    assert len(results) == 1
    assert results[0]["success"] is True
    assert results[0]["file"] == log
    assert results[0]["output"] is not None
    assert results[0]["output"].exists()
    assert results[0]["error"] is None


def test_run_output_in_exe_dir(tmp_path):
    log = tmp_path / "sample.log"
    log.write_text("test line\n", encoding="utf-8")
    engine = DeidentifyEngine(exe_dir=tmp_path)
    results = engine.run([log], options={})
    output = results[0]["output"]
    assert str(tmp_path) in str(output)


def test_run_returns_error_for_missing_file(tmp_path):
    missing = tmp_path / "nonexistent.log"
    engine = DeidentifyEngine(exe_dir=tmp_path)
    results = engine.run([missing], options={})
    assert len(results) == 1
    assert results[0]["success"] is False
    assert results[0]["error"] is not None


def test_run_multiple_files(tmp_path):
    f1 = tmp_path / "a.log"
    f2 = tmp_path / "b.log"
    f1.write_text("line from 192.168.1.1\n", encoding="utf-8")
    f2.write_text("another line\n", encoding="utf-8")
    engine = DeidentifyEngine(exe_dir=tmp_path)
    results = engine.run([f1, f2], options={})
    assert len(results) == 2
    assert all(r["success"] for r in results)


# ===========================================================
# 跨檔案 entity mapping 一致性
# ===========================================================

def test_same_ip_gets_same_placeholder_across_files(tmp_path):
    f1 = tmp_path / "first.log"
    f2 = tmp_path / "second.log"
    f1.write_text("connect from 10.0.0.5\n", encoding="utf-8")
    f2.write_text("alert from 10.0.0.5\n", encoding="utf-8")

    engine = DeidentifyEngine(exe_dir=tmp_path)
    engine.run([f1, f2], options={})

    out1 = (tmp_path / "deidentified_output" / "first_deidentified.json").read_text(encoding="utf-8")
    out2 = (tmp_path / "deidentified_output" / "second_deidentified.json").read_text(encoding="utf-8")

    import json, re
    placeholder_pattern = re.compile(r"<INT_IP_\d+>")
    p1 = placeholder_pattern.findall(out1)
    p2 = placeholder_pattern.findall(out2)

    assert p1, "first.log 應該有 IP 佔位符"
    assert p2, "second.log 應該有 IP 佔位符"
    assert p1[0] == p2[0], "同一個 IP 在不同檔案應得到相同佔位符"


# ===========================================================
# options 傳遞
# ===========================================================

def test_keep_public_ip_option_preserves_public_ip(tmp_path):
    log = tmp_path / "pub.log"
    log.write_text("connect to 8.8.8.8\n", encoding="utf-8")
    engine = DeidentifyEngine(exe_dir=tmp_path)
    engine.run([log], options={"keep_public_ip": True})
    out = (tmp_path / "deidentified_output" / "pub_deidentified.json").read_text(encoding="utf-8")
    assert "8.8.8.8" in out


# ===========================================================
# rules.yaml 整合到 run()
# ===========================================================

def test_rules_keywords_applied_in_run(tmp_path):
    rules = tmp_path / "rules.yaml"
    rules.write_text("block:\n  - ProjectX\n", encoding="utf-8")
    log = tmp_path / "secret.log"
    log.write_text("Attacker targeted ProjectX system\n", encoding="utf-8")

    engine = DeidentifyEngine(exe_dir=tmp_path)
    engine.run([log], options={})

    out = (tmp_path / "deidentified_output" / "secret_deidentified.json").read_text(encoding="utf-8")
    assert "ProjectX" not in out
