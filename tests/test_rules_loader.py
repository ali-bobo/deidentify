"""
TDD tests for load_rules() — YAML 規則檔讀取功能

規格：
- load_rules(path) 讀取 YAML 檔，回傳 {"block": [...], "block_patterns": [...]}
- block 列表：字串關鍵字，效果等同 -w
- block_patterns 列表：regex 字串，匹配子字串也遮蔽
- 若只有 block 沒有 block_patterns，回傳 block_patterns=[]，反之亦然
- 若檔案不存在，raise FileNotFoundError
- 若 YAML 格式錯誤（不是 dict），raise ValueError
- 若 block 或 block_patterns 內容不是 list，raise ValueError
- 空檔案視為 {"block": [], "block_patterns": []}
"""

import pytest
import yaml
from pathlib import Path


# ---- 待實作的函數 (尚未存在，測試必須先失敗) ----
from deidentify import load_rules


# ===========================================================
# 基本載入
# ===========================================================

def test_load_rules_returns_block_list(tmp_path):
    f = tmp_path / "rules.yaml"
    f.write_text("block:\n  - ProjectX\n  - HR-System\n", encoding="utf-8")
    result = load_rules(f)
    assert result["block"] == ["ProjectX", "HR-System"]


def test_load_rules_returns_block_patterns(tmp_path):
    f = tmp_path / "rules.yaml"
    f.write_text('block_patterns:\n  - "PROJ-\\\\d+"\n  - "SRV\\\\d{3}"\n', encoding="utf-8")
    result = load_rules(f)
    assert result["block_patterns"] == [r"PROJ-\d+", r"SRV\d{3}"]


def test_load_rules_both_keys(tmp_path):
    f = tmp_path / "rules.yaml"
    # YAML 單引號不做逸脫，\d 就是字面上的 \d，這是使用者正確寫法
    f.write_text(
        "block:\n  - finance-team\nblock_patterns:\n  - 'PROJ-\\d+'\n",
        encoding="utf-8",
    )
    result = load_rules(f)
    assert result["block"] == ["finance-team"]
    assert result["block_patterns"] == [r"PROJ-\d+"]


# ===========================================================
# 缺少其中一個 key → 補上空 list
# ===========================================================

def test_load_rules_missing_block_patterns_defaults_to_empty(tmp_path):
    f = tmp_path / "rules.yaml"
    f.write_text("block:\n  - SomeKeyword\n", encoding="utf-8")
    result = load_rules(f)
    assert result["block_patterns"] == []


def test_load_rules_missing_block_defaults_to_empty(tmp_path):
    f = tmp_path / "rules.yaml"
    f.write_text('block_patterns:\n  - "SRV\\\\d+"\n', encoding="utf-8")
    result = load_rules(f)
    assert result["block"] == []


# ===========================================================
# 空檔案
# ===========================================================

def test_load_rules_empty_file_returns_empty_lists(tmp_path):
    f = tmp_path / "rules.yaml"
    f.write_text("", encoding="utf-8")
    result = load_rules(f)
    assert result == {"block": [], "block_patterns": []}


# ===========================================================
# 錯誤處理
# ===========================================================

def test_load_rules_missing_file_raises_file_not_found():
    with pytest.raises(FileNotFoundError):
        load_rules(Path("/nonexistent/path/rules.yaml"))


def test_load_rules_invalid_yaml_root_not_dict_raises_value_error(tmp_path):
    f = tmp_path / "rules.yaml"
    f.write_text("- item1\n- item2\n", encoding="utf-8")
    with pytest.raises(ValueError, match="rules.yaml 格式錯誤"):
        load_rules(f)


def test_load_rules_block_not_list_raises_value_error(tmp_path):
    f = tmp_path / "rules.yaml"
    f.write_text("block: ProjectX\n", encoding="utf-8")
    with pytest.raises(ValueError, match="block"):
        load_rules(f)


def test_load_rules_block_patterns_not_list_raises_value_error(tmp_path):
    f = tmp_path / "rules.yaml"
    # block_patterns 的值是純字串而非 list，這是格式錯誤
    f.write_text("block_patterns: some-pattern\n", encoding="utf-8")
    with pytest.raises(ValueError, match="block_patterns"):
        load_rules(f)


# ===========================================================
# block_patterns 編譯驗證（無效 regex 要報錯）
# ===========================================================

def test_load_rules_invalid_regex_in_block_patterns_raises_value_error(tmp_path):
    f = tmp_path / "rules.yaml"
    f.write_text('block_patterns:\n  - "[invalid"\n', encoding="utf-8")
    with pytest.raises(ValueError, match="無效的 regex"):
        load_rules(f)
