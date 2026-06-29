"""
TDD tests for block_patterns 整合到 redact_keywords()

規格：
- redact_keywords() 接受額外參數 block_patterns: List[str]（預設 []）
- block_patterns 每條 regex 匹配到的子字串替換為 <KEYWORD_N>
- block_patterns 與 block 關鍵字共用同一個 KEYWORD bucket（確保一致性）
- 無 block_patterns 時行為與現有完全相同（向下相容）
"""

import pytest
from deidentify import redact_keywords


def test_block_patterns_replaces_matched_substring():
    mapping = {}
    result = redact_keywords(
        "Alert on server SRV001 detected",
        keywords=[],
        entity_mapping=mapping,
        block_patterns=[r"SRV\d+"],
    )
    assert "SRV001" not in result
    assert "<KEYWORD_1>" in result


def test_block_patterns_consistent_same_value_same_placeholder():
    mapping = {}
    result = redact_keywords(
        "SRV001 and SRV001 again",
        keywords=[],
        entity_mapping=mapping,
        block_patterns=[r"SRV\d+"],
    )
    # 同一個值應該得到同一個佔位符
    assert result.count("<KEYWORD_1>") == 2


def test_block_patterns_different_values_different_placeholders():
    mapping = {}
    result = redact_keywords(
        "SRV001 and SRV002",
        keywords=[],
        entity_mapping=mapping,
        block_patterns=[r"SRV\d+"],
    )
    assert "<KEYWORD_1>" in result
    assert "<KEYWORD_2>" in result


def test_block_patterns_shares_bucket_with_keywords():
    mapping = {}
    # 先用 keyword 佔掉 KEYWORD_1
    result1 = redact_keywords(
        "ProjectX found",
        keywords=["ProjectX"],
        entity_mapping=mapping,
        block_patterns=[],
    )
    # 再用 block_pattern 匹配 SRV001，應得到 KEYWORD_2
    result2 = redact_keywords(
        "SRV001 alert",
        keywords=[],
        entity_mapping=mapping,
        block_patterns=[r"SRV\d+"],
    )
    assert "<KEYWORD_1>" in result1
    assert "<KEYWORD_2>" in result2


def test_block_patterns_empty_list_no_change():
    mapping = {}
    text = "Normal log line with no sensitive data"
    result = redact_keywords(text, keywords=[], entity_mapping=mapping, block_patterns=[])
    assert result == text


def test_block_patterns_backward_compatible_no_param():
    """不傳 block_patterns 時行為與原來完全相同。"""
    mapping = {}
    result = redact_keywords(
        "ProjectX is sensitive",
        keywords=["ProjectX"],
        entity_mapping=mapping,
    )
    assert "ProjectX" not in result
    assert "<KEYWORD_1>" in result
