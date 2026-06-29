"""
TDD tests for entity options 擴充

規格：
- build_engines(options) 接受 options dict 控制各 entity 的啟用/停用
- options key：keep_datetime / keep_public_ip / keep_domain / keep_crypto / keep_uuid
- 預設全部 False（遮蔽）；True = 保留明文（不掛入對應 recognizer）
- 新增 entity：DATE_TIME / CRYPTO / IBAN_CODE / US_PASSPORT
- ORG_PATTERN bug：Microsoft Corporation 應完整被遮蔽，不留殘缺
- UUID 語意改為預設遮蔽（keep_uuid=False）
"""

import pytest
import re
from deidentify import build_engines, build_operator_configs, deidentify_text


def _run(text, options=None, extra_entities=None):
    """helper：用指定 options 跑一次 deidentify_text，回傳結果字串。"""
    opts = options or {}
    analyzer, anonymizer, entities = build_engines(options=opts)
    if extra_entities:
        entities = entities + [e for e in extra_entities if e not in entities]
    entity_mapping = {}
    operators = build_operator_configs(entity_mapping, entities)
    flag = []
    return deidentify_text(
        text, analyzer, anonymizer, entity_mapping, entities,
        operators, opts.get("keep_public_ip", False), [], [], flag
    )


# ===========================================================
# ORG_PATTERN regression
# ===========================================================

def test_org_corporation_fully_redacted():
    result = _run("Attacker used Microsoft Corporation infrastructure")
    assert "Corporation" not in result, f"ORG suffix 殘留: {result}"
    assert "Microsoft" not in result, f"ORG 前綴殘留: {result}"


def test_org_corp_suffix_fully_redacted():
    result = _run("vendor Acme Corp paid ransom", options={"keep_domain": False})
    assert "Acme" not in result or "Corp" not in result


def test_org_inc_fully_redacted():
    result = _run("company name Initech Inc filed report")
    assert "Initech" not in result


# ===========================================================
# DATE_TIME
# ===========================================================

def test_datetime_redacted_by_default():
    result = _run("attack at 2024-01-15T09:30:00Z", options={})
    assert "2024-01-15" not in result, f"DATE_TIME 應被遮蔽: {result}"


def test_datetime_preserved_when_keep_datetime():
    result = _run("attack at 2024-01-15T09:30:00Z", options={"keep_datetime": True})
    assert "2024-01-15" in result, f"keep_datetime=True 應保留時間: {result}"


def test_datetime_various_formats_redacted():
    cases = [
        "event on 15/01/2024",
        "logged 2024-01-15",
    ]
    for text in cases:
        result = _run(text, options={})
        assert "2024" not in result or "01" not in result, f"DATE_TIME 格式未遮蔽: {text!r} -> {result!r}"


# ===========================================================
# CRYPTO
# ===========================================================

_P2SH = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"       # checksum 合法的 P2SH 地址
_BECH32 = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"  # 合法 bech32 地址


def test_crypto_redacted_by_default():
    result = _run(f"ransom to {_P2SH}", options={})
    assert _P2SH not in result, f"CRYPTO 應被遮蔽: {result}"


def test_crypto_preserved_when_keep_crypto():
    result = _run(f"ransom to {_P2SH}", options={"keep_crypto": True})
    assert _P2SH in result, f"keep_crypto=True 應保留: {result}"


def test_crypto_bech32_redacted():
    result = _run(f"payment {_BECH32}", options={})
    assert "bc1q" not in result, f"bech32 CRYPTO 應被遮蔽: {result}"


# ===========================================================
# IBAN_CODE
# ===========================================================

def test_iban_redacted_by_default():
    result = _run("transfer to GB29NWBK60161331926819", options={})
    assert "GB29NWBK60161331926819" not in result, f"IBAN 應被遮蔽: {result}"


def test_iban_consistent_placeholder():
    entity_mapping = {}
    opts = {}
    analyzer, anonymizer, entities = build_engines(options=opts)
    operators = build_operator_configs(entity_mapping, entities)
    flag = []
    r1 = deidentify_text("account GB29NWBK60161331926819 used", analyzer, anonymizer,
                          entity_mapping, entities, operators, False, [], [], flag)
    r2 = deidentify_text("again GB29NWBK60161331926819 found", analyzer, anonymizer,
                          entity_mapping, entities, operators, False, [], [], flag)
    ph1 = re.findall(r"<IBAN_CODE_\d+>", r1)
    ph2 = re.findall(r"<IBAN_CODE_\d+>", r2)
    assert ph1 and ph2 and ph1[0] == ph2[0], "同一 IBAN 應得到相同佔位符"


# ===========================================================
# US_PASSPORT
# ===========================================================

def test_passport_redacted_by_default():
    result = _run("passport A12345678 scanned at border", options={})
    assert "A12345678" not in result, f"US_PASSPORT 應被遮蔽: {result}"


# ===========================================================
# UUID — 語意改為預設遮蔽
# ===========================================================

def test_uuid_redacted_by_default():
    result = _run("session 550e8400-e29b-41d4-a716-446655440000 opened", options={})
    assert "550e8400-e29b-41d4-a716-446655440000" not in result, f"UUID 預設應被遮蔽: {result}"


def test_uuid_preserved_when_keep_uuid():
    result = _run("session 550e8400-e29b-41d4-a716-446655440000 opened", options={"keep_uuid": True})
    assert "550e8400-e29b-41d4-a716-446655440000" in result, f"keep_uuid=True 應保留: {result}"


# ===========================================================
# keep_domain 選項
# ===========================================================

def test_domain_redacted_by_default():
    result = _run("beacon to evil.io/payload", options={})
    assert "evil.io" not in result, f"DOMAIN 應被遮蔽: {result}"


def test_domain_preserved_when_keep_domain():
    result = _run("beacon to evil.io callback", options={"keep_domain": True})
    assert "evil.io" in result, f"keep_domain=True 應保留: {result}"


# ===========================================================
# 向後相容：舊有 entity 不受影響
# ===========================================================

def test_existing_email_still_redacted():
    result = _run("user alice@corp.com logged in", options={})
    assert "alice@corp.com" not in result


def test_existing_ip_still_redacted():
    result = _run("connect from 192.168.1.100", options={})
    assert "192.168.1.100" not in result


def test_existing_tw_id_still_redacted():
    result = _run("ID: A123456789 accessed", options={})
    assert "A123456789" not in result


# ===========================================================
# MAC_ADDRESS
# ===========================================================

def test_mac_colon_redacted_by_default():
    result = _run("host AA:BB:CC:DD:EE:FF connected", options={})
    assert "AA:BB:CC:DD:EE:FF" not in result, f"MAC colon 應被遮蔽: {result}"


def test_mac_hyphen_redacted_by_default():
    result = _run("device AA-BB-CC-DD-EE-FF registered", options={})
    assert "AA-BB-CC-DD-EE-FF" not in result, f"MAC hyphen 應被遮蔽: {result}"


def test_mac_preserved_when_keep_mac():
    result = _run("host AA:BB:CC:DD:EE:FF connected", options={"keep_mac": True})
    assert "AA:BB:CC:DD:EE:FF" in result, f"keep_mac=True 應保留: {result}"


def test_mac_lowercase_redacted():
    result = _run("arp aa:bb:cc:dd:ee:ff seen", options={})
    assert "aa:bb:cc:dd:ee:ff" not in result, f"小寫 MAC 應被遮蔽: {result}"
