"""
TDD tests for redact_cmdline_secrets() — 命令列憑證識別器

規格：
- 偵測 --flag value、--flag=value、/flag:value、net user NAME PASS 格式
- 保留旗標名稱，只遮蔽值，替換為 <CMDLINE_SECRET_N>
- 敏感旗標：password, passwd, pwd, credential, cred, secret,
            apikey, api-key, api_key, token, key, pass（case-insensitive）
- 不遮蔽：純數字且長度 < 4（避免誤判 port、版本號）
- 一致性：同一個值在同一次執行中得到同一個佔位符
- secret_hit_flag 有命中時 append True
"""

import pytest
from deidentify import redact_cmdline_secrets


# ===========================================================
# --flag value 格式（空白分隔）
# ===========================================================

def test_double_dash_password_space_value():
    mapping = {}
    flag = []
    result = redact_cmdline_secrets("net start svc --password Secret123", mapping, flag)
    assert "Secret123" not in result
    assert "--password" in result
    assert "<CMDLINE_SECRET_1>" in result
    assert flag  # secret_hit_flag 要有 True


def test_double_dash_token_space_value():
    mapping = {}
    flag = []
    result = redact_cmdline_secrets("call --token eyABC123def", mapping, flag)
    assert "eyABC123def" not in result
    assert "--token" in result


def test_single_dash_pwd_space_value():
    mapping = {}
    flag = []
    result = redact_cmdline_secrets("login -pwd MyPass!", mapping, flag)
    assert "MyPass!" not in result
    assert "-pwd" in result


# ===========================================================
# --flag=value 格式（等號連接）
# ===========================================================

def test_double_dash_password_equals_value():
    mapping = {}
    flag = []
    result = redact_cmdline_secrets("run --password=TopSecret", mapping, flag)
    assert "TopSecret" not in result
    assert "--password=" in result
    assert flag


def test_double_dash_api_key_equals_value():
    mapping = {}
    flag = []
    result = redact_cmdline_secrets("curl --api-key=sk-abc123XYZ", mapping, flag)
    assert "sk-abc123XYZ" not in result
    assert "--api-key=" in result


# ===========================================================
# /flag:value 格式（Windows 風格）
# ===========================================================

def test_slash_password_colon_value():
    mapping = {}
    flag = []
    result = redact_cmdline_secrets(r"runas /password:WinPass99", mapping, flag)
    assert "WinPass99" not in result
    assert "/password:" in result
    assert flag


def test_slash_credential_colon_value():
    mapping = {}
    flag = []
    result = redact_cmdline_secrets(r"tool /credential:domain\user:pass", mapping, flag)
    assert "domain\\user:pass" not in result
    assert "/credential:" in result


# ===========================================================
# net user NAME PASS 格式
# ===========================================================

def test_net_user_command():
    mapping = {}
    flag = []
    result = redact_cmdline_secrets("net user administrator P@ssw0rd123", mapping, flag)
    assert "P@ssw0rd123" not in result
    assert "net user" in result
    assert "administrator" in result
    assert flag


def test_net_user_add_command():
    mapping = {}
    flag = []
    result = redact_cmdline_secrets("net user newuser Str0ng!Pass /add", mapping, flag)
    assert "Str0ng!Pass" not in result
    assert "net user" in result
    assert "/add" in result  # 後面的旗標要保留


# ===========================================================
# 一致性：同值同佔位符
# ===========================================================

def test_same_value_same_placeholder():
    mapping = {}
    flag = []
    r1 = redact_cmdline_secrets("--password Secret123", mapping, flag)
    r2 = redact_cmdline_secrets("--pwd Secret123", mapping, flag)
    # 兩次遮蔽同一個值，應該得到同一個佔位符
    assert "<CMDLINE_SECRET_1>" in r1
    assert "<CMDLINE_SECRET_1>" in r2


def test_different_values_different_placeholders():
    mapping = {}
    flag = []
    r1 = redact_cmdline_secrets("--password Pass1", mapping, flag)
    r2 = redact_cmdline_secrets("--password Pass2", mapping, flag)
    assert "<CMDLINE_SECRET_1>" in r1
    assert "<CMDLINE_SECRET_2>" in r2


# ===========================================================
# 不遮蔽：純數字且長度 < 4
# ===========================================================

def test_short_numeric_value_not_redacted():
    mapping = {}
    flag = []
    result = redact_cmdline_secrets("connect --port 443", mapping, flag)
    # 443 是純數字且 < 4 位，不應遮蔽
    assert "443" in result
    assert not flag


def test_longer_numeric_value_is_redacted():
    mapping = {}
    flag = []
    result = redact_cmdline_secrets("auth --token 12345678", mapping, flag)
    # 8 位數字應該遮蔽（可能是 PIN 或 token）
    assert "12345678" not in result
    assert flag


# ===========================================================
# 無命中：正常文字不被遮蔽
# ===========================================================

def test_no_sensitive_flag_no_redaction():
    mapping = {}
    flag = []
    text = "process --output report.json --verbose"
    result = redact_cmdline_secrets(text, mapping, flag)
    assert result == text
    assert not flag


def test_case_insensitive_flag_detection():
    mapping = {}
    flag = []
    result = redact_cmdline_secrets("tool --PASSWORD secret", mapping, flag)
    assert "secret" not in result
    assert flag
