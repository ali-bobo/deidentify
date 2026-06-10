#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
deidentify.py — Log De-identification Tool

Replaces PII and sensitive identifiers in log files with consistent
pseudonyms, producing an uploadable de-identified copy and a local
reversal mapping.

Supported input: .txt / .log / .json / .csv (others treated as plain text)
EDR-style CSV exports (threat/host/events structure) are auto-detected
and processed through a structured parse → optional dedup → de-identify pipeline.

Flags:
  --keep-public-ip      Retain public IPs (useful for C2 analysis)
  --redact-uuid         Enable UUID redaction (off by default)
  --max-mb N            Per-file output size limit (default 10 MB)
  --no-dedup            Disable duplicate-event collapsing for EDR CSVs
  --output-dir DIR      Folder for de-identified output (default: deidentified_output/)
  --mapping-dir DIR     Folder for reversal mapping files (default: deidentify_mapping/)
  -w KEYWORD            Additional terms to redact (repeatable)
  --custom-id-pattern P Extra regex pattern to treat as a custom ID entity (repeatable)
"""

import io
import re
import sys
import csv
import json
import glob
import base64
import binascii
import ipaddress
from pathlib import Path
from typing import Any, Dict, List, Tuple, Optional

# ---- Windows 主控台輸出強制 UTF-8 ----
if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf8"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

from presidio_analyzer import (
    AnalyzerEngine, PatternRecognizer, Pattern, RecognizerRegistry
)
from presidio_analyzer.nlp_engine import SpacyNlpEngine
from presidio_anonymizer import AnonymizerEngine, OperatorConfig
from presidio_anonymizer.operators import Operator, OperatorType


# ============================================================================
# 偵測規則
# ============================================================================

# 中文 + 全形標點
CJK_PATTERN = Pattern("cjk", r"[\u4e00-\u9fff\u3000-\u303f\uff00-\uffef]+", 1.0)

# IPv6 由 ipaddress 驗證型流程處理，避免把時間（如 12:34:56）誤判成 IPv6。

# 網域（真實 TLD 結尾）
DOMAIN_PATTERN = Pattern(
    "domain",
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:com|net|org|edu|gov|mil|biz|info|io|co|"
    r"tw|cn|jp|us|uk|hk|kr|sg|de|fr|ru|au|ca|nl|eu|in|br|"
    r"xyz|top|online|site|club|shop|app|dev|cloud|tech|live|"
    r"win|vip|cc|tk|ml|ga|cf|gq|pw|me|cyou|icu|"
    r"internal|local|corp|lan|intra)"
    r"(?:\.tw|\.cn|\.jp|\.uk|\.hk|\.kr|\.au|\.br|\.in)?\b",
    0.85,
)

EMAIL_PATTERN = Pattern(
    "email", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", 0.95
)

# 跨 OS 使用者名：Windows \Users\NAME\、macOS /Users/NAME/、Linux /home/NAME/
WINUSER_PATTERN   = Pattern("winuser",   r"(?i)(?<=\\Users\\)[^\\/:*?\"<>|]+", 0.8)
MACUSER_PATTERN   = Pattern("macuser",   r"(?<=/Users/)[^/]+", 0.8)
LINUXUSER_PATTERN = Pattern("linuxuser", r"(?<=/home/)[^/]+", 0.8)

# 員工/客戶識別碼（沿用現有規則：1 字母 + 6~8 數字）
EMPID_PATTERN = Pattern("empid", r"\b[A-Za-z]\d{6,8}\b", 0.7)

# 觸發「下一格遮蔽」的欄位名（CSV 兩欄式 key,value 結構用）
# Common EDR/endpoint agent field names that contain device hostnames.
# Extend via --custom-id-pattern or by editing this set.
NEXT_CELL_REDACT_KEYS = {"agentcomputername", "computername", "hostname", "devicename"}

# ---- 台灣本土 PII ----

# 台灣手機：09xx-xxx-xxx / +886-9xx / 0086-9xx，支援連字號/空格/點分隔
TW_PHONE_PATTERN = Pattern(
    "tw_phone",
    r"(?:(?:\+886|0086)[-.\s]?|0)9\d{2}[-.\s]?\d{3}[-.\s]?\d{3}\b",
    0.85,
)

# 台灣身分證：1 縣市字母 + [12] + 8 位數，靠 validate_result 做 checksum 驗證
TWID_PATTERN = Pattern(
    "tw_id",
    r"\b[A-Z][12]\d{8}\b",
    0.7,
)

# 信用卡：13~16 位數字（含空格/連字號分隔），靠 validate_result 做 Luhn 驗證
CC_PATTERN = Pattern(
    "credit_card",
    r"\b(?:\d{4}[-.\s]?){3}\d{1,4}\b",
    0.6,
)

# 公司名後綴錨定（含常見法律實體後綴；初始分數低，靠 context 提升）
CORP_SUFFIX = (
    r"(?:"
    r"Ltd\.?|LTD\.?|Limited|"
    r"Co\.,?\s*Ltd\.?|CO\.,?\s*LTD\.?|"
    r"Co\.|CO\.|"
    r"Corp\.?|CORP\.?|Corporation|"
    r"Inc\.?|INC\.?|Incorporated|"
    r"LLC|L\.L\.C\.|LLP|"
    r"GmbH|PLC|plc"
    r")"
)
ORG_PATTERN = Pattern(
    "org_suffix",
    r"(?:[A-Z][A-Za-z0-9&'\-\.]*\s+){1,7}" + CORP_SUFFIX + r"(?:,?\s*" + CORP_SUFFIX + r")?",
    0.5,
)

# UUID（旗標開啟才掛載）
UUID_PATTERN = Pattern(
    "uuid",
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b",
    0.8,
)

# 密碼 / Token / 憑證 key 名稱。採嚴格策略，命中時 key 與 value 都要遮蔽。
SENSITIVE_KEY_RE = re.compile(
    r"(?i)^(?:"
    r"password|passwd|pwd|api[_-]?key|apikey|secret|token|authorization|"
    r"auth[_-]?token|bearer|secret[_-]?key|private[_-]?key|access[_-]?key|"
    r"access[_-]?token|client[_-]?secret|"
    r"refresh[_-]?token|id[_-]?token|cookie|set[_-]?cookie|session(?:[_-]?id)?|"
    r"connection[_-]?string"
    r")$"
)

SENSITIVE_KEY_INLINE_RE = re.compile(
    r"(?i)\b("
    r"password|passwd|pwd|api[_-]?key|apikey|secret|token|authorization|"
    r"auth[_-]?token|secret[_-]?key|private[_-]?key|access[_-]?key|"
    r"access[_-]?token|client[_-]?secret|"
    r"refresh[_-]?token|id[_-]?token|cookie|set[_-]?cookie|session(?:[_-]?id)?|"
    r"connection[_-]?string"
    r")\b"
)

SENSITIVE_KEY_TERMS = (
    "password", "passwd", "pwd", "api_key", "apikey", "secret", "secret_key",
    "token", "authorization", "auth_token", "bearer", "private_key",
    "access_key", "access_token", "client_secret", "refresh_token", "id_token",
    "cookie", "set_cookie", "session", "session_id", "connection_string",
)

AUTH_SECRET_RE = re.compile(
    r"(?i)\b(?:authorization|auth[_-]?token)\s*[:=]\s*"
    r"(?:bearer|basic|digest|token|apikey)?\s*\S+|\bbearer\s+\S+"
)

SECRET_PAIR_RE = re.compile(
    r"(?i)(?P<key>[A-Za-z0-9_.-]*(?:"
    r"password|passwd|pwd|api[_-]?key|apikey|secret|token|secret[_-]?key|"
    r"private[_-]?key|access[_-]?key|access[_-]?token|client[_-]?secret|"
    r"refresh[_-]?token|id[_-]?token|"
    r"cookie|set[_-]?cookie|session(?:[_-]?id)?|connection[_-]?string"
    r")[A-Za-z0-9_.-]*)(?P<sep>\s*[:=]\s*)"
    r"(?P<quote>[\"']?)(?P<value>[^\s,;\"']+)(?P=quote)"
)

JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")
COMMON_TOKEN_RE = re.compile(
    r"\b(?:AKIA[0-9A-Z]{16}|"
    r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}|"
    r"github_pat_[A-Za-z0-9_]{20,})\b"
)

IPV4_LITERAL_RE = re.compile(
    r"(?<![\w.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\w.])"
)

CIDR_LITERAL_RE = re.compile(
    r"(?<![\w:.])(?:"
    r"(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)"
    r"|[0-9A-Fa-f:.]{2,39}"
    r")/(?:12[0-8]|1[01]\d|[1-9]?\d)(?![\w:.])"
)

IPV6_LITERAL_RE = re.compile(
    r"(?<![\w:.])(?=[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*:)"
    r"[0-9A-Fa-f:.]+(?:%\w+)?(?![\w:.])"
)

# 公開網域白名單（保留，不替換）
PUBLIC_DOMAIN_WHITELIST = {
    "google.com", "googleapis.com", "microsoft.com", "windows.com",
    "cloudflare.com", "virustotal.com", "github.com", "mozilla.org",
    "w3.org", "schema.org", "gstatic.com", "msn.com", "bing.com",
}

# context 詞：出現時提升 ORG 等弱規則的信心
ORG_CONTEXT = ["account", "name", "company", "organization", "customer",
               "client", "vendor", "site", "group", "corp"]


# ============================================================================
# Mapping / 遮蔽 helper
# ============================================================================

def normalize_secret_key(key: str) -> str:
    text = key.strip()
    text = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", text)
    return re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")


def is_sensitive_key(key: Any) -> bool:
    if not isinstance(key, str):
        return False
    normalized = normalize_secret_key(key)
    return bool(SENSITIVE_KEY_RE.fullmatch(normalized) or
                SENSITIVE_KEY_INLINE_RE.search(normalized) or
                any(term in normalized for term in SENSITIVE_KEY_TERMS))


def looks_like_sensitive_key_name(value: str) -> bool:
    text = value.strip()
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", text):
        return False
    return is_sensitive_key(text)


def map_value(entity_mapping: Dict[str, Dict[str, str]], entity_type: str,
              original: Any) -> str:
    text = original if isinstance(original, str) else json.dumps(
        original, ensure_ascii=False, sort_keys=True
    )
    bucket = entity_mapping.setdefault(entity_type, {})
    if text in bucket:
        return bucket[text]
    replacement = f"<{entity_type}_{len(bucket) + 1}>"
    bucket[text] = replacement
    return replacement


def classify_ip_entity(value: str, is_cidr: bool = False) -> Tuple[str, bool]:
    if is_cidr:
        network = ipaddress.ip_network(value, strict=False)
        version = network.version
        is_public = network.is_global
        if version == 4:
            return ("EXT_CIDR" if is_public else "INT_CIDR"), is_public
        return ("EXT_IPV6_CIDR" if is_public else "INT_IPV6_CIDR"), is_public

    addr = ipaddress.ip_address(value.split("%", 1)[0])
    is_public = addr.is_global
    if addr.version == 4:
        return ("EXT_IP" if is_public else "INT_IP"), is_public
    return ("EXT_IPV6" if is_public else "INT_IPV6"), is_public


def redact_secret_value(value: Any, key: str,
                        entity_mapping: Dict[str, Dict[str, str]]) -> str:
    entity_type = "AUTH_SECRET" if normalize_secret_key(key) in {
        "authorization", "auth_token"
    } else "SECRET_VALUE"
    return map_value(entity_mapping, entity_type, value)


def redact_inline_secrets(text: str, entity_mapping: Dict[str, Dict[str, str]],
                          secret_hit_flag: List[bool]) -> str:
    def replace_auth(match):
        secret_hit_flag.append(True)
        return map_value(entity_mapping, "AUTH_SECRET", match.group(0))

    def replace_pair(match):
        secret_hit_flag.append(True)
        key = match.group("key")
        value = match.group("value")
        key_placeholder = map_value(entity_mapping, "SECRET_KEY", key)
        value_placeholder = redact_secret_value(value, key, entity_mapping)
        return f"{key_placeholder}{match.group('sep')}{value_placeholder}"

    def replace_token(match):
        secret_hit_flag.append(True)
        return map_value(entity_mapping, "SECRET_VALUE", match.group(0))

    text = AUTH_SECRET_RE.sub(replace_auth, text)
    text = SECRET_PAIR_RE.sub(replace_pair, text)
    text = JWT_RE.sub(replace_token, text)
    text = COMMON_TOKEN_RE.sub(replace_token, text)
    return text


def redact_ip_literals(text: str, entity_mapping: Dict[str, Dict[str, str]],
                       keep_public_ip: bool) -> str:
    def replace_cidr(match):
        value = match.group(0)
        try:
            entity_type, is_public = classify_ip_entity(value, is_cidr=True)
        except ValueError:
            return value
        if keep_public_ip and is_public:
            return value
        return map_value(entity_mapping, entity_type, value)

    def replace_ipv4(match):
        value = match.group(0)
        # 版本號形狀排除：後三段全 0（如 148.0.0.0、Chrome/145.0.0.0）
        octets = value.split(".")
        if octets[1:] == ["0", "0", "0"]:
            return value
        # 版本號前綴白名單：只有已知 UA token 後的斜線才排除
        # 避免把 URL path 中的 IP（如 /NSR/192.168.1.1）誤排除
        start = match.start()
        _UA_PREFIXES = (
            "chrome/", "firefox/", "safari/", "version/", "edg/", "edge/",
            "opr/", "opera/", "chromium/", "gecko/", "trident/", "msie/",
        )
        prefix = text[max(0, start-12):start].lower()
        if any(prefix.endswith(p) for p in _UA_PREFIXES):
            return value
        try:
            entity_type, is_public = classify_ip_entity(value)
        except ValueError:
            return value
        if keep_public_ip and is_public:
            return value
        return map_value(entity_mapping, entity_type, value)

    def replace_ipv6(match):
        value = match.group(0)
        try:
            entity_type, is_public = classify_ip_entity(value)
        except ValueError:
            return value
        if keep_public_ip and is_public:
            return value
        return map_value(entity_mapping, entity_type, value)

    text = CIDR_LITERAL_RE.sub(replace_cidr, text)
    text = IPV4_LITERAL_RE.sub(replace_ipv4, text)
    text = IPV6_LITERAL_RE.sub(replace_ipv6, text)
    return text


def redact_keywords(text: str, keywords: List[str],
                    entity_mapping: Dict[str, Dict[str, str]]) -> str:
    """用戶自訂關鍵字遮蔽（直接子字串，case-insensitive）。"""
    for kw in keywords:
        if not kw:
            continue
        replacement = map_value(entity_mapping, "KEYWORD", kw.lower())
        text = re.sub(re.escape(kw), replacement, text, flags=re.IGNORECASE)
    return text


def stringify_secret_value(value: Any) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


# ============================================================================
# 編碼處理
# ============================================================================

def read_text_any_encoding(path: Path):
    raw = path.read_bytes()
    for enc in ("utf-8-sig", "utf-8", "cp950", "big5", "gb18030"):
        try:
            return raw.decode(enc), enc
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace"), "utf-8(replace)"


def clean_mojibake(text: str) -> str:
    text = re.sub(r"[\uE000-\uF8FF]", "\uFFFD", text)
    text = re.sub(r"[\uFFFD]+", "[…]", text)
    return text


# ============================================================================
# EDR Parser — structured threat/host/events CSV export format
# ============================================================================


ENC_CMD_RE = re.compile(
    r"(?i)-(?:enc|encodedcommand|e)\s+[\"']?([A-Za-z0-9+/=]{16,})[\"']?"
)


def try_decode_powershell(cmdline: str) -> Optional[str]:
    """偵測 PowerShell -EncodedCommand 並以 UTF-16LE 解碼。失敗回 None。"""
    if not cmdline:
        return None
    m = ENC_CMD_RE.search(cmdline)
    if not m:
        return None
    b64 = m.group(1)
    # base64 長度需為 4 的倍數，補齊
    b64 += "=" * (-len(b64) % 4)
    try:
        raw = base64.b64decode(b64)
    except (binascii.Error, ValueError):
        return None
    # PowerShell 慣用 UTF-16LE；失敗退回 UTF-8
    for enc in ("utf-16-le", "utf-8"):
        try:
            decoded = raw.decode(enc)
            # 過濾控制字元，確認像可讀命令
            if sum(c.isprintable() or c.isspace() for c in decoded) > len(decoded) * 0.8:
                return decoded
        except UnicodeDecodeError:
            continue
    return None


# ============================================================================
# IOC 萃取
# ============================================================================

URL_RE     = re.compile(r"https?://[^\s\"'<>|)]+")
IPV4_RE    = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
SHA1_RE    = re.compile(r"\b[0-9a-fA-F]{40}\b")
WINPATH_RE = re.compile(r"[A-Za-z]:\\\\?(?:[^\\/:*?\"<>|\r\n]+\\\\?)*[^\\/:*?\"<>|\r\n]*")
DOMAIN_RE  = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")


def extract_iocs_from_text(text: str, iocs: Dict[str, set]):
    if not text:
        return
    for u in URL_RE.findall(text):
        iocs["urls"].add(u.rstrip(".,;)"))
        # 從 URL 抽域名
        m = re.match(r"https?://([^/:\s]+)", u)
        if m:
            iocs["domains"].add(m.group(1))
    for ip in IPV4_RE.findall(text):
        # 排除版本號形狀
        if ip.split(".")[1:] != ["0", "0", "0"]:
            iocs["ipv4"].add(ip)
    for h in SHA1_RE.findall(text):
        if h != "0" * 40:  # 排除空 hash
            iocs["sha1"].add(h.lower())


# ============================================================================
# CSV section 解析
# ============================================================================

# key-value 區塊的欄位 → schema 欄位對照
THREAT_KEY_MAP = {
    "Threat name": "name",
    "Threat ID": "threat_id",
    "Classification": "classification",
    "Confidence level": "confidence",
    "Mitigation status": "mitigation_status",
    "File content SHA1 hash": "sha1",
    "File path": "file_path",
    "Originator process": "originator_process",
    "Initiated by": "initiated_by",
    "Malicious process arguments": "raw_cmdline",
    "Identified at": "identified_at",
    "Last update": "last_update",
    "Fileless threat": "fileless",
}

HOST_KEY_MAP = {
    "agentComputerName": "name",
    "agentIpV4": "ipv4",
    "agentIpV6": "ipv6",
    "Agent OS name": "os",
    "Agent Domain": "domain",
    "Site name": "site",
    "Account name": "account",
    "agentUuid": "agent_uuid",
    "Agent version": "agent_version",
    "Last logged in user": "last_user",
}

# 各表格 section header 的關鍵字 → category
SECTION_CATEGORY = {
    "Processes": "process",
    "Files": "file",
    "Indicators": "indicator",
    "Network Actions": "network",
}


def is_section_header(row: List[str]) -> Optional[str]:
    """單欄且內容是已知 section 名稱 → 回傳 section 名。"""
    if len(row) == 1 and row[0].strip() in (
        "Threat Information", "Agent info on Detection Time",
        "Processes", "Files", "Indicators", "Network Actions"
    ):
        return row[0].strip()
    return None


def parse_edr_csv(text: str) -> Dict[str, Any]:
    reader = list(csv.reader(io.StringIO(text)))
    result = {
        "schema_version": "1.0",
        "threat": {},
        "host": {},
        "events": [],
        "iocs": {"urls": set(), "ipv4": set(), "sha1": set(),
                 "dropped_paths": set(), "domains": set()},
    }
    iocs = result["iocs"]

    current_section = None
    table_header = None  # 水平表格的 header 欄位名

    i = 0
    while i < len(reader):
        row = [clean_mojibake(c) for c in reader[i]]

        # 空行
        if not any(c.strip() for c in row):
            i += 1
            continue

        # section header？
        sec = is_section_header(row)
        if sec:
            current_section = sec
            table_header = None
            i += 1
            continue

        # key-value 區塊（Threat / Agent info）
        if current_section == "Threat Information" and len(row) == 2:
            key, val = row[0].strip(), row[1].strip()
            if key in THREAT_KEY_MAP:
                result["threat"][THREAT_KEY_MAP[key]] = val
                if key == "Malicious process arguments":
                    decoded = try_decode_powershell(val)
                    if decoded:
                        result["threat"]["decoded_cmdline"] = decoded
                        extract_iocs_from_text(decoded, iocs)
                if key == "File content SHA1 hash" and val and val != "0"*40:
                    iocs["sha1"].add(val.lower())
            i += 1
            continue

        if current_section == "Agent info on Detection Time" and len(row) == 2:
            key, val = row[0].strip(), row[1].strip()
            if key in HOST_KEY_MAP:
                result["host"][HOST_KEY_MAP[key]] = val
            i += 1
            continue

        # 水平表格區塊
        if current_section in SECTION_CATEGORY:
            # 第一個非空行是表格 header
            if table_header is None:
                table_header = row
                i += 1
                continue
            # 資料列
            category = SECTION_CATEGORY[current_section]
            event = parse_table_row(table_header, row, category, iocs)
            if event:
                result["events"].append(event)
            i += 1
            continue

        i += 1

    # set → sorted list
    result["iocs"] = {k: sorted(v) for k, v in iocs.items()}
    # 統計
    by_cat: Dict[str, int] = {}
    for e in result["events"]:
        by_cat[e["category"]] = by_cat.get(e["category"], 0) + 1
    result["stats"] = {"total_events": len(result["events"]), "by_category": by_cat}
    return result


def col(header, row, name):
    """從表格列取指定欄位值，找不到回空字串。"""
    try:
        idx = header.index(name)
        return row[idx].strip() if idx < len(row) else ""
    except ValueError:
        return ""


def parse_table_row(header, row, category, iocs) -> Optional[Dict[str, Any]]:
    etype = col(header, row, "Event Type")
    if not etype:
        return None
    e: Dict[str, Any] = {"category": category, "type": etype,
                         "time": col(header, row, "Created At")}

    if category == "process":
        cmdline = col(header, row, "Command Line")
        e.update({
            "process_name": col(header, row, "Process Name"),
            "process_uid": col(header, row, "Process UID"),
            "process_id": col(header, row, "Process ID"),
            "parent_name": col(header, row, "Source Process Name"),
            "parent_uid": col(header, row, "Source Process UID"),
            "cmdline": cmdline,
            "sha1": col(header, row, "SHA1"),
            "verified_status": col(header, row, "Verified Status"),
        })
        decoded = try_decode_powershell(cmdline)
        if decoded:
            e["decoded_cmdline"] = decoded
            extract_iocs_from_text(decoded, iocs)
        if e["sha1"] and e["sha1"] != "0"*40:
            iocs["sha1"].add(e["sha1"].lower())

    elif category == "network":
        e.update({
            "src_ip": col(header, row, "Source IP"),
            "src_port": col(header, row, "Source Port"),
            "dst_ip": col(header, row, "Destination IP"),
            "dst_port": col(header, row, "Destination Port"),
            "protocol": col(header, row, "Protocol"),
            "process_name": col(header, row, "Process Name"),
        })
        for ipf in (e["src_ip"], e["dst_ip"]):
            if ipf and not ipf.startswith("<"):  # 排除已去識別佔位符
                extract_iocs_from_text(ipf, iocs)

    elif category == "file":
        full_path = col(header, row, "Full Path")
        e.update({
            "full_path": full_path,
            "sha1": col(header, row, "SHA1"),
            "file_type": col(header, row, "File Type"),
            "process_name": col(header, row, "Process Name"),
        })
        if e["sha1"] and e["sha1"] != "0"*40:
            iocs["sha1"].add(e["sha1"].lower())

    elif category == "indicator":
        e.update({
            "indicator_name": col(header, row, "Indicator Name"),
            "indicator_desc": col(header, row, "Indicator Description"),
            "process_name": col(header, row, "Process Name"),
            "source_process": col(header, row, "Source Process Name"),
        })

    return e


# ============================================================================
# 去重（摺疊重複事件）與大小分割
# ============================================================================

def dedup_events(events: List[Dict[str, Any]]):
    """
    將高頻重複事件摺疊，回傳 (精簡後事件清單, 去重對照表)。

    摺疊鍵：
      file      → (full_path)
      network   → (dst_ip, dst_port, protocol, process_name)
      process   → (process_name, cmdline)
      indicator → (indicator_name, process_name)
    每個摺疊群組保留：首次/末次時間、操作類型計數、出現次數、代表欄位。
    被摺疊的明細寫進 dedup_map（以 group_id 綁定），可回溯。
    """
    def group_key(e):
        cat = e["category"]
        if cat == "file":
            return ("file", e.get("full_path", ""))
        if cat == "network":
            return ("network", e.get("dst_ip", ""), e.get("dst_port", ""),
                    e.get("protocol", ""), e.get("process_name", ""))
        if cat == "process":
            return ("process", e.get("process_name", ""), e.get("cmdline", ""))
        if cat == "indicator":
            return ("indicator", e.get("indicator_name", ""), e.get("process_name", ""))
        return ("other", json.dumps(e, sort_keys=True, ensure_ascii=False))

    groups: Dict[tuple, List[Dict[str, Any]]] = {}
    order: List[tuple] = []
    for e in events:
        k = group_key(e)
        if k not in groups:
            groups[k] = []
            order.append(k)
        groups[k].append(e)

    compact: List[Dict[str, Any]] = []
    dedup_map: Dict[str, Any] = {}
    gid = 0
    for k in order:
        members = groups[k]
        if len(members) == 1:
            compact.append(members[0])
            continue
        # 多筆 → 摺疊
        gid += 1
        group_id = f"GROUP_{gid}"
        times = [m.get("time", "") for m in members if m.get("time")]
        type_counts: Dict[str, int] = {}
        for m in members:
            type_counts[m["type"]] = type_counts.get(m["type"], 0) + 1
        rep = dict(members[0])  # 以第一筆為代表
        rep.update({
            "_collapsed": True,
            "_group_id": group_id,
            "_occurrences": len(members),
            "_type_counts": type_counts,
            "_first_seen": min(times) if times else "",
            "_last_seen": max(times) if times else "",
        })
        # 代表欄位裡的 type 改成摘要
        rep["type"] = " / ".join(f"{t}×{c}" for t, c in type_counts.items())
        compact.append(rep)
        # 完整明細存進對照表（可回溯）
        dedup_map[group_id] = {
            "key": list(k),
            "occurrences": len(members),
            "events": members,
        }

    return compact, dedup_map


def write_json_with_split(obj: Dict[str, Any], out_path: Path,
                          max_mb: float = 10.0):
    """
    寫出 JSON；若超過 max_mb，將 events 分割成多個 _partN.json，
    主檔保留 threat/host/iocs/stats 與分割索引。回傳實際寫出的檔案清單。
    """
    text = json.dumps(obj, ensure_ascii=False, indent=2)
    size_mb = len(text.encode("utf-8")) / (1024 * 1024)
    written = []

    if size_mb <= max_mb:
        out_path.write_text(text, encoding="utf-8")
        return [out_path], size_mb

    # 需要分割：把 events 切塊
    events = obj.get("events", [])
    # 估算每塊事件數：用整體比例推回
    if events:
        per_event_bytes = len(json.dumps(events, ensure_ascii=False).encode("utf-8")) / len(events)
        chunk_size = max(1, int((max_mb * 1024 * 1024 * 0.9) / per_event_bytes))
    else:
        chunk_size = len(events) or 1

    parts = [events[i:i + chunk_size] for i in range(0, len(events), chunk_size)]

    # 主檔（無 events，含索引）
    main_obj = {k: v for k, v in obj.items() if k != "events"}
    main_obj["events_split"] = {
        "total_events": len(events),
        "part_count": len(parts),
        "parts": [f"{out_path.stem}_part{i+1}.json" for i in range(len(parts))],
        "note": "events 過大已分割，逐 part 讀取。",
    }
    main_obj["events"] = []  # 主檔不放 events
    out_path.write_text(json.dumps(main_obj, ensure_ascii=False, indent=2),
                        encoding="utf-8")
    written.append(out_path)

    for i, chunk in enumerate(parts):
        part_path = out_path.with_name(f"{out_path.stem}_part{i+1}.json")
        part_obj = {
            "schema_version": obj.get("schema_version"),
            "source_file": obj.get("source_file"),
            "part_index": i + 1,
            "part_total": len(parts),
            "events": chunk,
        }
        part_path.write_text(json.dumps(part_obj, ensure_ascii=False, indent=2),
                            encoding="utf-8")
        written.append(part_path)

    return written, size_mb


# ============================================================================
# 一致性假名化 Operator
# ============================================================================

class ConsistentPseudonymizer(Operator):
    REPLACING_FORMAT = "<{entity_type}_{index}>"

    def operate(self, text: str, params: Dict = None) -> str:
        entity_type = params["entity_type"]
        entity_mapping = params["entity_mapping"]

        if entity_type == "DOMAIN":
            low = text.lower()
            if any(low == d or low.endswith("." + d) for d in PUBLIC_DOMAIN_WHITELIST):
                return text

        etype = entity_type
        if entity_type == "IPV4":
            try:
                etype = "INT_IP" if ipaddress.ip_address(text).is_private else "EXT_IP"
            except ValueError:
                etype = "IPV4"

        bucket = entity_mapping.setdefault(etype, {})
        if text in bucket:
            return bucket[text]
        new_text = self.REPLACING_FORMAT.format(entity_type=etype, index=len(bucket) + 1)
        bucket[text] = new_text
        return new_text

    def validate(self, params: Dict = None) -> None:
        if "entity_mapping" not in params:
            raise ValueError("entity_mapping is required")
        if "entity_type" not in params:
            raise ValueError("entity_type is required")

    def operator_name(self) -> str:
        return "consistent_pseudonymizer"

    def operator_type(self) -> OperatorType:
        return OperatorType.Anonymize


# ============================================================================
# 台灣本土 PII recognizer（含 validate_result 驗證，降低誤殺）
# ============================================================================

# 台灣身分證 checksum 字母對照表
_TWID_AREA = {c: i + 10 for i, c in enumerate("ABCDEFGHJKLMNPQRSTUVXYWZIO")}

def _twid_checksum(s: str) -> bool:
    """回傳 True 代表身分證號碼 checksum 合法。"""
    s = s.upper()
    n = _TWID_AREA.get(s[0])
    if n is None:
        return False
    total = (n // 10) + (n % 10) * 9
    weights = [8, 7, 6, 5, 4, 3, 2, 1]
    total += sum(int(s[i + 1]) * weights[i] for i in range(8))
    total += int(s[9])
    return total % 10 == 0


def _luhn_check(value: str) -> bool:
    """Luhn 演算法驗證信用卡號。"""
    digits = [int(d) for d in re.sub(r"\D", "", value)]
    if len(digits) < 13:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        total += d if i % 2 == 0 else (d * 2 - 9 if d * 2 > 9 else d * 2)
    return total % 10 == 0


class TwPhoneRecognizer(PatternRecognizer):
    """台灣手機號碼（09xx 或 +886-9xx），無需額外 checksum。"""
    def validate_result(self, pattern_text: str):
        digits = re.sub(r"\D", "", pattern_text)
        # 本地格式：10 位 09xxxxxxxx；國際格式：+886 + 9 位 = 12 位
        return len(digits) in (10, 12)


class TwIdRecognizer(PatternRecognizer):
    """台灣身分證字號，加 checksum 驗證降低誤殺。"""
    def validate_result(self, pattern_text: str):
        return _twid_checksum(pattern_text)


class CreditCardRecognizer(PatternRecognizer):
    """信用卡號，加 Luhn 演算法驗證，避免把日誌中的純數字誤殺。"""
    def validate_result(self, pattern_text: str):
        return _luhn_check(pattern_text)


# ============================================================================
# 引擎組裝
# ============================================================================

def build_engines(redact_uuid: bool, custom_id_patterns: List[str] = None):
    import spacy

    class _BlankSpacyEngine(SpacyNlpEngine):
        def __init__(self):
            super().__init__(models=[{"lang_code": "en", "model_name": "en"}])
            self.nlp = {"en": spacy.blank("en")}

    registry = RecognizerRegistry()

    # IP / CIDR 由 ipaddress 驗證型流程處理，避免版本號與時間格式誤判。
    registry.add_recognizer(PatternRecognizer(supported_entity="CJK",
                                              patterns=[CJK_PATTERN]))
    registry.add_recognizer(PatternRecognizer(supported_entity="DOMAIN",
                                              patterns=[DOMAIN_PATTERN]))
    registry.add_recognizer(PatternRecognizer(supported_entity="EMAIL",
                                              patterns=[EMAIL_PATTERN]))
    registry.add_recognizer(PatternRecognizer(
        supported_entity="OSUSER",
        patterns=[WINUSER_PATTERN, MACUSER_PATTERN, LINUXUSER_PATTERN]))
    registry.add_recognizer(PatternRecognizer(supported_entity="EMPID",
                                              patterns=[EMPID_PATTERN]))
    registry.add_recognizer(TwPhoneRecognizer(supported_entity="TW_PHONE",
                                              patterns=[TW_PHONE_PATTERN]))
    registry.add_recognizer(TwIdRecognizer(supported_entity="TW_ID",
                                           patterns=[TWID_PATTERN]))
    registry.add_recognizer(CreditCardRecognizer(supported_entity="CREDIT_CARD",
                                                 patterns=[CC_PATTERN]))
    registry.add_recognizer(PatternRecognizer(
        supported_entity="ORG", patterns=[ORG_PATTERN], context=ORG_CONTEXT,
        global_regex_flags=re.MULTILINE))

    entities = ["CJK", "DOMAIN", "EMAIL", "OSUSER", "EMPID",
                "TW_PHONE", "TW_ID", "CREDIT_CARD", "ORG"]

    if redact_uuid:
        registry.add_recognizer(PatternRecognizer(supported_entity="UUID",
                                                  patterns=[UUID_PATTERN]))
        entities.append("UUID")

    # User-supplied custom ID patterns (--custom-id-pattern)
    for i, pat_str in enumerate(custom_id_patterns or [], start=1):
        entity = f"CUSTOM_ID_{i}"
        try:
            re.compile(pat_str)  # validate before registering
        except re.error as exc:
            print(f"[警告] 忽略無效的 --custom-id-pattern #{i} ({pat_str!r}): {exc}")
            continue
        registry.add_recognizer(PatternRecognizer(
            supported_entity=entity,
            patterns=[Pattern(entity.lower(), pat_str, 0.85)],
        ))
        entities.append(entity)

    analyzer = AnalyzerEngine(registry=registry, nlp_engine=_BlankSpacyEngine(),
                              supported_languages=["en"])
    anonymizer = AnonymizerEngine()
    anonymizer.add_anonymizer(ConsistentPseudonymizer)
    return analyzer, anonymizer, entities


# ============================================================================
# 單字串去識別化
# ============================================================================

def build_operator_configs(entity_mapping: Dict[str, Dict[str, str]],
                           entities: List[str]) -> Dict[str, OperatorConfig]:
    return {
        e: OperatorConfig("consistent_pseudonymizer",
                          {"entity_mapping": entity_mapping})
        for e in entities
    }


def deidentify_text(text, analyzer, anonymizer, entity_mapping, entities,
                    operators, keep_public_ip, keywords, secret_hit_flag):
    if not text:
        return text

    if keywords:
        text = redact_keywords(text, keywords, entity_mapping)
    text = redact_inline_secrets(text, entity_mapping, secret_hit_flag)
    text = redact_ip_literals(text, entity_mapping, keep_public_ip)

    results = analyzer.analyze(text=text, language="en", entities=entities)

    if results:
        text = anonymizer.anonymize(text=text, analyzer_results=results,
                                    operators=operators).text
    return text


# ============================================================================
# 各格式處理器
# ============================================================================

def process_plain(text, *ctx):
    secret_lines = []
    lines = []
    for i, line in enumerate(text.splitlines(), 1):
        flag = []
        out = deidentify_text(clean_mojibake(line), *ctx, flag)
        if flag:
            secret_lines.append(i)
        lines.append(out)
    return {"format": "plain", "lines": lines}, secret_lines


def process_json(text, *ctx):
    secret_lines = []
    flag = []
    entity_mapping = ctx[2]

    def walk(obj):
        if isinstance(obj, dict):
            out = {}
            for key, value in obj.items():
                if is_sensitive_key(key):
                    flag.append(True)
                    new_key = map_value(entity_mapping, "SECRET_KEY", key)
                    out[new_key] = redact_secret_value(
                        stringify_secret_value(value), key, entity_mapping)
                else:
                    out[key] = walk(value)
            return out
        if isinstance(obj, list):
            return [walk(v) for v in obj]
        if isinstance(obj, str):
            return deidentify_text(clean_mojibake(obj), *ctx, flag)
        return obj

    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return process_plain(text, *ctx)

    if flag:
        secret_lines.append(0)
    return {"format": "json", "data": walk(data)}, secret_lines


def process_csv(text, *ctx):
    secret_lines = []
    reader = list(csv.reader(io.StringIO(text)))
    rows = []
    for idx, row in enumerate(reader, start=1):
        new_row = []
        redact_next = False
        for cell in row:
            flag = []
            cleaned = clean_mojibake(cell)
            if redact_next and cleaned.strip():
                new_row.append(map_value(ctx[2], "AGENTNAME", cleaned))
                redact_next = False
            elif looks_like_sensitive_key_name(cleaned):
                flag.append(True)
                new_row.append(map_value(ctx[2], "SECRET_KEY", cleaned))
            else:
                new_row.append(deidentify_text(cleaned, *ctx, flag))
            if cleaned.strip().lower() in NEXT_CELL_REDACT_KEYS:
                redact_next = True
            if flag:
                secret_lines.append(idx)
        rows.append(new_row)
    header = rows[0] if rows else []
    body = rows[1:] if len(rows) > 1 else []
    return {"format": "csv", "header": header, "rows": body}, sorted(set(secret_lines))


FORMAT_DISPATCH = {".json": process_json, ".csv": process_csv}


def is_edr_csv(text: str) -> bool:
    """Auto-detect EDR-style structured CSV exports (threat/host/events sections).
    Looks for a 'Threat Information' section header in the first 20 lines —
    a format used by several EDR platforms for threat export reports.
    """
    for line in text.splitlines()[:20]:
        if line.strip() == "Threat Information":
            return True
    return False


def process_file(path: Path, analyzer, anonymizer, entity_mapping, entities,
                 operators, keep_public_ip, keywords, output_dir: Path,
                 max_mb: float = 10.0, do_dedup: bool = True,
                 mapping_dir: Optional[Path] = None):
    text, enc = read_text_any_encoding(path)

    # CSV auto-detection: structured EDR export → dedicated pipeline
    if path.suffix.lower() == ".csv" and is_edr_csv(text):
        if mapping_dir is None:
            mapping_dir = output_dir.parent / "deidentify_mapping"
        ctx = (analyzer, anonymizer, entity_mapping, entities, operators, keep_public_ip, keywords)
        return None, enc, "edr", [], process_edr_file(
            path, ctx, output_dir, mapping_dir, max_mb, do_dedup
        )

    ctx = (analyzer, anonymizer, entity_mapping, entities, operators, keep_public_ip, keywords)
    handler = FORMAT_DISPATCH.get(path.suffix.lower(), process_plain)
    obj, secret_lines = handler(text, *ctx)
    obj["source_file"] = path.name

    output_dir.mkdir(parents=True, exist_ok=True)
    out_path = output_dir / (path.stem + "_deidentified.json")
    out_path.write_text(json.dumps(obj, ensure_ascii=False, indent=2),
                        encoding="utf-8")
    return out_path, enc, obj["format"], secret_lines, None


def deidentify_json_obj(obj, ctx):
    """對已解析的 JSON 物件做去識別化（複用 process_json 的 walk 邏輯）。
    回傳 (去識別後物件, 是否命中 secret)。"""
    flag = []
    entity_mapping = ctx[2]

    def walk(node):
        if isinstance(node, dict):
            out = {}
            for key, value in node.items():
                if is_sensitive_key(key):
                    flag.append(True)
                    new_key = map_value(entity_mapping, "SECRET_KEY", key)
                    out[new_key] = redact_secret_value(
                        stringify_secret_value(value), key, entity_mapping
                    )
                else:
                    out[key] = walk(value)
            return out
        if isinstance(node, list):
            return [walk(v) for v in node]
        if isinstance(node, str):
            return deidentify_text(clean_mojibake(node), *ctx, flag)
        return node

    return walk(obj), bool(flag)


def process_edr_file(path: Path, ctx, output_dir: Path, mapping_dir: Path,
                     max_mb: float, do_dedup: bool):
    """EDR-style CSV pipeline: parse → structured JSON → (dedup) → de-identify.
    Outputs:
      - Full version *_parsed.json (contains real IOCs — keep local only)
      - De-identified version *_parsed_deidentified.json (safe to upload;
        auto-split if size exceeds max_mb)
      - Dedup mapping (keep local only)
    """
    text, enc = read_text_any_encoding(path)
    result = parse_edr_csv(text)
    result["source_file"] = path.name

    raw_count = len(result["events"])
    dedup_map = {}
    if do_dedup:
        compact, dedup_map = dedup_events(result["events"])
        result["events"] = compact
        result["stats"]["after_dedup"] = len(compact)
        result["stats"]["collapsed_groups"] = sum(
            1 for e in compact if e.get("_collapsed"))

    output_dir.mkdir(parents=True, exist_ok=True)
    mapping_dir.mkdir(parents=True, exist_ok=True)

    # 完整版（含真實 IOC）→ 留本地（放 mapping_dir，與去識別輸出分開）
    full_path = mapping_dir / (path.stem + "_parsed.json")
    full_path.write_text(json.dumps(result, ensure_ascii=False, indent=2),
                         encoding="utf-8")

    # dedup mapping → 留本地
    if dedup_map:
        dmap_path = mapping_dir / (path.stem + "_dedup_mapping.json")
        dmap_path.write_text(json.dumps({
            "_note": "去重對照表：以 _group_id 對應被摺疊的完整事件明細，僅供本地回溯。",
            "source_file": path.name,
            "groups": dedup_map,
        }, ensure_ascii=False, indent=2), encoding="utf-8")

    # 去識別化（一律遮，含 IOC）→ 可上傳
    deid_obj, hit_secret = deidentify_json_obj(result, ctx)
    deid_path = output_dir / (path.stem + "_parsed_deidentified.json")
    written, size_mb = write_json_with_split(deid_obj, deid_path, max_mb)

    return {
        "encoding": enc, "raw_count": raw_count,
        "final_count": len(result["events"]),
        "collapsed": result["stats"].get("collapsed_groups", 0),
        "full_path": full_path, "written": written, "size_mb": size_mb,
        "decoded": bool(result["threat"].get("decoded_cmdline")),
        "urls": result["iocs"]["urls"], "hit_secret": hit_secret,
        "has_dedup_map": bool(dedup_map),
    }


def resolve_output_path(base_dir: Path, requested: str) -> Path:
    path = Path(requested)
    return path if path.is_absolute() else base_dir / path


def parse_cli_args(raw_args: List[str]) -> Tuple[List[str], Dict[str, Any]]:
    options = {
        "keep_public_ip": False,
        "redact_uuid": False,
        "output_dir": "deidentified_output",
        "mapping_dir": "deidentify_mapping",
        "max_mb": 10.0,
        "no_dedup": False,
        "keywords": [],
        "custom_id_patterns": [],
    }
    args = []
    i = 0
    while i < len(raw_args):
        arg = raw_args[i]
        if arg == "--keep-public-ip":
            options["keep_public_ip"] = True
        elif arg == "--redact-uuid":
            options["redact_uuid"] = True
        elif arg == "--no-dedup":
            options["no_dedup"] = True
        elif arg == "--max-mb":
            if i + 1 >= len(raw_args):
                raise ValueError("--max-mb 需要指定數字")
            try:
                options["max_mb"] = float(raw_args[i + 1])
            except ValueError:
                raise ValueError("--max-mb 的值必須是數字")
            i += 1
        elif arg.startswith("--max-mb="):
            try:
                options["max_mb"] = float(arg.split("=", 1)[1])
            except ValueError:
                raise ValueError("--max-mb 的值必須是數字")
        elif arg == "--strict-secrets":
            # Strict secret handling is now the default. Keep the flag for compatibility.
            pass
        elif arg in ("-w", "--word"):
            if i + 1 >= len(raw_args):
                raise ValueError("-w 需要指定關鍵字")
            options["keywords"].append(raw_args[i + 1])
            i += 1
        elif arg in ("--custom-id-pattern", "-p"):
            if i + 1 >= len(raw_args):
                raise ValueError("--custom-id-pattern 需要指定正規表達式")
            options["custom_id_patterns"].append(raw_args[i + 1])
            i += 1
        elif arg.startswith("--custom-id-pattern="):
            options["custom_id_patterns"].append(arg.split("=", 1)[1])
        elif arg in ("--output-dir", "--mapping-dir"):
            if i + 1 >= len(raw_args):
                raise ValueError(f"{arg} 需要指定路徑")
            options[arg[2:].replace("-", "_")] = raw_args[i + 1]
            i += 1
        elif arg.startswith("--output-dir="):
            options["output_dir"] = arg.split("=", 1)[1]
        elif arg.startswith("--mapping-dir="):
            options["mapping_dir"] = arg.split("=", 1)[1]
        elif arg.startswith("--"):
            raise ValueError(f"未知旗標：{arg}")
        else:
            args.append(arg)
        i += 1
    return args, options



# ============================================================================
# 主流程
# ============================================================================

def main():
    try:
        args, options = parse_cli_args(sys.argv[1:])
    except ValueError as exc:
        print(f"錯誤：{exc}")
        print("用法：python deidentify.py <檔案> [--keep-public-ip] [--redact-uuid] [-w 關鍵字]")
        print("      [--custom-id-pattern REGEX] [--output-dir DIR] [--mapping-dir DIR]")
        sys.exit(1)

    expanded = []
    for a in args:
        hits = glob.glob(a)
        expanded.extend(hits if hits else [a])
    args = expanded

    if not args:
        print("用法：python deidentify.py <檔案> [--keep-public-ip] [--redact-uuid] [-w 關鍵字]")
        print("      [--custom-id-pattern REGEX] [--output-dir DIR] [--mapping-dir DIR]")
        print("支援格式：.txt / .log / .json / .csv（其餘當純文字）")
        sys.exit(1)

    keep_public_ip = options["keep_public_ip"]
    redact_uuid = options["redact_uuid"]
    keywords = options["keywords"]
    custom_id_patterns = options["custom_id_patterns"]
    first = Path(args[0])
    base_dir = first.parent if first.parent != Path("") else Path.cwd()
    output_dir = resolve_output_path(base_dir, options["output_dir"])
    mapping_dir = resolve_output_path(base_dir, options["mapping_dir"])

    print("=" * 60)
    print(" Log De-identification Tool v3")
    print("=" * 60)

    analyzer, anonymizer, entities = build_engines(redact_uuid, custom_id_patterns)
    entity_mapping: Dict[str, Dict[str, str]] = {}
    operators = build_operator_configs(entity_mapping, entities)
    all_secret_lines = {}

    max_mb = options["max_mb"]
    do_dedup = not options["no_dedup"]

    for a in args:
        p = Path(a)
        if not p.exists():
            print(f"  [跳過] 找不到檔案：{a}")
            continue

        out_path, enc, fmt, secrets, edr_info = process_file(
            p, analyzer, anonymizer, entity_mapping, entities, operators,
            keep_public_ip, keywords, output_dir, max_mb, do_dedup, mapping_dir
        )

        if edr_info:
            info = edr_info
            print(f"  [完成] {p.name}（EDR 自動辨識，編碼={enc}）")
            if do_dedup:
                print(f"     事件數：{info['raw_count']} → 去重後 {info['final_count']}"
                      f"（摺疊 {info['collapsed']} 群組）")
            else:
                print(f"     事件數：{info['raw_count']}（未去重）")
            if info["decoded"]:
                print(f"     [!] PowerShell EncodedCommand 已解碼")
            if info["urls"]:
                print(f"     [!] C2/外部 URL（完整版保留，去識別版已遮）：{info['urls']}")
            print(f"     完整版（留本地）：{info['full_path'].name}")
            if len(info["written"]) > 1:
                print(f"     去識別版超過 {max_mb}MB，已分成主檔 + {len(info['written'])-1} 個 part")
            else:
                print(f"     去識別版（可上傳）：{info['written'][0].name}（{info['size_mb']:.1f}MB）")
            if info["hit_secret"]:
                all_secret_lines[p.name] = [0]
        else:
            print(f"  [完成] {p.name}  格式={fmt}  編碼={enc}  -> {out_path.name}")
            if secrets:
                all_secret_lines[p.name] = secrets

    mapping_dir.mkdir(parents=True, exist_ok=True)
    map_path = mapping_dir / (first.stem + "_mapping.json")
    map_path.write_text(json.dumps({
        "_warning": "SENSITIVE — local use only. Never upload this mapping file alongside the de-identified output.",
        "source_files": args,
        "mapping": entity_mapping,
        "secret_lines": all_secret_lines,
    }, ensure_ascii=False, indent=2), encoding="utf-8")

    print("-" * 60)
    print(f"  Output folder : {output_dir}")
    print(f"  Mapping folder (keep local, do NOT upload): {mapping_dir}")
    print(f"  Mapping file  : {map_path.name}")
    print("-" * 60)
    print(" Audit summary (review before uploading)")
    for etype, bucket in sorted(entity_mapping.items()):
        print(f"   {etype:<14} {len(bucket)} unique value(s) replaced")
    if not redact_uuid:
        print("   [info] UUIDs not redacted — add --redact-uuid to enable")
    if custom_id_patterns:
        for i, pat in enumerate(custom_id_patterns, start=1):
            print(f"   [info] Custom ID pattern #{i}: {pat!r}")
    if all_secret_lines:
        print(f"   [WARNING] Possible passwords/tokens detected: {all_secret_lines}")
        print(f"   [WARNING] Rotate those credentials immediately — redacting alone is not sufficient!")
    print("=" * 60)


if __name__ == "__main__":
    main()
