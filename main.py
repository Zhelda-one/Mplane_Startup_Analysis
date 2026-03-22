#!/usr/bin/env python3
from __future__ import annotations

import re
import json
import time
import socket
import logging
import hashlib
from pathlib import Path
from typing import Optional, Dict, Any, Iterable

from fastapi import FastAPI, UploadFile, File, Query, Body
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles

# analyzer.py가 같은 폴더에 있어야 합니다.
from analyzer import load_rules, evaluate_text

# ------------------------------------------------------------
# 1. 앱 초기화 (중복 제거됨)
# ------------------------------------------------------------
app = FastAPI()

# ------------------------------------------------------------
# 2. 경로 설정 (Linux Path 호환)
# ------------------------------------------------------------
APP_DIR = Path(__file__).parent.resolve()
STATIC_DIR = APP_DIR / "static"
RULES_PATH = APP_DIR / "rules" / "iot_test_case_v13.yaml"
REPORTS_ROOT = APP_DIR / "reports"

# 디버깅을 위한 로그 설정
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("analyzer")

# ------------------------------------------------------------
# 3. Helper Functions
# ------------------------------------------------------------
SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9._-]+$")

def sanitize_name(s: str) -> str:
    s = (s or "").strip()
    s = re.sub(r"[^A-Za-z0-9._-]+", "_", s)
    return s.strip("_")

def safe_report_path(sw: Optional[str], filename: str) -> Path:
    # reports 폴더가 없으면 생성 (권한 에러 방지용)
    REPORTS_ROOT.mkdir(parents=True, exist_ok=True)
    
    base = REPORTS_ROOT / sanitize_name(sw) if sw else REPORTS_ROOT
    base.mkdir(parents=True, exist_ok=True)
    
    filename = sanitize_name(filename)
    if not SAFE_NAME_RE.match(filename):
        raise ValueError("unsafe filename")
    
    p = base / filename
    # 경로 조작(Directory Traversal) 방지
    p.resolve().relative_to(REPORTS_ROOT.resolve())
    return p

def _date_mmddyyyy() -> str:
    return time.strftime("%m%d%Y", time.localtime())

def gen_unique_run_id(sw_version: str, base_dir: Path) -> str:
    safe_sw = sanitize_name(sw_version) or "default"
    base = f"{safe_sw}-{_date_mmddyyyy()}"

    def taken(candidate: str) -> bool:
        for ext in (".json", ".pdf", ".png"):
            if (base_dir / f"{candidate}{ext}").exists():
                return True
        return False

    if not taken(base):
        return base
    n = 2
    while taken(f"{base}-{n}"):
        n += 1
    return f"{base}-{n}"


SECURE_CONN_RULE_ID = "6.2.6.3 SSH/TLS Secure connection establishment"

SSH_CONN_PATTERNS = [
    r'(?i)Authentication successful',
    r'User\s+"[^"]+"\s+authenticated\.',
    r'(?i)SSH channel established',
]

TLS_CONN_PATTERNS = [
    r'(?i)TLS(?:v1(?:\.[0-3])?)?\s*(?:handshake|session)?\s*(?:successful|complete|established)',
    r'(?i)SSL\s*(?:handshake|session)?\s*(?:successful|complete|established)',
    r'(?i)(?:mTLS|mutual\s*TLS)',
]

def apply_secure_connection_mode(rules, conn_mode: str) -> str:
    mode = (conn_mode or "ssh").strip().lower()
    if mode not in {"ssh", "tls"}:
        mode = "ssh"

    if mode == "ssh":
        selected = SSH_CONN_PATTERNS
    else:
        selected = TLS_CONN_PATTERNS

    for rule in rules:
        if getattr(rule, "id", "") == SECURE_CONN_RULE_ID:
            rule.any_pattern = selected
            break

    return mode


def apply_tls_skip_for_secure_session(report: Dict[str, Any], conn_mode: str) -> None:
    if (conn_mode or "").lower() != "tls":
        return

    for section in ("results", "main_results"):
        for row in report.get(section) or []:
            if row.get("id") != SECURE_CONN_RULE_ID:
                continue
            row["status"] = "PASS"
            row["evidences"] = [{
                "start": 0,
                "end": 0,
                "lines": ["Skipped in TLS mode (auto-pass)."],
                "text": "Skipped in TLS mode (auto-pass).",
            }]
            row["evidence_count"] = 1
            extra = row.get("extra") or {}
            if not isinstance(extra, dict):
                extra = {}
            extra["skipped"] = True
            extra["skip_reason"] = "TLS mode selected"
            row["extra"] = extra

    main_results = report.get("main_results") or []
    report["overall"] = "PASS" if not any(x.get("status") == "FAIL" for x in main_results) else "FAIL"

    infos = warns = errs = 0
    for x in main_results:
        if x.get("status") != "PASS":
            continue
        sev = str(x.get("severity") or "INFO").upper()
        if sev == "INFO":
            infos += 1
        elif sev == "WARN":
            warns += 1
        else:
            errs += 1
    report["summary"] = {"infos": infos, "warnings": warns, "errors": errs}


_XML_OPEN_TAG_RE = re.compile(r"<\s*(?!/)([A-Za-z_][\w:.-]*)\b")
_ISO_TS_RE = re.compile(r"\b\d{4}-\d{2}-\d{2}[T ][0-9:.+-]+Z?\b")
_SESSION_TS_RE = re.compile(r"\b\d{2}:\d{2}:\d{2}(?:\.\d+)?\b")
_SESSION_BOUNDARY_RE = re.compile(r"\bSession\b.*\b(Sending|Received)\s+message:", re.I)
_IGNORED_MAIN_TAGS = {
    "rpc", "rpc-reply", "data", "filter", "config", "edit-config",
    "notification", "hello", "capabilities", "capability"
}


def _strip_ns(tag: str) -> str:
    return (tag or "").split(":")[-1].lower()


def _extract_direction(text: str) -> str:
    m = re.search(r"\b(Sending|Received)\s+message\b", text or "", re.I)
    return (m.group(1).title() if m else "Unknown")


def _extract_message_id(text: str) -> Optional[str]:
    m = re.search(r'message-id\s*=\s*"?(?P<id>\d+)"?', text or "", re.I)
    return m.group("id") if m else None


def _extract_rpc_kind(text: str) -> str:
    lowered = text or ""
    if re.search(r"<\s*hello\b", lowered, re.I):
        return "hello"
    if re.search(r"<\s*rpc-reply\b", lowered, re.I):
        return "rpc-reply"
    if re.search(r"<\s*notification\b", lowered, re.I):
        return "notification"
    if re.search(r"<\s*rpc\b", lowered, re.I):
        return "rpc"
    return "text"


def _extract_main_tag(text: str) -> str:
    for m in _XML_OPEN_TAG_RE.finditer(text or ""):
        local = _strip_ns(m.group(1))
        if local in _IGNORED_MAIN_TAGS:
            continue
        return local
    return "text"


def _normalize_evidence_text(text: str) -> str:
    normalized = (text or "").replace("\r", "")
    normalized = re.sub(r'message-id\s*=\s*"?(?:\d+)"?', 'message-id="*"', normalized, flags=re.I)
    normalized = _ISO_TS_RE.sub("<ts>", normalized)
    normalized = _SESSION_TS_RE.sub("<time>", normalized)
    normalized = re.sub(r">\s+<", "><", normalized)
    normalized = re.sub(r"\s+", " ", normalized).strip()
    return normalized


def _build_evidence_metadata(ev: Dict[str, Any], source_file: str) -> Dict[str, Any]:
    text = str(ev.get("text") or "")
    normalized = _normalize_evidence_text(text)
    signature = hashlib.sha1(normalized.encode("utf-8")).hexdigest()[:12] if normalized else "empty"
    message_id = _extract_message_id(text)
    direction = _extract_direction(text)
    rpc_kind = _extract_rpc_kind(text)
    main_tag = _extract_main_tag(text)
    return {
        "source_file": source_file or "-",
        "message_id": message_id,
        "direction": direction,
        "rpc_kind": rpc_kind,
        "main_tag": main_tag,
        "normalized_signature": signature,
        "duplicate_group_key": f"{source_file or '-'}:{signature}",
    }


def _group_evidences(evidences: list[Dict[str, Any]]) -> list[Dict[str, Any]]:
    groups: Dict[str, Dict[str, Any]] = {}
    order: list[str] = []

    for ev in evidences or []:
        if not isinstance(ev, dict):
            continue
        key = str(ev.get("duplicate_group_key") or ev.get("normalized_signature") or "")
        if not key:
            continue
        if key not in groups:
            groups[key] = {
                "group_key": key,
                "normalized_signature": ev.get("normalized_signature"),
                "source_file": ev.get("source_file") or "-",
                "direction": ev.get("direction") or "Unknown",
                "rpc_kind": ev.get("rpc_kind") or "text",
                "main_tag": ev.get("main_tag") or "text",
                "message_ids": [],
                "occurrence_count": 0,
                "occurrences": [],
            }
            order.append(key)
        group = groups[key]
        msgid = ev.get("message_id")
        if msgid and msgid not in group["message_ids"]:
            group["message_ids"].append(msgid)
        group["occurrence_count"] += 1
        group["occurrences"].append({
            "start": ev.get("start"),
            "end": ev.get("end"),
            "text": ev.get("text"),
            "message_id": ev.get("message_id"),
            "direction": ev.get("direction"),
            "rpc_kind": ev.get("rpc_kind"),
            "main_tag": ev.get("main_tag"),
            "source_file": ev.get("source_file"),
            "normalized_signature": ev.get("normalized_signature"),
        })

    return [groups[k] for k in order]


def _extract_session_blocks(text: str, source_file: str, base_start: int = 1) -> list[Dict[str, Any]]:
    lines = str(text or "").splitlines()
    if not lines:
        return []

    boundary_re = globals().get("_SESSION_BOUNDARY_RE") or re.compile(r"\bSession\b.*\b(Sending|Received)\s+message:", re.I)
    starts = [idx for idx, line in enumerate(lines) if boundary_re.search(line)]
    if not starts:
        starts = [0]

    blocks: list[Dict[str, Any]] = []
    for pos, start in enumerate(starts):
        end = starts[pos + 1] if pos + 1 < len(starts) else len(lines)
        chunk_lines = lines[start:end]
        chunk_text = "\n".join(chunk_lines).strip()
        if not chunk_text:
            continue
        start_line = max(1, int(base_start) + start)
        end_line = max(start_line, int(base_start) + end - 1)
        blocks.append({
            "start": start_line,
            "end": end_line,
            "text": chunk_text,
            "source_file": source_file or "-",
            "message_id": _extract_message_id(chunk_text),
            "direction": _extract_direction(chunk_text),
            "rpc_kind": _extract_rpc_kind(chunk_text),
            "main_tag": _extract_main_tag(chunk_text),
        })
    return blocks


def _normalize_hit_text(text: str) -> str:
    hit = str(text or "").strip()
    hit = re.sub(r'message-id\s*=\s*"?(?:\d+)"?', 'message-id="*"', hit, flags=re.I)
    hit = _ISO_TS_RE.sub("<ts>", hit)
    hit = _SESSION_TS_RE.sub("<time>", hit)
    hit = re.sub(r"\s+", " ", hit).strip()
    return hit


def _find_anchor_block(blocks: list[Dict[str, Any]], hit_line: Optional[int]) -> Optional[Dict[str, Any]]:
    if not blocks:
        return None
    if hit_line is None:
        return blocks[0]

    for block in blocks:
        start = int(block.get("start") or 0)
        end = int(block.get("end") or start)
        if start <= hit_line <= end:
            return block

    return min(
        blocks,
        key=lambda block: min(
            abs(int(block.get("start") or 0) - hit_line),
            abs(int(block.get("end") or 0) - hit_line),
        ),
    )


def _build_transaction_signature(ev: Dict[str, Any], rpc_block: Optional[Dict[str, Any]], reply_block: Optional[Dict[str, Any]]) -> str:
    payload = "||".join([
        str(ev.get("source_file") or "-"),
        _normalize_hit_text(ev.get("match_text") or ""),
        _normalize_evidence_text((rpc_block or {}).get("text") or ""),
        _normalize_evidence_text((reply_block or {}).get("text") or ""),
    ])
    return hashlib.sha1(payload.encode("utf-8")).hexdigest()[:12] if payload else "empty"


def _group_transactions(transactions: list[Dict[str, Any]]) -> list[Dict[str, Any]]:
    groups: Dict[str, Dict[str, Any]] = {}
    order: list[str] = []

    for tx in transactions:
        key = str(tx.get("transaction_signature") or "")
        if not key:
            continue
        if key not in groups:
            groups[key] = {
                "transaction_signature": key,
                "keyword_hit": tx.get("keyword_hit") or "",
                "message_id": tx.get("message_id"),
                "source_file": tx.get("source_file") or "-",
                "occurrence_count": 0,
                "transactions": [],
            }
            order.append(key)
        groups[key]["occurrence_count"] += 1
        groups[key]["transactions"].append(tx)

    return [groups[k] for k in order]


def _build_transactions_for_row(row: Dict[str, Any], source_file: str) -> list[Dict[str, Any]]:
    transactions: list[Dict[str, Any]] = []
    seen: set[tuple[Any, ...]] = set()

    for ev in row.get("evidences") or []:
        if not isinstance(ev, dict):
            continue
        hit_line = ev.get("match_line")
        session_blocks = _extract_session_blocks(ev.get("text") or "", source_file, int(ev.get("start") or 1))
        anchor_block = _find_anchor_block(session_blocks, int(hit_line) if hit_line is not None else None)
        message_id = (anchor_block or {}).get("message_id") or ev.get("message_id")
        relevant_blocks = [b for b in session_blocks if message_id and b.get("message_id") == message_id]
        if not relevant_blocks and anchor_block:
            relevant_blocks = [anchor_block]
        rpc_block = next((b for b in relevant_blocks if b.get("rpc_kind") == "rpc"), None)
        reply_block = next((b for b in relevant_blocks if b.get("rpc_kind") == "rpc-reply"), None)
        notifications = [b for b in relevant_blocks if b.get("rpc_kind") == "notification"]
        if not relevant_blocks:
            relevant_blocks = session_blocks

        signature = _build_transaction_signature(ev, rpc_block, reply_block)
        dedupe_key = (
            message_id or "n/a",
            ev.get("match_line") or 0,
            signature,
        )
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)

        transactions.append({
            "transaction_signature": signature,
            "source_file": source_file or "-",
            "message_id": message_id,
            "keyword_hit": ev.get("match_text") or "",
            "match_line": ev.get("match_line"),
            "rpc": rpc_block,
            "rpc_reply": reply_block,
            "notifications": notifications,
            "raw_blocks": relevant_blocks,
        })

    return transactions


def enrich_report_evidences(report: Dict[str, Any], source_file: str) -> None:
    for row in report.get("results") or []:
        evidences = row.get("evidences") or []
        for ev in evidences:
            if not isinstance(ev, dict):
                continue
            ev.update(_build_evidence_metadata(ev, source_file))
        row["evidence_groups"] = _group_evidences(evidences)
        row["evidence_transactions"] = _group_transactions(_build_transactions_for_row(row, source_file))
        collect_mode = str(row.get("collect_mode") or "").lower()
        row["view_mode"] = "transaction" if collect_mode == "message-id" and row["evidence_transactions"] else "context"

# ------------------------------------------------------------
# 4. Export Dependencies (PDF/PNG)
# ------------------------------------------------------------
EXPORT_CAP = {"pdf": False, "png": False}

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfgen import canvas
    from reportlab.lib.utils import simpleSplit
    from reportlab.lib import colors
    EXPORT_CAP["pdf"] = True
except ImportError:
    pass

try:
    from PIL import Image, ImageDraw, ImageFont
    EXPORT_CAP["png"] = True
except ImportError:
    pass

# ------------------------------------------------------------
# 5. Export Logic
# ------------------------------------------------------------
def _iter_evidence_lines(ev) -> Iterable[str]:
    if isinstance(ev, dict):
        rng = ev.get("range") or ev.get("label")
        if "lines" in ev and isinstance(ev["lines"], list):
            if rng: yield f"[{rng}]"
            for ln in ev["lines"]:
                yield str(ln)
            return
        if "text" in ev and isinstance(ev["text"], str):
            if rng: yield f"[{rng}]"
            for ln in ev["text"].splitlines():
                yield ln
            return
    elif isinstance(ev, str):
        for ln in ev.splitlines():
            yield ln
        return
    elif isinstance(ev, list):
        for ln in ev:
            yield str(ln)
        return

def export_pdf(report: Dict[str, Any], out_path: Path):
    if not EXPORT_CAP["pdf"]:
        raise RuntimeError("PDF export not available")

    MAX_BLOCKS_PER_RULE = 5
    MAX_CHARS_PER_RULE  = 4000

    c = canvas.Canvas(str(out_path), pagesize=A4)
    W, H = A4
    left, top = 40, H - 50
    line_h = 14

    def draw_line(txt: str, size=11, bold=False, color=None):
        nonlocal top
        if top < 60: c.showPage(); top = H - 50
        font = "Helvetica-Bold" if bold else "Helvetica"
        c.setFont(font, size)
        c.setFillColor(color or colors.black)
        for seg in simpleSplit(str(txt), font, size, W - 2 * left):
            c.drawString(left, top, seg); top -= line_h

    def new_page_if_needed(min_space=80):
        nonlocal top
        if top < min_space:
            c.showPage(); top = H - 50

    title = report.get("title") or "O-RAN M-Plane Startup Log Analyzer - Report"
    draw_line(title, 14, True)
    draw_line(f"Run ID: {report.get('run_id','-')}   SW: {report.get('sw_version') or '-'}", 10)
    draw_line(f"Input: {report.get('input_filename','-')}", 10)
    draw_line(f"Saved At (UTC): {report.get('saved_at','-')}", 10)
    draw_line(f"Overall: {report.get('overall','-')}", 12, True)
    top -= 6

    # Table
    table_width = W - 2 * left
    col_w_id = int(table_width * 0.80)
    x_id = left
    x_status = left + col_w_id

    def draw_header():
        nonlocal top
        new_page_if_needed(100)
        y = top
        c.setFillColorRGB(243/255, 247/255, 251/255)
        c.rect(left - 4, y - (line_h + 4), (W - 2*left) + 8, line_h + 8, fill=1, stroke=0)
        c.setFillColor(colors.black)
        c.setFont("Helvetica-Bold", 10)
        c.drawString(x_id, y - 2, "IOT Test ID")
        c.drawString(x_status, y - 2, "Status")
        top = y - (line_h + 4) - 6

    def draw_row(rule_id: str, status: str):
        nonlocal top
        new_page_if_needed(80)
        c.setFont("Helvetica", 10)
        c.setFillColor(colors.black)
        id_lines = simpleSplit(rule_id or "", "Helvetica", 10, int((W - 2*left) * 0.80) - 4)
        row_h = max(line_h * len(id_lines), line_h)
        if top - row_h < 40:
            c.showPage(); top = H - 50; draw_header()
        y = top
        for seg in id_lines:
            c.drawString(x_id, y, seg); y -= line_h
        st = (status or "").upper()
        if st == "PASS": c.setFillColorRGB(34/255, 139/255, 34/255)
        elif st == "FAIL": c.setFillColorRGB(204/255, 0, 0)
        else: c.setFillColor(colors.black)
        c.drawString(x_status, top, st)
        top -= (row_h + 2)
        c.setFillColor(colors.black)

    draw_header()
    for r in (report.get("results") or []):
        draw_row(str(r.get("id","")), str(r.get("status","")))

    # Logs
    top -= 4
    draw_line("Detailed Logs", 12, True)

    for r in (report.get("results") or []):
        rid = str(r.get("id",""))
        status = (r.get("status","") or "").upper()
        color = colors.green if status=="PASS" else (colors.red if status=="FAIL" else colors.black)
        draw_line(f"[{rid}] Status: {status}", 11, True, color=color)

        evidences = r.get("evidences") or []
        if not evidences:
            draw_line("(no captured logs)", 10)
            continue

        printed_chars = 0
        blocks = 0
        for ev in evidences:
            if blocks >= MAX_BLOCKS_PER_RULE: 
                draw_line("... (more evidence blocks omitted)", 10, False, color=colors.grey)
                break
            blocks += 1
            draw_line("— Logs —", 10, True)
            lines = list(_iter_evidence_lines(ev))
            for ln in lines:
                if printed_chars >= MAX_CHARS_PER_RULE:
                    draw_line("... (truncated)", 10, False, color=colors.grey)
                    break
                printed_chars += len(ln) + 1
                for seg in simpleSplit(ln, "Helvetica", 10, W - 2*left):
                    draw_line(seg, 10)
        top -= 4
        new_page_if_needed(60)

    c.showPage()
    c.save()

def export_png(report: Dict[str, Any], out_path: Path):
    if not EXPORT_CAP["png"]:
        raise RuntimeError("PNG export not available")
    
    try:
        font = ImageFont.truetype("arial.ttf", 16)
        small = ImageFont.truetype("arial.ttf", 13)
    except Exception:
        font = ImageFont.load_default()
        small = ImageFont.load_default()

    rows = min(60, len(report.get("results") or []))
    row_h = 24
    w = 1100
    h = 180 + rows * row_h + 20

    img = Image.new("RGB", (w, h), (255, 255, 255))
    d = ImageDraw.Draw(img)

    def text(x, y, t, f=font, color=(20, 20, 20)):
        d.text((x, y), str(t), font=f, fill=color)

    title = report.get("title") or "O-RAN M-Plane Startup Log Analyzer - Report"
    text(16, 12, title, font)
    text(16, 40, f"Run ID: {report.get('run_id','-')}    SW: {report.get('sw_version') or '-'}", small)
    text(16, 60, f"Input: {report.get('input_filename','-')}", small)
    text(16, 80, f"Saved At (UTC): {report.get('saved_at','-')}", small)
    text(16, 104, f"Overall: {report.get('overall','-')}", font)

    table_y = 150
    colx = [16, 740]
    header_h = 26
    d.rectangle((12, table_y - 6, w - 12, table_y - 6 + header_h), fill=(243,247,251))
    text(colx[0], table_y - 2, "IOT Test ID", small)
    text(colx[1], table_y - 2, "Status", small)

    y = table_y + header_h + 6
    for r in (report.get("results") or [])[:rows]:
        text(colx[0], y, r.get("id",""), small)
        st = (r.get("status","") or "").upper()
        color = (34,139,34) if st=="PASS" else ((204,0,0) if st=="FAIL" else (20,20,20))
        text(colx[1], y, st, small, color=color)
        y += row_h

    img.save(str(out_path))

# ------------------------------------------------------------
# 6. API Endpoints
# ------------------------------------------------------------

def _guess_media_type(p: Path) -> str:
    ext = p.suffix.lower()
    if ext == ".pdf": return "application/pdf"
    if ext == ".png": return "image/png"
    if ext == ".json": return "application/json"
    return "application/octet-stream"

@app.get("/")
async def root():
    index_path = STATIC_DIR / "index.html"
    if not index_path.exists():
        return JSONResponse({"error": "index.html not found"}, status_code=404)
    return FileResponse(
        str(index_path),
        headers={
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "Pragma": "no-cache",
            "Expires": "0",
        },
    )

# static 폴더 마운트
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

@app.get("/healthz")
def healthz():
    return {"ok": True}

# 파일 다운로드 경로 (반드시 uvicorn.run 이전에 정의되어야 함)
@app.get("/api/reports/{maybe_ver}/{filename}")
async def download_with_ver(maybe_ver: str, filename: str):
    try:
        p = safe_report_path(maybe_ver, filename)
        if not p.exists():
            return JSONResponse({"error": "not found"}, status_code=404)
        return FileResponse(str(p), media_type=_guess_media_type(p), filename=p.name)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=400)

@app.get("/api/reports/{filename}")
async def download_no_ver(filename: str):
    try:
        p = safe_report_path(None, filename)
        if not p.exists():
            return JSONResponse({"error": "not found"}, status_code=404)
        return FileResponse(str(p), media_type=_guess_media_type(p), filename=p.name)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=400)

# 분석 API
@app.post("/api/analyze")
async def api_analyze(
    logfile: UploadFile = File(...),
    ctx: Optional[int] = Query(None),
    items: Optional[int] = Query(None),
    maxchars: Optional[int] = Query(None),
    conn_mode: Optional[str] = Query("ssh"),
):
    try:
        text = (await logfile.read()).decode("utf-8", errors="replace")
        
        # 룰 파일 존재 여부 확인
        if not RULES_PATH.exists():
             return JSONResponse({"error": f"Rule file not found at {RULES_PATH}"}, status_code=500)

        rules = load_rules(RULES_PATH)
        selected_conn_mode = apply_secure_connection_mode(rules, conn_mode or "ssh")
        report = evaluate_text(text, rules, ctx_lines=ctx, max_items=items, max_chars=maxchars)
        apply_tls_skip_for_secure_session(report, selected_conn_mode)
        enrich_report_evidences(report, logfile.filename or "-")
        report.update({
            "run_id": None,
            "input_filename": logfile.filename,
            "saved_at": None,
            "sw_version": None,
            "exports": {},
            "saved_path": None,
            "connection_mode": selected_conn_mode,
        })
        return JSONResponse(report)
    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        return JSONResponse({"error": f"Internal Server Error: {str(e)}"}, status_code=500)

# 저장 API
@app.post("/api/save")
async def api_save(payload: Dict[str, Any] = Body(...)):
    report = payload.get("report") or {}
    sw_version = (payload.get("sw_version") or "").strip()
    export_str = (payload.get("export") or "").strip()
    export_types = {t.strip().lower() for t in export_str.split(",") if t.strip()}

    safe_sw = sanitize_name(sw_version) or "default"
    base_dir = REPORTS_ROOT / safe_sw
    # 디렉토리 생성 보장
    base_dir.mkdir(parents=True, exist_ok=True)

    run_id = gen_unique_run_id(safe_sw, base_dir)
    report["run_id"] = run_id
    report["sw_version"] = safe_sw
    report["saved_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    # JSON 저장
    json_path = base_dir / f"{run_id}.json"
    json_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    exports: Dict[str, str] = {}
    errors: Dict[str, str] = {}

    if "pdf" in export_types:
        try:
            pdf_path = base_dir / f"{run_id}.pdf"
            export_pdf(report, pdf_path)
            if pdf_path.exists():
                exports["pdf"] = f"/api/reports/{safe_sw}/{pdf_path.name}"
            else:
                errors["pdf"] = "PDF not generated"
        except Exception as e:
            errors["pdf"] = str(e)

    if "png" in export_types:
        try:
            png_path = base_dir / f"{run_id}.png"
            export_png(report, png_path)
            if png_path.exists():
                exports["png"] = f"/api/reports/{safe_sw}/{png_path.name}"
            else:
                errors["png"] = "PNG not generated"
        except Exception as e:
            errors["png"] = str(e)

    body = {
        "saved_path": f"reports/{safe_sw}/{json_path.name}",
        "exports": exports
    }
    if errors: body["errors"] = errors
    return JSONResponse(body)


# ------------------------------------------------------------
# 7. Execution Entry Point
# ------------------------------------------------------------

def get_server_ip():
    """사내망 환경에서 서버의 IP를 찾습니다 (Intranet 친화적)"""
    try:
        # 8.8.8.8은 사내망에서 막힐 수 있으므로, UDP 소켓만 생성하여 IP 추측
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            # 실제로 연결하지 않고 라우팅 테이블만 참조함
            sock.connect(('10.255.255.255', 1))
            return sock.getsockname()[0]
    except Exception:
        try:
            # 실패 시 hostname으로 시도
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "127.0.0.1"

if __name__ == "__main__":
    import uvicorn
    
    server_ip = get_server_ip()
    # 포트를 8001로 변경 (기존 8000 충돌 해결)
    port = 8888
    
    print(f"\n" + "="*50)
    print(f"  O-RAN Analyzer 서버가 시작되었습니다!")
    print(f"  외부 접속 주소: http://{server_ip}:{port}")
    print(f"  서버 이름 접속: http://usda5g25iperf002:{port}")
    print("="*50 + "\n")
    
    # 여기서 서버가 실행되어 loop에 들어갑니다.
    # 이 줄 아래에 있는 코드는 서버 종료 전까지 실행되지 않습니다.
    uvicorn.run(app, host="0.0.0.0", port=port)
