#!/usr/bin/env python3

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

# ============================================================
# Rule model
# ============================================================

@dataclass
class Rule:
    id: str
    description: str
    severity: str = "INFO"
    all_pattern: List[str] = None
    any_pattern: List[str] = None
    evidences_pattern: List[str] = None
    extra: Dict[str, Any] = None

    # per-rule contextual collection config
    # collect:
    #   mode: "regex" | "boundary" | "message-id"
    #   before:
    #   after:
    #   max_block_lines:
    #   max_evidence:
    collect: Dict[str, Any] = None

    def __post_init__(self):
        self.all_pattern = self.all_pattern or []
        self.any_pattern = self.any_pattern or []
        self.evidences_pattern = self.evidences_pattern or []
        self.extra = self.extra or {}
        self.collect = self.collect or {}

# ============================================================
# Loader
# ============================================================

def _normalize_collect(c: Dict[str, Any]) -> Dict[str, Any]:
    """
    collect 설정을 안전하게 보정 (앵커가 잘리지 않도록)
    """
    mode = str(c.get("mode", "regex")).lower() if c else "regex"
    before = int(c.get("before", 5)) if c else 5
    after = int(c.get("after", 20)) if c else 20
    max_block_lines = c.get("max_block_lines", 80)
    max_evidence = int(c.get("max_evidence", 3)) if c else 3

    # 최소 필요 길이(앵커 포함): before + after + 1
    min_needed = before + after + 1

    if max_block_lines is None:
        max_block_lines = min_needed
    else:
        max_block_lines = int(max_block_lines)
    if max_block_lines < min_needed:
        max_block_lines = min_needed

    return {
        "mode": mode,
        "before": before,
        "after": after,
        "max_block_lines": max_block_lines,
        "max_evidence": max_evidence,
    }

def load_rules(path: Path | str) -> List[Rule]:
    p = Path(path)
    with p.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or []

    out: List[Rule] = []
    for item in data:
        if not isinstance(item, dict) or "id" not in item:
            continue

        collect_cfg = _normalize_collect(item.get("collect", {}) or {})
        out.append(
            Rule(
                id=str(item.get("id")),
                description=str(item.get("description", "")),
                severity=str(item.get("severity", "INFO")),
                all_pattern=list(item.get("all_pattern", []) or []),
                any_pattern=list(item.get("any_pattern", []) or []),
                evidences_pattern=list(item.get("evidences_pattern", []) or []),
                extra=dict(item.get("extra", {}) or {}),
                collect=collect_cfg,
            )
        )

    return out

# ============================================================
# Helpers
# ============================================================

_TS_RE = re.compile(r"^\s*\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}")

def _compile_many(pats: List[str]) -> List[re.Pattern]:
    return [re.compile(p, re.I | re.M) for p in pats]

def _match_all(text: str, pats: List[re.Pattern]) -> bool:
    return all(p.search(text) for p in pats)

def _match_any(text: str, pats: List[re.Pattern]) -> bool:
    return any(p.search(text) for p in pats) if pats else False

def _to_lines(text: str) -> List[str]:
    return text.splitlines()

def _safe_slice(lines: List[str], start: int, end: int) -> List[str]:
    start = max(1, start)
    end = min(len(lines), end)
    return [lines[i - 1] for i in range(start, end + 1)]

def _block_for_line(lines: List[str], ln: int, before: int, after: int) -> Tuple[int, int]:
    start = max(1, ln - max(0, before))
    end = min(len(lines), ln + max(0, after))
    return start, end

# ---------- contextual collection helpers ----------

_MSG_BOUNDARY_RE = re.compile(r"\bSession\b.*\b(Sending|Received) message:", re.IGNORECASE)
_MSGID_RE = re.compile(r'message-id\s*=\s*"?(\d+)"?', re.IGNORECASE)

def _find_hit_line_indices(text: str, patterns: List[re.Pattern]) -> List[int]:
    lines = _to_lines(text)
    hit: List[int] = []
    for i, ln in enumerate(lines):
        for p in patterns:
            if p.search(ln):
                hit.append(i)
                break
    return hit

def _window_centered(
    lines: List[str],
    idx: int,
    before: int,
    after: int,
    clamp: Optional[int],
) -> Tuple[int, int]:
    """
    앵커를 포함한 before/after 창을 만들되, clamp(최대길이)를 넘으면
    앵커를 기준으로 앞/뒤를 균형 있게 잘라서 포함시키는 창으로 보정.
    """
    s = max(0, idx - max(0, before))
    e = min(len(lines), idx + max(0, after) + 1)

    if clamp is not None and (e - s) > clamp:
        head = min(before, clamp // 2)
        tail = clamp - head - 1
        s = max(0, idx - head)
        e = min(len(lines), idx + tail + 1)
        if e - s > clamp:
            e = s + clamp

    return s, e

def _expand_by_boundary(
    lines: List[str],
    idx: int,
    max_block: int | None = None,
) -> Tuple[int, int]:
    start = idx
    i = idx
    while i >= 0:
        if _MSG_BOUNDARY_RE.search(lines[i]):
            start = i
            break
        i -= 1

    end = idx + 1
    j = idx + 1
    while j < len(lines):
        if _MSG_BOUNDARY_RE.search(lines[j]):
            end = j
            break
        j += 1

    if max_block is not None and (end - start) > max_block:
        end = start + max_block

    return start, end

def _expand_by_message_id(
    lines: List[str],
    idx: int,
    max_block: int | None = None,
) -> Tuple[int, int]:
    m = _MSGID_RE.search(lines[idx])
    if not m:
        lo = max(0, idx - 10)
        hi = min(len(lines), idx + 11)
        for k in range(lo, hi):
            m2 = _MSGID_RE.search(lines[k])
            if m2:
                idx = k
                m = m2
                break

    if not m:
        return _expand_by_boundary(lines, idx, max_block)

    msgid = m.group(1)

    start = idx
    i = idx
    while i >= 0:
        if _MSG_BOUNDARY_RE.search(lines[i]):
            start = i
            break
        m2 = _MSGID_RE.search(lines[i])
        if m2 and m2.group(1) != msgid:
            start = i + 1
            break
        i -= 1

    end = idx + 1
    j = idx + 1
    while j < len(lines):
        if _MSG_BOUNDARY_RE.search(lines[j]):
            end = j
            break
        m2 = _MSGID_RE.search(lines[j])
        if m2 and m2.group(1) != msgid:
            end = j
            break
        j += 1

    if max_block is not None and (end - start) > max_block:
        end = start + max_block

    return start, end

def _collect_contextual_blocks(
    text: str,
    hit_indices: List[int],
    collect_cfg: Dict[str, Any],
    *,
    default_before: int = 0,
    default_after: int = 0,
    default_max_lines: int | None = None,
    max_evidence: int | None = None,
) -> List[Dict[str, Any]]:
    lines = _to_lines(text)

    mode = (collect_cfg.get("mode") or "").lower()
    before = int(collect_cfg.get("before", default_before))
    after = int(collect_cfg.get("after", default_after))
    clamp = collect_cfg.get("max_block_lines", default_max_lines)
    if clamp is not None:
        clamp = int(clamp)

    # regex 모드일 때는 앵커 포함 최소 길이 보장
    min_needed = before + after + 1
    if mode == "regex" and clamp is not None and clamp < min_needed:
        clamp = min_needed

    limit = int(collect_cfg.get("max_evidence", max_evidence or len(hit_indices)))

    blocks: List[Dict[str, Any]] = []
    used = 0

    for idx in hit_indices:
        if used >= limit:
            break

        if mode == "boundary":
            s0, e0 = _expand_by_boundary(lines, idx, clamp)
        elif mode == "message-id":
            s0, e0 = _expand_by_message_id(lines, idx, clamp)
        elif mode == "regex":
            s0, e0 = _window_centered(lines, idx, before, after, clamp)
        else:
            # 옵션 없으면 한 줄만(기존 동작 유지)
            s0, e0 = idx, idx + 1

        s1 = s0 + 1
        e1 = e0
        blk_lines = lines[s0:e0]

        blocks.append(
            {
                "start": s1,
                "end": e1,
                "lines": blk_lines,
                "text": "\n".join(blk_lines),
            }
        )
        used += 1

    return blocks

# ============================================================
# Evidence collection
# ============================================================

def _collect_evidences(
    text: str,
    rule: Rule,
    *,
    ctx_before: int = 3,
    ctx_after: int = 2,
    max_items: int = 15,
    max_chars: int = 8000,
) -> List[Dict[str, Any]]:
    lines = _to_lines(text)

    # 룰별 기본 before/after (기존 extra 방식 유지)
    b = int(rule.extra.get("before", ctx_before)) if isinstance(rule.extra, dict) else ctx_before
    a = int(rule.extra.get("after", ctx_after)) if isinstance(rule.extra, dict) else ctx_after

    raw_pats = rule.evidences_pattern or rule.any_pattern or rule.all_pattern or []
    if not raw_pats:
        return []

    pats = _compile_many(raw_pats)

    # collect가 있으면 per-rule 컨텍스트 확장
    if rule.collect:
        hit = _find_hit_line_indices(text, pats)
        if not hit:
            return []

        blocks = _collect_contextual_blocks(
            text=text,
            hit_indices=sorted(set(hit)),
            collect_cfg=rule.collect,
            default_before=b,
            default_after=a,
            default_max_lines=None,
            max_evidence=10,
        )

        out: List[Dict[str, Any]] = []
        used_chars = 0

        for blk in blocks:
            t = blk.get("text", "")
            if used_chars + len(t) > max_chars:
                break
            out.append(blk)
            used_chars += len(t)
            if len(out) >= max_items:
                break

        return out

    # (구버전) 라인 단위 작은 창
    evidences: List[Dict[str, Any]] = []
    used_lns: set[int] = set()
    printed = 0
    printed_chars = 0
    joined = text

    for p in pats:
        for m in p.finditer(joined):
            if printed >= max_items or printed_chars >= max_chars:
                break
            start_ofs = m.start()
            ln = joined.count("\n", 0, start_ofs) + 1
            if ln in used_lns:
                continue
            used_lns.add(ln)

            s, e = _block_for_line(lines, ln, b, a)
            blk_lines = _safe_slice(lines, s, e)
            t = "\n".join(blk_lines)
            evidences.append(
                {
                    "start": s,
                    "end": e,
                    "lines": blk_lines,
                    "text": t,
                }
            )
            printed += 1
            printed_chars += len(t)

            if printed >= max_items or printed_chars >= max_chars:
                break

    return evidences

# ============================================================
# Evaluation (완전 수정 버전)
# ============================================================

def evaluate_text(
    text: str,
    rules: List[Rule],
    *,
    ctx_lines: Optional[int] = None,
    max_items: Optional[int] = None,
    max_chars: Optional[int] = None,
) -> Dict[str, Any]:
    """
    - 서브 룰(no_judge: true): OBSERVED / NOT_OBSERVED만 표시 (별도 sub_results)
    - 메인 룰: 기존 PASS/FAIL/NO_LOG 로직 (main_results)
    - overall 계산시 no_judge 룰은 완전 제외
    """
    ctx_before = int(ctx_lines or 3)
    ctx_after = int(ctx_lines or 2)
    max_items = int(max_items or 10)
    max_chars = int(max_chars or 2000)

    results: List[Dict[str, Any]] = []
    main_results: List[Dict[str, Any]] = []
    sub_results: Dict[str, List[Dict[str, Any]]] = {}  # parent별 그룹화
    infos = warns = errs = 0

    for r in rules:
        # 패턴 매칭 판정
        all_ok = True
        if r.all_pattern:
            all_ok = _match_all(text, _compile_many(r.all_pattern))

        any_ok = True
        if r.any_pattern:
            any_ok = _match_any(text, _compile_many(r.any_pattern))

        matched = (all_ok and any_ok)

        # extra 플래그 확인
        no_fail = False
        no_judge = False
        parent_id = None
        if isinstance(r.extra, dict):
            no_fail = bool(r.extra.get("no_fail", False))
            no_judge = bool(r.extra.get("no_judge", False))
            parent_id = r.extra.get("parent")

        # 기본 status 결정
        if no_judge:
            # 서브 룰: 관찰 여부만 표시
            status = "OBSERVED" if matched else "NOT_OBSERVED"
        else:
            # 메인 룰: 기존 로직
            status = "PASS" if matched else "NO_LOG"

        # 증거 수집
        evidences = _collect_evidences(
            text,
            r,
            ctx_before=ctx_before,
            ctx_after=ctx_after,
            max_items=max_items,
            max_chars=max_chars,
        )

        # evidence가 없으면 처리
        if not evidences:
            if no_judge:
                # 서브 룰: 관찰 여부 룰은 미관찰로 유지
                status = "NOT_OBSERVED"
                evidences = []
            elif no_fail:
                # no_fail 플래그: FAIL로 안 바꿈
                status = "NO_LOG"
                evidences = []
            elif matched:
                # 패턴은 충족했지만 evidence 수집 실패(포맷/컨텍스트 차이 가능)
                # => 과도한 FAIL 대신 NO_LOG로 완화해 미탐 방지
                status = "NO_LOG"
                evidences = []
            else:
                # 패턴 자체 불충족 + evidence 없음 => FAIL 유지
                status = "FAIL"
                evidences = [{
                    "start": 0,
                    "end": 0,
                    "lines": [],
                    "text": "No logs",
                }]

        evidence_count = sum(len(ev.get("lines") or []) for ev in (evidences or []))

        sev = (r.severity or "INFO").upper()

        result = {
            "id": r.id,
            "description": r.description,
            "severity": r.severity,
            "status": status,
            "evidence_count": evidence_count,
            "evidences": evidences,
            "extra": r.extra or {},
        }

        # 메인 vs 서브 룰 분류
        if no_judge and parent_id:
            # 서브 룰: parent별 그룹화
            if parent_id not in sub_results:
                sub_results[parent_id] = []
            sub_results[parent_id].append(result)
        else:
            # 메인 룰: main_results에 추가 + summary 카운트
            main_results.append(result)
            if status == "PASS":
                if sev == "INFO":
                    infos += 1
                elif sev == "WARN":
                    warns += 1
                else:
                    errs += 1

        results.append(result)  # 전체 호환성용

    # overall: 메인 룰만 보고 결정
    overall = "PASS" if not any(
        x["status"] == "FAIL" for x in main_results
    ) else "FAIL"

    return {
        "overall": overall,
        "summary": {"infos": infos, "warnings": warns, "errors": errs},
        "main_results": main_results,              # 메인 룰들 (PASS/FAIL)
        "sub_results": sub_results,                # { "6.2.6.8": [서브룰들] }
        "results": results,                        # 기존 전체 호환성
    }
