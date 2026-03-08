# Copilot Instructions for O-RAN M-Plane Startup Log Analyzer

## Project Overview
This is a FastAPI-based web application for analyzing O-RAN (Open Radio Access Network) startup logs against predefined YAML rules. The system detects compliance issues in M-Plane communication logs through pattern matching and contextual evidence extraction.

## Architecture

### Core Components

**1. `main.py` - Web API Server**
- FastAPI application serving HTTP endpoints for log upload and analysis
- Handles file management, report generation (JSON/PDF/PNG exports)
- Routes: `/analyze` (upload & process), `/report/{run_id}` (retrieve results)
- Environment variable: `MPLANE_INCLUDE_STEP1=1` toggles Step 1 rules visibility

**2. `analyzer.py` - Rule Engine (524 lines)**
- `Rule` dataclass: Defines pattern-matching rules with evidence collection configuration
- `load_rules(path)` → loads YAML rules and normalizes `collect` settings
- `evaluate_text(text, rules)` → main evaluation function returning `{overall, main_results, sub_results, summary}`
- Key distinction: **main rules** (PASS/FAIL) vs **sub-rules** (OBSERVED/NOT_OBSERVED) via `no_judge: true` flag

**3. `rules/iot_test_case_v13.yaml` - Rule Definitions**
- YAML format with fields: `id`, `description`, `severity`, `all_pattern`, `any_pattern`, `evidences_pattern`, `collect`, `extra`
- Example: Rule `6.2.6.3` checks for SSH/TLS connection with 5 lines before, 2 after context
- Rules marked with `extra.no_judge: true` are sub-rules (metadata only, don't affect overall pass/fail)

## Key Patterns & Conventions

### Pattern Matching Strategy
- **`all_pattern`**: ALL patterns must match (AND logic)
- **`any_pattern`**: At least ONE pattern must match (OR logic)
- **`evidences_pattern`**: Patterns for extracting evidence lines (defaults to `any_pattern` if absent)
- Patterns are compiled with `re.I | re.M` flags (case-insensitive, multiline)

### Evidence Collection Modes
Rules use `collect.mode` for contextual extraction:
- **`regex` (default)**: Extract `before/after` lines around match; respects `max_block_lines` clamping
- **`boundary`**: Extract from message boundary to boundary (line with `Session...Sending|Received message`)
- **`message-id`**: Extract by grouping lines with same `message-id=` value
- Limit results: `max_evidence` per rule (default 3), `max_chars` per analysis (default 2000)

### Result Classification
```python
# Main rule flow:
matched = all_ok and any_ok  # Pattern matching
if matched: status = "PASS"
else: status = "NO_LOG" or "FAIL" (depends on no_fail flag)

# Sub-rule flow (no_judge: true):
status = "OBSERVED" if matched else "NOT_OBSERVED"

# Overall calculation:
overall = "PASS" if no main_rule is "FAIL" else "FAIL"
# (sub-rules excluded from overall)
```

### Report Structure
Analysis returns `Dict` with:
- `overall`: "PASS" or "FAIL" (main rules only)
- `main_results`: List of main rules with status/evidences
- `sub_results`: Dict grouped by `extra.parent` ID for organized display
- `summary`: `{infos, warnings, errors}` counts (from main rules only)

## Critical Developer Workflows

### Run Server
```powershell
# Default (Step 1 hidden)
python -m uvicorn main:app --host 127.0.0.1 --port 8000 --log-level info

# Include Step 1 rules
$env:MPLANE_INCLUDE_STEP1 = '1'
python -m uvicorn main:app --host 127.0.0.1 --port 8000 --log-level info
```

### Add/Modify Rules
1. Edit `rules/iot_test_case_v13.yaml`
2. Test patterns with Python: `re.compile(pattern, re.I | re.M).search(text)`
3. Verify `collect.mode` for evidence extraction (especially message boundaries)
4. Reload server; rules auto-load on `/analyze` request

### Export Capabilities
- **PDF** (reportlab): Requires `from reportlab...` imports; exports first 5 blocks per rule, 4000 char limit
- **PNG** (Pillow): Image rendering of report table
- Check `EXPORT_CAP` dict before triggering exports

## Important Details

### Path Safety
- All report paths sanitized via `sanitize_name()`: converts non-alphanumeric to `_`
- Reports stored in `reports/{sanitized_sw}/{run_id}.json|pdf|png`
- Unique run_id generation: `{sw_version}-MMDDYYYY` (+`-2`, `-3` etc. for duplicates)

### Datetime Handling
- Log lines matched for ISO 8601 timestamp prefix: `YYYY-MM-DDTHH:MM:SS`
- Stored as `saved_at` in UTC in JSON reports

### Performance Constraints
- Single text analysis: max 10 evidence items, max 2000 chars per rule
- PDF generation: clamped to 5 blocks per rule, max 4000 chars
- Message-id search: scans ±10 lines before finding pattern

### Dependencies
Core: `fastapi`, `uvicorn`, `PyYAML`, `pydantic`
Optional exports: `reportlab` (PDF), `Pillow` (PNG)

## Common Modifications

**Adjust evidence context globally**: Modify `ctx_before=3, ctx_after=2` in `evaluate_text()` signature
**Add new collection mode**: Implement `_expand_by_X()` function in analyzer.py, add case to `_collect_contextual_blocks()`
**Hide/show rule categories**: Use `extra.category` in YAML and filter in main.py response
**Change report location**: Update `REPORTS_ROOT` path in main.py
