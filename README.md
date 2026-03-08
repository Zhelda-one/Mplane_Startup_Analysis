# O-RAN M-Plane Startup Log Analyzer (Call-Home First Edition)

This build hides Step 1 (Network Discovery) and S1_* rules by default.
To re-enable Step 1 show-up, set `MPLANE_INCLUDE_STEP1=1` before starting the server.

## Install
```
python -m pip install -r requirements.txt
```

## Run
```
# Default: Step 1 hidden
python -m uvicorn main:app --host 127.0.0.1 --port 8000 --log-level info

# Optional: include Step 1 again
$env:MPLANE_INCLUDE_STEP1 = '1'
python -m uvicorn main:app --host 127.0.0.1 --port 8000 --log-level info
```

Open http://127.0.0.1:8000
