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
python -m uvicorn main:app --host 0.0.0.0 --port 8888 --log-level info

# Optional: include Step 1 again
MPLANE_INCLUDE_STEP1=1
python -m uvicorn main:app --host 0.0.0.0 --port 8888 --log-level info
```

Open from same host: http://127.0.0.1:8888
Open from external host: http://10.48.238.180:8888/
