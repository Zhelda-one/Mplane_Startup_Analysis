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

아래 명령 쓰시면 백그라운드에서 계속 실행됩니다.

cd ~/mplane_startup_analyzer_V3
nohup python3 -m uvicorn main:app --host 0.0.0.0 --port 8888 --log-level info > mplane.log 2>&1 &
실행 확인:

ps -ef | grep "uvicorn main:app" | grep -v grep
로그 보기:

tail -f mplane.log
종료:

pkill -f "uvicorn main:app --host 0.0.0.0 --port 8888"
현재 프로젝트 문서/코드 기준 포트는 8888, 바인드는 0.0.0.0이 맞습니다.

확인에 사용한 명령:
