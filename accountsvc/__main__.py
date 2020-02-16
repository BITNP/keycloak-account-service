import uvicorn
uvicorn.run("accountsvc.app:app", host="127.0.0.1", port=80, log_level="info", reload=True)
# python3.7 -m accountsvc