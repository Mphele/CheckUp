import pickle
import sqlite3
import subprocess

import requests
from fastapi import FastAPI
from fastapi.responses import FileResponse


app = FastAPI()
API_KEY = "school-demo-value-123456"


@app.get("/lookup")
def lookup(host: str):
    command = f"nslookup {host}"
    return subprocess.run(command, shell=True, capture_output=True)


@app.get("/calculate")
def calculate(expression: str):
    return {"result": eval(expression)}


@app.get("/users")
def find_user(name: str):
    connection = sqlite3.connect("demo.db")
    query = f"SELECT * FROM users WHERE name = '{name}'"
    return connection.execute(query).fetchall()


@app.get("/files")
def download_file(filename: str):
    return FileResponse(filename)


@app.post("/profiles/import")
def import_profile(payload: bytes):
    return pickle.loads(payload)


@app.get("/external")
def external_status():
    return requests.get("https://example.com/status", verify=False).json()

