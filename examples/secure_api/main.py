import json
import os
import socket
import sqlite3

import requests
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse


app = FastAPI()
API_KEY = os.getenv("API_KEY")


@app.get("/lookup")
def lookup(host: str):
    return {"address": socket.gethostbyname(host)}


@app.get("/calculate")
def calculate(left: int, right: int):
    return {"result": left + right}


@app.get("/users")
def find_user(name: str):
    connection = sqlite3.connect("demo.db")
    query = "SELECT * FROM users WHERE name = ?"
    return connection.execute(query, (name,)).fetchall()


@app.get("/files")
def download_file(file_id: str):
    if file_id != "terms":
        raise HTTPException(status_code=404, detail="File not found")
    return FileResponse("static/terms.pdf")


@app.post("/profiles/import")
def import_profile(payload: str):
    return json.loads(payload)


@app.get("/external")
def external_status():
    return requests.get("https://example.com/status", timeout=5).json()

