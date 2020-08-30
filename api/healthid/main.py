from typing import Optional
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import os
from healthid.api import api
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(
    title=f"HealthID standalone WebApp",
)

origins = [
    "http://localhost:8000",
    "http://localhost:8080",
    "https://acme.spilikin.dev",
    "https://appauth.acme.spilikin.dev",
    "https://id.acme.spilikin.dev",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount('/api', api)

if "API_ENV" in os.environ and os.environ['API_ENV'] == 'DOCKER':
    vue_dir = "./vue/"
else:
    vue_dir = "../vue/dist/"

templates = Jinja2Templates(directory=vue_dir)

@app.get('/')
def signin(request: Request):
    return RedirectResponse("/Account/")

@app.get('/SignIn/')
def signin(request: Request):
    return templates.TemplateResponse("SignIn.html", {"request": request})

@app.get('/SignIn/{subpage}')
def signin_subpage(request: Request, subpage: str):
    return templates.TemplateResponse("SignIn.html", {"request": request})

@app.get('/Account/')
def account(request: Request):
    return templates.TemplateResponse("Account.html", {"request": request})

@app.get('/Account/{subpath}')
def account_subpath(request: Request):
    return templates.TemplateResponse("Account.html", {"request": request})


app.mount("/", StaticFiles(directory=vue_dir), name="static")
