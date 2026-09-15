from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from checkup.models import ScanReport, ScanRequest
from checkup.scanning.engine import scan_project


PACKAGE_DIR = Path(__file__).parent
templates = Jinja2Templates(directory=PACKAGE_DIR / "templates")


def create_app() -> FastAPI:
    application = FastAPI(
        title="CheckUp",
        description="A local security review assistant for FastAPI projects.",
    )
    application.mount(
        "/static", StaticFiles(directory=PACKAGE_DIR / "static"), name="static"
    )

    @application.get("/", response_class=HTMLResponse, include_in_schema=False)
    def dashboard(request: Request) -> HTMLResponse:
        return templates.TemplateResponse(request, "index.html")

    @application.get("/health", tags=["system"])
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @application.post("/api/scans", response_model=ScanReport, tags=["scans"])
    def create_scan(request: ScanRequest) -> ScanReport:
        try:
            return scan_project(Path(request.project_path))
        except (FileNotFoundError, NotADirectoryError):
            raise HTTPException(
                status_code=400,
                detail="Choose an existing project directory.",
            ) from None
        except PermissionError:
            raise HTTPException(
                status_code=400,
                detail="CheckUp cannot access that project directory.",
            ) from None

    return application


app = create_app()
