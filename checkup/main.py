from fastapi import FastAPI


def create_app() -> FastAPI:
    application = FastAPI(
        title="CheckUp",
        description="A local security review assistant for FastAPI projects.",
    )

    @application.get("/health", tags=["system"])
    def health() -> dict[str, str]:
        return {"status": "ok"}

    return application


app = create_app()

