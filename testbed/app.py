"""FastAPI Application for SAGA Vulnerable & Secure Research Testbed."""

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from testbed.routers import auth, secure, vulnerable
from testbed.seed import init_db


@asynccontextmanager
def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Lifespan context manager initializing and seeding testbed database."""
    init_db()
    yield


app = FastAPI(
    title="SAGA Research Testbed API",
    description="Deliberately vulnerable and secure API testbed for security audit experiments.",
    version="0.1.0",
    lifespan=lifespan,
)

app.include_router(auth.router)
app.include_router(vulnerable.router)
app.include_router(secure.router)


@app.get("/", tags=["health"])
def health_check() -> dict[str, str]:
    """Health check endpoint."""
    return {"status": "ok", "app": "SAGA Research Testbed"}
