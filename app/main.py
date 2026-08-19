"""Application factory and lifespan."""
import asyncio
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from .collector import collector_state, run_collector, run_container_collector, run_net_collector
from .config import settings
from .db import init_db, run_retention
from .health import run_health_checker
from .routes import api, pages


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    collector_task = asyncio.create_task(run_collector())
    health_task = asyncio.create_task(run_health_checker())
    retention_task = asyncio.create_task(_run_retention_loop())
    net_task = asyncio.create_task(run_net_collector())
    container_task = asyncio.create_task(run_container_collector())
    yield
    for task in (collector_task, health_task, retention_task, net_task, container_task):
        task.cancel()
    await asyncio.gather(collector_task, health_task, retention_task, net_task, container_task, return_exceptions=True)


async def _run_retention_loop():
    while True:
        await asyncio.sleep(86400)
        try:
            run_retention()
        except Exception:
            pass


app = FastAPI(title="sing-box Proxy Dashboard", lifespan=lifespan)

app.add_middleware(
    SessionMiddleware,
    secret_key=settings.secret_key,
    max_age=86400,
    https_only=False,
    same_site="lax",
)

static_dir = Path(__file__).parent / "static"
static_dir.mkdir(exist_ok=True)
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

app.include_router(pages.router)
app.include_router(api.router, prefix="/api")
