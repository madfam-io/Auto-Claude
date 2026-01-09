"""
Auto-Claude Agent API
======================

FastAPI REST wrapper for the Auto-Claude autonomous coding framework.
Provides headless API access with Janua SSO JWT authentication.

Endpoints:
    POST /tasks - Submit a new task
    GET /tasks - List all tasks
    GET /tasks/{task_id} - Get task status and details
    GET /tasks/{task_id}/logs - Get task execution logs
    DELETE /tasks/{task_id} - Cancel/delete a task

Authentication:
    All endpoints require a valid Janua JWT token in the Authorization header.
    Format: Authorization: Bearer <token>
"""

import asyncio
import json
import logging
import os
import sys
import uuid
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Any

import httpx
from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

# Ensure backend directory is in path
_BACKEND_DIR = Path(__file__).parent
if str(_BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(_BACKEND_DIR))

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# JWT validation settings
JANUA_URL = os.environ.get("JANUA_URL", "https://auth.madfam.io")
JANUA_JWKS_URL = os.environ.get("JANUA_JWKS_URL", f"{JANUA_URL}/.well-known/jwks.json")

# In-memory task registry (in production, use Redis or a database)
_TASKS: dict[str, dict[str, Any]] = {}
_TASK_PROCESSES: dict[str, asyncio.subprocess.Process] = {}

# Security
security = HTTPBearer()

# JWKS cache
_jwks_cache: dict[str, Any] | None = None
_jwks_cache_time: float = 0
JWKS_CACHE_TTL = 3600  # 1 hour


class TaskRequest(BaseModel):
    """Request model for creating a new task."""

    description: str = Field(..., min_length=1, max_length=10000)
    project_url: str | None = Field(
        None, description="Git repository URL to clone (optional)"
    )
    complexity: str = Field(
        "auto", description="Task complexity: auto, simple, standard, complex"
    )
    model: str = Field(
        "claude-sonnet-4-5-20250929", description="Claude model to use"
    )


class TaskResponse(BaseModel):
    """Response model for task information."""

    id: str
    status: str
    description: str
    created_at: str
    updated_at: str
    user_id: str
    progress: dict[str, Any] | None = None
    error: str | None = None


class TaskListResponse(BaseModel):
    """Response model for listing tasks."""

    tasks: list[TaskResponse]
    total: int


async def get_jwks() -> dict[str, Any]:
    """Fetch and cache JWKS from Janua."""
    global _jwks_cache, _jwks_cache_time

    import time

    now = time.time()
    if _jwks_cache and (now - _jwks_cache_time) < JWKS_CACHE_TTL:
        return _jwks_cache

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(JANUA_JWKS_URL, timeout=10.0)
            response.raise_for_status()
            _jwks_cache = response.json()
            _jwks_cache_time = now
            logger.info(f"Fetched JWKS from {JANUA_JWKS_URL}")
            return _jwks_cache
    except Exception as e:
        logger.error(f"Failed to fetch JWKS: {e}")
        if _jwks_cache:
            return _jwks_cache
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Unable to validate tokens - JWKS unavailable",
        )


async def verify_janua_token(
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> dict[str, Any]:
    """
    Verify JWT token against Janua JWKS.

    Returns the decoded token claims if valid.
    Raises HTTPException if invalid.
    """
    token = credentials.credentials

    try:
        # Import jose for JWT validation
        from jose import JWTError, jwt
        from jose.constants import ALGORITHMS

        # Get JWKS
        jwks = await get_jwks()

        # Get the key ID from the token header
        unverified_header = jwt.get_unverified_header(token)
        kid = unverified_header.get("kid")

        if not kid:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token missing key ID",
            )

        # Find the matching key
        key = None
        for k in jwks.get("keys", []):
            if k.get("kid") == kid:
                key = k
                break

        if not key:
            # Refresh JWKS and try again
            global _jwks_cache_time
            _jwks_cache_time = 0
            jwks = await get_jwks()
            for k in jwks.get("keys", []):
                if k.get("kid") == kid:
                    key = k
                    break

        if not key:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token signing key not found",
            )

        # Verify the token
        claims = jwt.decode(
            token,
            key,
            algorithms=[key.get("alg", "RS256")],
            audience=os.environ.get("JANUA_CLIENT_ID"),
            issuer=JANUA_URL,
            options={"verify_exp": True, "verify_aud": True, "verify_iss": True},
        )

        return claims

    except JWTError as e:
        logger.warning(f"JWT validation failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {str(e)}",
        )
    except ImportError:
        logger.error("python-jose not installed")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="JWT validation not configured",
        )


def get_user_id(claims: dict[str, Any]) -> str:
    """Extract user ID from token claims."""
    return claims.get("sub") or claims.get("user_id") or "unknown"


def get_workspace_dir(user_id: str, task_id: str) -> Path:
    """Get the workspace directory for a task."""
    base_dir = Path(os.environ.get("WORKSPACE_BASE_DIR", "/tmp/auto-claude"))
    return base_dir / user_id / task_id


async def run_task_async(task_id: str, task_info: dict[str, Any]) -> None:
    """Run a task asynchronously in a subprocess."""
    workspace_dir = get_workspace_dir(task_info["user_id"], task_id)
    workspace_dir.mkdir(parents=True, exist_ok=True)

    try:
        # Update status
        _TASKS[task_id]["status"] = "running"
        _TASKS[task_id]["updated_at"] = datetime.utcnow().isoformat()

        # If project_url is provided, clone the repository
        if task_info.get("project_url"):
            logger.info(f"Cloning repository: {task_info['project_url']}")
            clone_proc = await asyncio.create_subprocess_exec(
                "git",
                "clone",
                "--depth=1",
                task_info["project_url"],
                str(workspace_dir / "project"),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await clone_proc.wait()
            if clone_proc.returncode != 0:
                stderr = await clone_proc.stderr.read()
                raise Exception(f"Failed to clone repository: {stderr.decode()}")
            project_dir = workspace_dir / "project"
        else:
            # Use workspace as project dir
            project_dir = workspace_dir
            # Initialize git repo
            await asyncio.create_subprocess_exec(
                "git", "init", cwd=str(project_dir)
            )

        # Create spec using spec_runner
        spec_runner = _BACKEND_DIR / "runners" / "spec_runner.py"
        logger.info(f"Creating spec for task {task_id}")

        spec_proc = await asyncio.create_subprocess_exec(
            sys.executable,
            str(spec_runner),
            "--task",
            task_info["description"],
            "--complexity",
            task_info.get("complexity", "auto"),
            "--auto-approve",
            "--project-dir",
            str(project_dir),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(project_dir),
            env={**os.environ, "PROJECT_DIR": str(project_dir)},
        )
        _TASK_PROCESSES[task_id] = spec_proc

        stdout, stderr = await spec_proc.communicate()

        if spec_proc.returncode != 0:
            logger.error(f"Spec creation failed: {stderr.decode()}")
            _TASKS[task_id]["status"] = "failed"
            _TASKS[task_id]["error"] = f"Spec creation failed: {stderr.decode()[:500]}"
            return

        # Find the created spec directory
        specs_dir = project_dir / ".auto-claude" / "specs"
        if not specs_dir.exists():
            _TASKS[task_id]["status"] = "failed"
            _TASKS[task_id]["error"] = "No spec directory created"
            return

        spec_dirs = sorted(specs_dir.iterdir())
        if not spec_dirs:
            _TASKS[task_id]["status"] = "failed"
            _TASKS[task_id]["error"] = "No spec created"
            return

        spec_dir = spec_dirs[-1]  # Most recent spec
        _TASKS[task_id]["spec_name"] = spec_dir.name

        # Run the build
        logger.info(f"Running build for task {task_id}, spec {spec_dir.name}")
        run_script = _BACKEND_DIR / "run.py"

        build_proc = await asyncio.create_subprocess_exec(
            sys.executable,
            str(run_script),
            "--spec",
            spec_dir.name,
            "--project-dir",
            str(project_dir),
            "--auto-continue",
            "--model",
            task_info.get("model", "claude-sonnet-4-5-20250929"),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(project_dir),
            env={**os.environ, "PROJECT_DIR": str(project_dir)},
        )
        _TASK_PROCESSES[task_id] = build_proc

        stdout, stderr = await build_proc.communicate()

        # Check result
        if build_proc.returncode == 0:
            _TASKS[task_id]["status"] = "completed"
            logger.info(f"Task {task_id} completed successfully")
        else:
            _TASKS[task_id]["status"] = "failed"
            _TASKS[task_id]["error"] = f"Build failed: {stderr.decode()[:500]}"
            logger.error(f"Task {task_id} failed: {stderr.decode()[:200]}")

        # Save logs
        log_file = workspace_dir / "build.log"
        log_file.write_text(stdout.decode() + "\n--- STDERR ---\n" + stderr.decode())
        _TASKS[task_id]["log_file"] = str(log_file)

    except asyncio.CancelledError:
        _TASKS[task_id]["status"] = "cancelled"
        logger.info(f"Task {task_id} was cancelled")
    except Exception as e:
        _TASKS[task_id]["status"] = "failed"
        _TASKS[task_id]["error"] = str(e)[:500]
        logger.exception(f"Task {task_id} failed with exception")
    finally:
        _TASKS[task_id]["updated_at"] = datetime.utcnow().isoformat()
        if task_id in _TASK_PROCESSES:
            del _TASK_PROCESSES[task_id]


def get_task_progress(task_id: str) -> dict[str, Any] | None:
    """Get progress information for a task from implementation_plan.json."""
    task = _TASKS.get(task_id)
    if not task:
        return None

    spec_name = task.get("spec_name")
    if not spec_name:
        return None

    workspace_dir = get_workspace_dir(task["user_id"], task_id)
    project_dir = workspace_dir / "project" if task.get("project_url") else workspace_dir
    plan_file = project_dir / ".auto-claude" / "specs" / spec_name / "implementation_plan.json"

    if not plan_file.exists():
        return None

    try:
        plan = json.loads(plan_file.read_text())
        subtasks = plan.get("subtasks", [])
        completed = sum(1 for s in subtasks if s.get("status") == "completed")
        in_progress = sum(1 for s in subtasks if s.get("status") == "in_progress")
        pending = sum(1 for s in subtasks if s.get("status") == "pending")
        return {
            "total": len(subtasks),
            "completed": completed,
            "in_progress": in_progress,
            "pending": pending,
            "subtasks": [
                {
                    "id": s.get("id"),
                    "description": s.get("description", "")[:200],
                    "status": s.get("status"),
                }
                for s in subtasks
            ],
        }
    except Exception:
        return None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler."""
    logger.info("Auto-Claude Agent API starting up")
    yield
    # Cleanup: cancel any running tasks
    for task_id, proc in list(_TASK_PROCESSES.items()):
        try:
            proc.terminate()
            await asyncio.wait_for(proc.wait(), timeout=5.0)
        except Exception:
            proc.kill()
    logger.info("Auto-Claude Agent API shutting down")


# Create FastAPI app
app = FastAPI(
    title="Auto-Claude Agent API",
    description="Headless API for the Auto-Claude autonomous coding framework",
    version="1.0.0",
    lifespan=lifespan,
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://agents.madfam.io",
        "http://localhost:3000",
        "http://localhost:3001",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "service": "auto-claude-api",
        "version": "1.0.0",
    }


@app.post("/tasks", response_model=TaskResponse, status_code=status.HTTP_201_CREATED)
async def create_task(
    request: TaskRequest,
    background_tasks: BackgroundTasks,
    claims: dict = Depends(verify_janua_token),
):
    """
    Create a new autonomous coding task.

    The task will be processed asynchronously. Use GET /tasks/{task_id} to check status.
    """
    user_id = get_user_id(claims)
    task_id = str(uuid.uuid4())
    now = datetime.utcnow().isoformat()

    task_info = {
        "id": task_id,
        "status": "pending",
        "description": request.description,
        "project_url": request.project_url,
        "complexity": request.complexity,
        "model": request.model,
        "created_at": now,
        "updated_at": now,
        "user_id": user_id,
        "error": None,
    }
    _TASKS[task_id] = task_info

    # Start task in background
    background_tasks.add_task(run_task_async, task_id, task_info)

    logger.info(f"Created task {task_id} for user {user_id}")
    return TaskResponse(**task_info)


@app.get("/tasks", response_model=TaskListResponse)
async def list_tasks(
    claims: dict = Depends(verify_janua_token),
    limit: int = 50,
    offset: int = 0,
):
    """List all tasks for the authenticated user."""
    user_id = get_user_id(claims)

    # Filter tasks by user
    user_tasks = [
        TaskResponse(**{**task, "progress": get_task_progress(task["id"])})
        for task in _TASKS.values()
        if task["user_id"] == user_id
    ]

    # Sort by created_at descending
    user_tasks.sort(key=lambda t: t.created_at, reverse=True)

    return TaskListResponse(
        tasks=user_tasks[offset : offset + limit],
        total=len(user_tasks),
    )


@app.get("/tasks/{task_id}", response_model=TaskResponse)
async def get_task(
    task_id: str,
    claims: dict = Depends(verify_janua_token),
):
    """Get details for a specific task."""
    user_id = get_user_id(claims)

    task = _TASKS.get(task_id)
    if not task:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Task not found",
        )

    if task["user_id"] != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied",
        )

    return TaskResponse(**{**task, "progress": get_task_progress(task_id)})


@app.get("/tasks/{task_id}/logs")
async def get_task_logs(
    task_id: str,
    claims: dict = Depends(verify_janua_token),
    tail: int = 100,
):
    """Get execution logs for a task."""
    user_id = get_user_id(claims)

    task = _TASKS.get(task_id)
    if not task:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Task not found",
        )

    if task["user_id"] != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied",
        )

    log_file = task.get("log_file")
    if not log_file or not Path(log_file).exists():
        return {"logs": "", "lines": 0}

    try:
        content = Path(log_file).read_text()
        lines = content.split("\n")
        if tail > 0:
            lines = lines[-tail:]
        return {"logs": "\n".join(lines), "lines": len(lines)}
    except Exception as e:
        return {"logs": f"Error reading logs: {e}", "lines": 0}


@app.delete("/tasks/{task_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_task(
    task_id: str,
    claims: dict = Depends(verify_janua_token),
):
    """Cancel and delete a task."""
    user_id = get_user_id(claims)

    task = _TASKS.get(task_id)
    if not task:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Task not found",
        )

    if task["user_id"] != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied",
        )

    # Cancel if running
    if task_id in _TASK_PROCESSES:
        proc = _TASK_PROCESSES[task_id]
        try:
            proc.terminate()
            await asyncio.wait_for(proc.wait(), timeout=5.0)
        except Exception:
            proc.kill()
        del _TASK_PROCESSES[task_id]

    # Remove from registry
    del _TASKS[task_id]

    logger.info(f"Deleted task {task_id}")
    return None


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "api:app",
        host="0.0.0.0",
        port=int(os.environ.get("PORT", "8080")),
        reload=os.environ.get("ENV") != "production",
    )
