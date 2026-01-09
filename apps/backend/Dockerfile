# Auto-Claude Agent API Dockerfile
# Python 3.12 with Claude Agent SDK and FastAPI
#
# Build: docker build -t auto-claude-api .
# Run:   docker run -p 8080:8080 -e CLAUDE_CODE_OAUTH_TOKEN=... auto-claude-api

FROM python:3.12-slim

# Install system dependencies
# - git: Required for Auto-Claude git operations
# - nodejs & npm: Required for Claude Agent SDK (npx commands for MCP servers)
# - build-essential: Required for compiling native Python extensions
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    ca-certificates \
    gnupg \
    build-essential \
    && mkdir -p /etc/apt/keyrings \
    && curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg \
    && echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_20.x nodistro main" > /etc/apt/sources.list.d/nodesource.list \
    && apt-get update \
    && apt-get install -y nodejs \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install Claude Code CLI (required by Claude Agent SDK)
RUN npm install -g @anthropic-ai/claude-code

# Create app user for security
RUN useradd -m -s /bin/bash appuser

# Set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create workspace directory for task execution
RUN mkdir -p /tmp/auto-claude && chown -R appuser:appuser /tmp/auto-claude

# Create .auto-claude directory
RUN mkdir -p /app/.auto-claude && chown -R appuser:appuser /app/.auto-claude

# Set ownership
RUN chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Configure git for the app user
RUN git config --global user.email "auto-claude@madfam.io" \
    && git config --global user.name "Auto-Claude Agent" \
    && git config --global init.defaultBranch main

# Environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV PORT=8080
ENV WORKSPACE_BASE_DIR=/tmp/auto-claude

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Run the API
CMD ["python", "-m", "uvicorn", "api:app", "--host", "0.0.0.0", "--port", "8080"]
