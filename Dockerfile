FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Install runtime deps directly (no editable install — code is copied below
# and run from /app, so the package itself doesn't need to be installed).
# Keep this list in sync with pyproject.toml.
RUN pip install \
    "anthropic>=0.42.0" \
    "datadog-api-client>=2.20.0" \
    "httpx>=0.27.0" \
    "pydantic>=2.5.0" \
    "rich>=13.7.0" \
    "tenacity>=8.2.0" \
    "structlog>=24.1.0" \
    "python-dotenv>=1.0.0" \
    "slack-bolt>=1.18.0" \
    "slack-sdk>=3.27.0" \
    "aiohttp>=3.9.0"

COPY config ./config
COPY src ./src
COPY slack_bot.py main.py ./

# Cloud Run injects PORT; SlackConfig prefers PORT over SLACK_BOT_PORT.
EXPOSE 8080

CMD ["python", "slack_bot.py"]
