FROM python:3.13-slim
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

WORKDIR /app

# Copy project files
COPY graphql_authz_proxy/ ./graphql_authz_proxy/
COPY README.md ./
COPY pyproject.toml ./

# Install dependencies
RUN uv sync && uv pip install .

# Expose Flask port
EXPOSE 8080

# Set environment variables for Flask
ENV FLASK_APP=graphql_authz_proxy/main.py
ENV FLASK_RUN_PORT=8080
ENV FLASK_RUN_HOST=0.0.0.0

ENTRYPOINT ["uv", "run", "gqlproxy"]