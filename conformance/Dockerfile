FROM python:3.12-slim@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea

# uv (pinned) for dependency installation — copied from the official image.
COPY --from=ghcr.io/astral-sh/uv:0.9.5@sha256:f459f6f73a8c4ef5d69f4e6fbbdb8af751d6fa40ec34b39a1ab469acd6e289b7 /uv /uvx /bin/

WORKDIR /app

# Install harness dependencies
COPY conformance/requirements.txt requirements.txt
RUN uv pip install --system --no-cache -r requirements.txt

# Install py-identity-model from source (relocated under /py in CONS-2.1; build
# context is the repo root, so the package now lives at py/).
COPY py/pyproject.toml py/README.md ./
COPY py/src/ src/
RUN uv pip install --system --no-cache .

# Copy harness app
COPY conformance/app.py .

EXPOSE 8888

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8888"]
