# The identity plane's API. Non-root; config baked in; secrets (keys, SCIM tokens) come from the environment.
FROM python:3.13-slim AS build
WORKDIR /src
COPY pyproject.toml ./
COPY src ./src
RUN pip install --no-cache-dir --prefix=/install .

FROM python:3.13-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 FIP_ROOT=/app
RUN useradd --create-home --uid 10001 fip
WORKDIR /app
COPY --from=build /install /usr/local
COPY config ./config
USER fip
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz')"
CMD ["python", "-m", "fip.cli", "serve", "--port", "8000"]
