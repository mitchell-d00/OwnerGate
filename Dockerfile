# syntax=docker/dockerfile:1
FROM python:3.12-slim
WORKDIR /app
COPY requirements.lock .
RUN --mount=type=secret,id=proxy_ca \
    if [ -f /run/secrets/proxy_ca ]; then export PIP_CERT=/run/secrets/proxy_ca; fi; \
    pip install --no-cache-dir -r requirements.lock
COPY pyproject.toml README.md ./
COPY ownergate ./ownergate
RUN pip install --no-index --no-deps --no-build-isolation . && useradd --uid 10001 --create-home ownergate && mkdir /state && chown ownergate:ownergate /state
USER 10001
ENV OWNERGATE_STATE=/state PYTHONDONTWRITEBYTECODE=1
EXPOSE 8000
CMD ["ownergate", "serve", "--host", "0.0.0.0"]
