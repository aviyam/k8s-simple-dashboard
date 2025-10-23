FROM python:3.13-alpine
RUN pip install uv
WORKDIR /app

ENV UV_COMPILE_BYTECODE=1
ENV UV_LINK_MODE=copy
ENV UV_TOOL_BIN_DIR=/usr/local/bin

#RUN --mount=type=cache,target=/root/.cache/uv \
#    --mount=type=bind,source=uv.lock,target=uv.lock \
#    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
#    uv sync --locked --no-install-project --no-dev

COPY pyproject.toml .
COPY uv.lock .
COPY run.py .
COPY gunicorn_config.py .
COPY app app

RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-dev

ENV PATH="/app/.venv/bin:$PATH"
EXPOSE 8080

ENTRYPOINT []
CMD ["gunicorn", "--config", "gunicorn_config.py", "run:app"]