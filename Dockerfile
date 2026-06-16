# pii-anonymizer 容器: 纯 CPU(presidio+requests), 无 GPU 需求。
# 检测仍调宿主机原生的 GLiNER2 服务 (host.docker.internal:8000)。
FROM ghcr.io/astral-sh/uv:python3.13-bookworm-slim

WORKDIR /app

# 先拷依赖清单和源码, 用 uv.lock 做可复现安装
COPY pyproject.toml uv.lock README.md ./
COPY src ./src
RUN uv sync --frozen --no-dev

# 容器内默认调宿主机的检测服务 (运行时需 --add-host=host.docker.internal:host-gateway)
ENV DETECTOR_URL=http://host.docker.internal:8000/pii/extract

EXPOSE 8100
CMD ["/app/.venv/bin/pii-anon", "serve", "--host", "0.0.0.0", "--port", "8100"]
