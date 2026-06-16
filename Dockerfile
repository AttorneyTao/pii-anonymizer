# pii-anonymizer 容器: 纯 CPU(presidio+requests), 无 GPU 需求。
# 检测仍调宿主机原生的 GLiNER2 服务 (host.docker.internal:8000)。
FROM ghcr.io/astral-sh/uv:python3.13-bookworm-slim

WORKDIR /app

# 先拷依赖清单和源码, 用 uv.lock 做可复现安装 (base: presidio-anonymizer + requests)
COPY pyproject.toml uv.lock README.md ./
COPY src ./src
RUN uv sync --frozen --no-dev

# 容器专属: 装 presidio-analyzer + spaCy + 英文模型 (本地检测能力)。
# 不进 uv.lock —— 宿主 Python 3.14 装不了它, 仅在此 Linux 容器(3.13)安装。
# 直接装模型 wheel (而非 spacy download CLI), 更可复现; 显式补 click (spacy 导入需要)。
RUN uv pip install --python /app/.venv/bin/python \
      "presidio-analyzer>=2.2" "spacy>=3.8,<3.9" "click>=8" \
      "en_core_web_sm @ https://github.com/explosion/spacy-models/releases/download/en_core_web_sm-3.8.0/en_core_web_sm-3.8.0-py3-none-any.whl"

# 容器内默认调宿主机的检测服务 (运行时需 --add-host=host.docker.internal:host-gateway)
ENV DETECTOR_URL=http://host.docker.internal:8000/pii/extract
ENV PRESIDIO_SPACY_MODEL=en_core_web_sm

EXPOSE 8100
CMD ["/app/.venv/bin/pii-anon", "serve", "--host", "0.0.0.0", "--port", "8100"]
