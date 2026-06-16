# pii-anonymizer

用 **Presidio** 对文本做 PII 脱敏；**检测交给后台运行的 GLiNER2 服务**（`local-ai-service` 的
`POST /pii/extract`），本项目自己不加载任何模型，只做「调用 + 脱敏」。

```
文本 ──> [本项目] ──HTTP──> GLiNER2 服务 (:8000/pii/extract)  返回 PII 位置
                │
                └──> Presidio Anonymizer 算子 (replace/redact/mask/hash/encrypt) ──> 脱敏结果
```

与 `local-ai-service` **完全解耦**：独立目录、独立 uv 环境、独立 git 仓库。
后台服务地址变了，改环境变量 `DETECTOR_URL` 即可。

## 安装

```bash
cd ~/pii-anonymizer && uv sync     # 装 presidio-anonymizer + requests, 并安装 pii-anon 命令
```

前提：后台 GLiNER2 服务在跑（`cd ~/local-ai-service && localai start`）。

## 三种用法

**1) CLI**
```bash
uv run pii-anon "Email john@acme.com, card 4111 1111 1111 1111"            # 默认 replace
uv run pii-anon "card 4111 1111 1111 1111" -o mask                         # 保留末4位
uv run pii-anon "email john@acme.com" -o hash                              # 一致性哈希
uv run pii-anon "..." -o encrypt --key 0123456789abcdef0123456789abcdef    # 可逆加密
uv run pii-anon "..." --detect                                            # 只看检测结果(JSON)
echo "long text..." | uv run pii-anon -o redact                           # 从 stdin
```

**2) 库**
```python
from pii_anon import anonymize, detect
anonymize("Email john@acme.com", operator="mask")     # -> "Email *************.com" 等
results, entities = detect("call +1 415 555 0199")    # 原始检测结果
```

**3) HTTP 服务**
```bash
uv run pii-anon serve --port 8100        # 常驻
curl -s -X POST http://127.0.0.1:8100/anonymize \
  -H 'Content-Type: application/json' \
  -d '{"text":"card 4111 1111 1111 1111","operator":"mask"}'
# -> {"result":"card *************1111","operator":"mask"}
```

## 脱敏算子

| operator | 效果 | 可逆 |
|---|---|---|
| `replace`（默认） | PII → `[TYPE]` | 否 |
| `redact` | 直接删除 | 否 |
| `mask` | 保留末 4 位，其余打码 | 否 |
| `hash` | SHA-256，同值同结果（一致性假名化） | 否 |
| `encrypt` | AES 加密，需密钥 | **是**（用 Presidio DeanonymizeEngine 还原） |

## 检测模式（`-m` / `mode`）

检测有两个来源，可单用或融合：

- **gliner**：后台 GLiNER2 服务（多语言、强 NER）。
- **presidio**：presidio-analyzer 本地检测（spaCy + 正则 + Luhn/IBAN 等校验）。**仅容器内可用**
  （宿主 Python 3.14 装不了 presidio-analyzer，代码懒加载，宿主缺它不影响其它模式）。

| mode | 行为 | 适用 |
|---|---|---|
| `auto`（默认） | GLiNER2 可达 → 与 presidio **融合去重**；不可达 → presidio **兜底** | 通用，自动降级 |
| `gliner` | 只用 GLiNER2 | 有 AI，只要多语言 NER |
| `presidio` | 只用 presidio-analyzer（**无 AI 也能跑**） | 后台服务挂了 / 纯本地 |
| `fused` | 两者都跑，合并去重 | 要最高召回 |

融合规则：两来源的 span 按置信度从高到低贪心保留，丢弃重叠的低分项；实体类型名做统一归一。
检测结果可用 `--detect` 查看，每条带 `source`（gliner / presidio）。

```bash
pii-anon "..." -m presidio        # 无 AI, 纯 presidio 检测
pii-anon "..." -m fused --detect  # 看融合后每条来自哪个来源
```

## 配置（环境变量）

| 变量 | 默认 | 说明 |
|---|---|---|
| `DETECTOR_URL` | `http://127.0.0.1:8000/pii/extract` | 后台 GLiNER2 检测端点 |
| `PRESIDIO_SPACY_MODEL` | `en_core_web_sm` | presidio 用的 spaCy 模型（容器内） |
| `PII_ANON_KEY` | （无） | `encrypt` 算子密钥，16/24/32 字节 |

## Docker 运行（Colima）

本项目纯 CPU，适合容器化。**检测仍调宿主机原生的 GLiNER2 服务**（容器拿不到 Mac 的
Metal/MLX，所以 `local-ai-service` 保持本机原生不动）。

前提：① Colima 已启动 `colima start`；② 宿主 `local-ai-service` 在跑且绑 `0.0.0.0`
（`cd ~/local-ai-service && localai start`，它默认就绑 0.0.0.0）。

```bash
cd ~/pii-anonymizer
docker build -t pii-anonymizer:latest .

docker run -d -p 8100:8100 \
  --add-host=host.docker.internal:host-gateway \
  --name pii-anonymizer --restart unless-stopped \
  pii-anonymizer:latest
```

关键：`--add-host=host.docker.internal:host-gateway` 让容器能回连宿主机的 `:8000` 检测服务。
默认 `DETECTOR_URL=http://host.docker.internal:8000/pii/extract`（已写进镜像）。

```bash
# 容器内的 HTTP 服务
curl -s -X POST http://127.0.0.1:8100/anonymize \
  -H 'Content-Type: application/json' \
  -d '{"text":"card 4111 1111 1111 1111","operator":"mask"}'

# 一次性 CLI 也可走容器
docker exec pii-anonymizer /app/.venv/bin/pii-anon "email john@x.com" -o hash

# 运维
docker logs -f pii-anonymizer
docker stop/start/rm -f pii-anonymizer
```

> CLI 和库仍可在宿主机原生用（`pii-anon ...` / `from pii_anon import ...`）；容器主要承载常驻 HTTP 服务。

## 说明

- 检测能力 = GLiNER2（多语言、模式化 PII 准；中文人名/地址不可靠）+ 可选 presidio-analyzer
  （英文、正则+校验，结构化 PII 强）。两者可融合（见「检测模式」）。
- 依赖分两层：`presidio-anonymizer`（纯脱敏，无 spaCy，**支持 Python 3.14**，宿主/容器都装）；
  `presidio-analyzer`（spaCy NER + 正则，**不支持 3.14**）**只在容器内装**，代码懒加载，
  所以宿主原生 `pii-anon` 仍可用（只是没有 presidio/fused 模式）。
- presidio 本地检测目前配英文 spaCy 模型（`en_core_web_sm`）；非英文 NER 仍以 GLiNER2 为主。
