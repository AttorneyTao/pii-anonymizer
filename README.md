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

## 配置（环境变量）

| 变量 | 默认 | 说明 |
|---|---|---|
| `DETECTOR_URL` | `http://127.0.0.1:8000/pii/extract` | 后台 GLiNER2 检测端点 |
| `PII_ANON_KEY` | （无） | `encrypt` 算子密钥，16/24/32 字节 |

## 说明

- 检测能力 = GLiNER2（多语言、模式化 PII 准；中文人名/地址不可靠）。本项目只换脱敏方式，不改检测。
- 依赖 `presidio-anonymizer`（纯脱敏，无 spaCy，支持 Python 3.14）。
  `presidio-analyzer`（正则+校验那套）不支持 3.14，本项目刻意不用它，检测统一交给 GLiNER2 服务。
