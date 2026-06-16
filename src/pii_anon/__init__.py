"""
pii_anon — 用 Presidio 对文本做 PII 脱敏。

分工:
  - 检测 (PII 在哪): 调用后台运行的 GLiNER2 服务 `POST /pii/extract`,
    本项目不加载任何模型。
  - 脱敏 (怎么处理): 用 presidio-anonymizer 的算子
    (replace / redact / mask / hash / encrypt)。

环境变量:
  DETECTOR_URL   GLiNER2 检测端点, 默认 http://127.0.0.1:8000/pii/extract
  PII_ANON_KEY   encrypt 算子用的密钥 (16/24/32 字节)
"""
import os
import requests
from presidio_anonymizer import AnonymizerEngine, DeanonymizeEngine
from presidio_anonymizer.entities import RecognizerResult, OperatorConfig

DETECTOR_URL = os.environ.get("DETECTOR_URL", "http://127.0.0.1:8000/pii/extract")
OPERATORS = ("replace", "redact", "mask", "hash", "encrypt")

_anon = AnonymizerEngine()
_deanon = DeanonymizeEngine()


class DetectorError(RuntimeError):
    """后台 GLiNER2 检测服务不可用。"""


def detect(text, threshold=0.5, labels=None, detector_url=None):
    """调远程 GLiNER2 服务, 返回 (presidio RecognizerResult 列表, 原始 entities dict)。"""
    url = detector_url or DETECTOR_URL
    payload = {"text": text, "threshold": threshold}
    if labels:
        payload["labels"] = labels
    try:
        r = requests.post(url, json=payload, timeout=30)
        r.raise_for_status()
    except requests.RequestException as e:
        raise DetectorError(f"检测服务不可用 ({url}): {e}") from e
    entities = r.json().get("entities", {})
    results = [
        RecognizerResult(entity_type=etype.upper(), start=it["start"],
                         end=it["end"], score=float(it.get("confidence", 1.0)))
        for etype, items in entities.items() for it in items
    ]
    return results, entities


def _build_operators(operator, results, key=None):
    op = operator.lower()
    if op == "replace":                       # 每种类型替换成 [TYPE]
        types = {r.entity_type for r in results}
        cfgs = {t: OperatorConfig("replace", {"new_value": f"[{t}]"}) for t in types}
        return cfgs or {"DEFAULT": OperatorConfig("replace", {})}
    if op == "redact":                        # 直接删除
        return {"DEFAULT": OperatorConfig("redact", {})}
    if op == "hash":                          # 一致性哈希 (同值同结果, 不可逆)
        return {"DEFAULT": OperatorConfig("hash", {"hash_type": "sha256"})}
    if op == "mask":                          # 保留末 4 位, 其余打码
        keep = 4
        return {"DEFAULT": OperatorConfig("custom", {"lambda": lambda x:
                ("*" * (len(x) - keep) + x[-keep:]) if len(x) > keep else "*" * len(x)})}
    if op == "encrypt":                       # AES 加密, 可逆 (用 deanonymize 还原)
        k = key or os.environ.get("PII_ANON_KEY")
        if not k:
            raise ValueError("encrypt 需要密钥: 设环境变量 PII_ANON_KEY 或传 key (16/24/32 字节)")
        return {"DEFAULT": OperatorConfig("encrypt", {"key": k})}
    raise ValueError(f"未知 operator: {operator} (可选: {', '.join(OPERATORS)})")


def anonymize(text, operator="replace", threshold=0.5, labels=None,
              detector_url=None, key=None):
    """检测 + 脱敏, 返回脱敏后的字符串。"""
    results, _ = detect(text, threshold, labels, detector_url)
    if not results:
        return text
    out = _anon.anonymize(text=text, analyzer_results=results,
                          operators=_build_operators(operator, results, key))
    return out.text
