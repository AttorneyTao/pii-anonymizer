"""
pii_anon — 用 Presidio 对文本做 PII 脱敏，检测可融合两个来源。

检测来源:
  - gliner   : 后台运行的 GLiNER2 服务 (POST /pii/extract), 多语言、强 NER。本项目不加载该模型。
  - presidio : presidio-analyzer 本地检测 (spaCy + 正则 + 校验和)。
               **仅容器内可用** (宿主 Python 3.14 装不了 presidio-analyzer), 懒加载。

模式 (mode):
  auto     (默认) GLiNER2 可达 -> 与 presidio 融合; 不可达 -> presidio 兜底
  gliner   只用 GLiNER2 (有 AI)
  presidio 只用 presidio-analyzer (无 AI)
  fused    两者都用并融合去重

脱敏: presidio-anonymizer 算子 (replace / redact / mask / hash / encrypt)。

环境变量:
  DETECTOR_URL          GLiNER2 端点, 默认 http://127.0.0.1:8000/pii/extract
  PRESIDIO_SPACY_MODEL  presidio 用的 spaCy 模型, 默认 en_core_web_sm
  PII_ANON_KEY          encrypt 算子密钥 (16/24/32 字节)
"""
import os
import requests
from presidio_anonymizer import AnonymizerEngine, DeanonymizeEngine
from presidio_anonymizer.entities import RecognizerResult, OperatorConfig

DETECTOR_URL = os.environ.get("DETECTOR_URL", "http://127.0.0.1:8000/pii/extract")
OPERATORS = ("replace", "redact", "mask", "hash", "encrypt")
MODES = ("auto", "gliner", "presidio", "fused")

_anon = AnonymizerEngine()
_deanon = DeanonymizeEngine()
_analyzer = None

# 统一不同来源的实体类型名, 便于融合与显示
_NORM = {
    "EMAIL_ADDRESS": "EMAIL", "CREDIT_CARD": "CREDIT_CARD_NUMBER",
    "US_SSN": "SOCIAL_SECURITY_NUMBER", "US_DRIVER_LICENSE": "DRIVER_LICENSE_NUMBER",
    "US_PASSPORT": "PASSPORT_NUMBER", "DATE_TIME": "DATE",
}


class DetectorError(RuntimeError):
    """GLiNER2 检测服务不可用，且没有可用的兜底检测。"""


class AnalyzerUnavailable(RuntimeError):
    """presidio-analyzer 未安装（仅容器内可用）。"""


def _norm(t):
    return _NORM.get(t, t)


# ----------------------------- 来源 1: GLiNER2 (远程) -----------------------------
def detect_gliner(text, threshold=0.5, labels=None, detector_url=None):
    """调远程 GLiNER2 服务, 返回 RecognizerResult 列表 (打上 source=gliner)。"""
    url = detector_url or DETECTOR_URL
    payload = {"text": text, "threshold": threshold}
    if labels:
        payload["labels"] = labels
    try:
        r = requests.post(url, json=payload, timeout=30)
        r.raise_for_status()
    except requests.RequestException as e:
        raise DetectorError(f"检测服务不可用 ({url}): {e}") from e
    out = []
    for etype, items in r.json().get("entities", {}).items():
        for it in items:
            rr = RecognizerResult(entity_type=_norm(etype.upper()), start=it["start"],
                                  end=it["end"], score=float(it.get("confidence", 1.0)))
            rr.source = "gliner"
            out.append(rr)
    return out


# 兼容旧 API: 返回 (results, entities dict)
def detect(text, threshold=0.5, labels=None, detector_url=None):
    results = detect_gliner(text, threshold, labels, detector_url)
    entities = {}
    for r in results:
        entities.setdefault(r.entity_type.lower(), []).append(
            {"text": text[r.start:r.end], "confidence": r.score, "start": r.start, "end": r.end})
    return results, entities


# --------------------------- 来源 2: presidio-analyzer (本地) ---------------------------
def analyzer_available():
    try:
        import presidio_analyzer  # noqa: F401
        return True
    except ImportError:
        return False


def _get_analyzer():
    global _analyzer
    if _analyzer is None:
        try:
            from presidio_analyzer import AnalyzerEngine
            from presidio_analyzer.nlp_engine import NlpEngineProvider
        except ImportError as e:
            raise AnalyzerUnavailable(
                "presidio-analyzer 未安装 (仅容器内可用; 宿主 Python 3.14 装不了)") from e
        model = os.environ.get("PRESIDIO_SPACY_MODEL", "en_core_web_sm")
        nlp = NlpEngineProvider(nlp_configuration={
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": "en", "model_name": model}],
        }).create_engine()
        _analyzer = AnalyzerEngine(nlp_engine=nlp, supported_languages=["en"])
    return _analyzer


def detect_presidio(text, threshold=0.5):
    """presidio-analyzer 本地检测 (无需 AI), 返回 RecognizerResult 列表 (source=presidio)。"""
    eng = _get_analyzer()
    out = []
    for r in eng.analyze(text=text, language="en", score_threshold=threshold):
        r.entity_type = _norm(r.entity_type)
        r.source = "presidio"
        out.append(r)
    return out


# ------------------------------- 融合 + 模式选择 -------------------------------
def _merge(spans):
    """跨来源合并: 按分数从高到低贪心保留, 丢弃与已保留区间重叠的低分项。"""
    kept = []
    for r in sorted(spans, key=lambda x: -x.score):
        if all(r.end <= o.start or r.start >= o.end for o in kept):
            kept.append(r)
    return sorted(kept, key=lambda x: x.start)


def detect_results(text, threshold=0.5, labels=None, detector_url=None, mode="auto"):
    """按模式选择/融合来源, 返回 (RecognizerResult 列表, 实际使用的来源列表)。"""
    mode = (mode or "auto").lower()
    if mode not in MODES:
        raise ValueError(f"未知 mode: {mode} (可选: {', '.join(MODES)})")

    if mode == "presidio":
        return detect_presidio(text, threshold), ["presidio"]

    # 需要 GLiNER2 的模式: 先试远程
    g = None
    try:
        g = detect_gliner(text, threshold, labels, detector_url)
    except DetectorError:
        if mode in ("gliner", "fused"):
            raise
        g = None  # auto: 降级

    if mode == "gliner":
        return g, ["gliner"]
    if mode == "fused":
        return _merge(g + detect_presidio(text, threshold)), ["gliner", "presidio"]

    # auto: 有 AI 且 analyzer 可用 -> 融合; 有 AI 无 analyzer -> 只 gliner; 无 AI -> presidio 兜底
    if g is not None:
        if analyzer_available():
            return _merge(g + detect_presidio(text, threshold)), ["gliner", "presidio"]
        return g, ["gliner"]
    if analyzer_available():
        return detect_presidio(text, threshold), ["presidio"]
    raise DetectorError("GLiNER2 不可用, 且 presidio-analyzer 也未安装 (仅容器内可用)")


def serialize(spans, text):
    return [{"type": r.entity_type, "text": text[r.start:r.end], "start": r.start,
             "end": r.end, "score": round(float(r.score), 4),
             "source": getattr(r, "source", None)} for r in spans]


# ------------------------------- 脱敏 -------------------------------
def _build_operators(operator, results, key=None):
    op = operator.lower()
    if op == "replace":
        types = {r.entity_type for r in results}
        cfgs = {t: OperatorConfig("replace", {"new_value": f"[{t}]"}) for t in types}
        return cfgs or {"DEFAULT": OperatorConfig("replace", {})}
    if op == "redact":
        return {"DEFAULT": OperatorConfig("redact", {})}
    if op == "hash":
        return {"DEFAULT": OperatorConfig("hash", {"hash_type": "sha256"})}
    if op == "mask":
        keep = 4
        return {"DEFAULT": OperatorConfig("custom", {"lambda": lambda x:
                ("*" * (len(x) - keep) + x[-keep:]) if len(x) > keep else "*" * len(x)})}
    if op == "encrypt":
        k = key or os.environ.get("PII_ANON_KEY")
        if not k:
            raise ValueError("encrypt 需要密钥: 设环境变量 PII_ANON_KEY 或传 key (16/24/32 字节)")
        return {"DEFAULT": OperatorConfig("encrypt", {"key": k})}
    raise ValueError(f"未知 operator: {operator} (可选: {', '.join(OPERATORS)})")


def anonymize(text, operator="replace", threshold=0.5, labels=None,
              detector_url=None, key=None, mode="auto"):
    """检测(按 mode 融合) + 脱敏, 返回脱敏后的字符串。"""
    spans, _ = detect_results(text, threshold, labels, detector_url, mode)
    if not spans:
        return text
    out = _anon.anonymize(text=text, analyzer_results=spans,
                          operators=_build_operators(operator, spans, key))
    return out.text
