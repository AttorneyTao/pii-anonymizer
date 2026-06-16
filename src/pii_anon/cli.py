"""命令行入口: pii-anon"""
import argparse
import json
import sys

from . import (anonymize, detect_results, serialize, DetectorError,
               AnalyzerUnavailable, DETECTOR_URL, OPERATORS, MODES)


def main():
    # 子命令 serve 单独处理, 避免与位置参数 text 冲突
    if len(sys.argv) > 1 and sys.argv[1] == "serve":
        sp = argparse.ArgumentParser(prog="pii-anon serve", description="启动常驻 HTTP 脱敏服务")
        sp.add_argument("--host", default="127.0.0.1")
        sp.add_argument("--port", type=int, default=8100)
        a = sp.parse_args(sys.argv[2:])
        from .server import run
        run(a.host, a.port)
        return

    ap = argparse.ArgumentParser(
        prog="pii-anon",
        description="PII 脱敏: 检测可融合 GLiNER2(远程) 与 presidio-analyzer(本地, 仅容器)。"
                    "子命令 serve 启动 HTTP 服务。")
    ap.add_argument("text", nargs="*", help="待脱敏文本; 省略则从 stdin 读取")
    ap.add_argument("-o", "--operator", default="replace", choices=OPERATORS,
                    help="脱敏算子 (默认 replace)")
    ap.add_argument("-m", "--mode", default="auto", choices=MODES,
                    help="检测来源: auto(默认)/gliner/presidio/fused")
    ap.add_argument("-t", "--threshold", type=float, default=0.5)
    ap.add_argument("--labels", help="逗号分隔的标签子集 (仅对 GLiNER2 生效)")
    ap.add_argument("--key", help="encrypt 算子的密钥 (16/24/32 字节)")
    ap.add_argument("--detector-url", help=f"检测端点 (默认 {DETECTOR_URL})")
    ap.add_argument("--detect", action="store_true",
                    help="只输出检测结果(JSON, 含来源), 不脱敏")
    args = ap.parse_args()

    text = " ".join(args.text) if args.text else sys.stdin.read().strip()
    labels = args.labels.split(",") if args.labels else None
    try:
        if args.detect:
            spans, sources = detect_results(text, args.threshold, labels,
                                            args.detector_url, args.mode)
            print(json.dumps({"sources": sources, "entities": serialize(spans, text)},
                             ensure_ascii=False, indent=2))
        else:
            print(anonymize(text, args.operator, args.threshold, labels,
                            args.detector_url, args.key, args.mode))
    except DetectorError as e:
        print(f"错误: {e}\n提示: 起后台服务 (cd ~/local-ai-service && localai start), "
              f"或用 -m presidio (需容器内的 presidio-analyzer)", file=sys.stderr)
        sys.exit(2)
    except AnalyzerUnavailable as e:
        print(f"错误: {e}\n提示: presidio/fused 模式请在容器内运行", file=sys.stderr)
        sys.exit(3)
    except ValueError as e:
        print(f"错误: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
