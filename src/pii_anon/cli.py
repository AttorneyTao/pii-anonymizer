"""命令行入口: pii-anon"""
import argparse
import json
import sys

from . import anonymize, detect, DetectorError, DETECTOR_URL, OPERATORS


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
        description="PII 脱敏: 检测调后台 GLiNER2 服务, 脱敏用 Presidio。子命令 serve 启动 HTTP 服务。")
    ap.add_argument("text", nargs="*", help="待脱敏文本; 省略则从 stdin 读取")
    ap.add_argument("-o", "--operator", default="replace", choices=OPERATORS,
                    help="脱敏算子 (默认 replace)")
    ap.add_argument("-t", "--threshold", type=float, default=0.5)
    ap.add_argument("--labels", help="逗号分隔的标签子集, 限定检测类型")
    ap.add_argument("--key", help="encrypt 算子的密钥 (16/24/32 字节)")
    ap.add_argument("--detector-url", help=f"检测端点 (默认 {DETECTOR_URL})")
    ap.add_argument("--detect", action="store_true", help="只输出检测到的实体(JSON), 不脱敏")
    args = ap.parse_args()

    text = " ".join(args.text) if args.text else sys.stdin.read().strip()
    labels = args.labels.split(",") if args.labels else None
    try:
        if args.detect:
            _, ents = detect(text, args.threshold, labels, args.detector_url)
            print(json.dumps(ents, ensure_ascii=False, indent=2))
        else:
            print(anonymize(text, args.operator, args.threshold, labels,
                            args.detector_url, args.key))
    except DetectorError as e:
        print(f"错误: {e}\n提示: 确认脱敏服务在跑 (cd ~/local-ai-service && localai start)",
              file=sys.stderr)
        sys.exit(2)
    except ValueError as e:
        print(f"错误: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
