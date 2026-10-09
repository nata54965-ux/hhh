#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""AI-разбор находок gitleaks.

Читает JSON-отчёты папки скана, отправляет находки в LLM и пишет
_ai_verdict.html: REAL (боевые секреты) сверху, мусор внизу.

Провайдеры (все OpenAI-совместимые):
  groq       — бесплатный, быстрый (llama-3.3-70b)
  openrouter — бесплатные модели (:free)
  deepseek   — дешёвый (deepseek-chat)
  gemini     — бесплатный free-tier (gemini-3.8-flash)

Ключ: --key <...> | env AI_API_KEY | preferences.json Fyne
(файл ~/.config/fyne/com.ihor.github-gitleaks-scanner/preferences.json,
 ключ ai_key_<провайдер> — туда же его пишет GUI).
"""
import argparse
import glob
import html
import json
import os
import sys
import time

PROVIDERS = {
    # провайдер: (base_url, модель по умолчанию)
    "groq": ("https://api.groq.com/openai/v1", "llama-3.3-70b-versatile"),
    "openrouter": ("https://openrouter.ai/api/v1",
                   "meta-llama/llama-3.3-70b-instruct:free"),
    "deepseek": ("https://api.deepseek.com/v1", "deepseek-chat"),
    "gemini": ("https://generativelanguage.googleapis.com/v1beta/openai",
               "gemini-3.8-flash"),
}

PREFS_PATH = os.path.expanduser(
    "~/.config/fyne/com.ihor.github-gitleaks-scanner/preferences.json")

BATCH = 50          # находок в одном запросе
SECRET_MAX = 120    # обрезка секрета в промпте
MAX_RETRIES = 3

SYSTEM = (
    "Ты — эксперт по безопасности и криптовалютам. Тебе дают находки "
    "gitleaks из открытых GitHub-репозиториев. Для каждой реши:\n"
    "REAL — настоящий рабочий секрет (приватный ключ кошелька, seed/мнемоника, "
    "xprv, живой API-токен с доступом);\n"
    "FAKE — тестовый ключ, пример из документации, вордлист, плейсхолдер, "
    "хеш/сигнатура, очевидный мусор;\n"
    "UNKNOWN — сомнительно, нужна ручная проверка.\n"
    "Отвечай ТОЛЬКО JSON-массивом без пояснений вида "
    '[{"i":1,"v":"REAL","r":"причина до 120 символов, по-русски"}].'
)


def prefs_key(provider: str) -> str:
    """Ключ из preferences.json Fyne (его туда пишет GUI)."""
    try:
        with open(PREFS_PATH, encoding="utf-8") as f:
            data = json.load(f)
        return str(data.get("ai_key_" + provider, "") or "").strip()
    except Exception:
        return ""


def collect_findings(scan_dir: str) -> list[dict]:
    """Все находки из *.json папки скана, без дублей (rule+secret)."""
    out, seen = [], set()
    for path in sorted(glob.glob(os.path.join(scan_dir, "*.json"))):
        try:
            with open(path, encoding="utf-8") as f:
                items = json.load(f)
        except Exception:
            continue
        if not isinstance(items, list):
            continue
        for it in items:
            if not isinstance(it, dict):
                continue
            rule = str(it.get("RuleID") or it.get("Description") or "?")
            secret = str(it.get("Secret") or "").strip()
            if not secret:
                continue
            key = (rule, secret[:200])
            if key in seen:
                continue
            seen.add(key)
            out.append({
                "rule": rule,
                "file": str(it.get("File") or "?"),
                "line": it.get("StartLine") or "?",
                "secret": secret,
                "commit": str(it.get("Commit") or "")[:12],
                "src": os.path.basename(path),
            })
    return out


def provider_request(provider: str, model: str, key: str,
                     user_prompt: str) -> str:
    """Один запрос к LLM (OpenAI-совместимый chat/completions)."""
    import requests
    base, _ = PROVIDERS[provider]
    url = base + "/chat/completions"
    headers = {"Content-Type": "application/json"}
    if provider == "openrouter":
        headers["Authorization"] = "Bearer " + key
        headers["HTTP-Referer"] = "https://github-scanner.local"
    else:
        headers["Authorization"] = "Bearer " + key
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM},
            {"role": "user", "content": user_prompt},
        ],
        "temperature": 0,
    }
    last = ""
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            r = requests.post(url, headers=headers, json=payload, timeout=90)
            if r.status_code == 429 or r.status_code >= 500:
                last = "HTTP %d: %s" % (r.status_code, r.text[:200])
                time.sleep(2 ** attempt)
                continue
            if r.status_code != 200:
                raise RuntimeError("HTTP %d: %s" % (r.status_code, r.text[:300]))
            data = r.json()
            return data["choices"][0]["message"]["content"]
        except RuntimeError:
            raise
        except Exception as e:  # сеть, таймаут
            last = repr(e)
            time.sleep(2 ** attempt)
    raise RuntimeError("провал после %d попыток: %s" % (MAX_RETRIES, last))


def parse_verdicts(text: str) -> list[dict]:
    """Достаёт JSON-массив из ответа (в т.ч. обёрнутого в ```json)."""
    t = text.strip()
    if "```" in t:
        t = t.replace("```json", "").replace("```", "").strip()
    a, b = t.find("["), t.rfind("]")
    if a < 0 or b <= a:
        return []
    try:
        arr = json.loads(t[a:b + 1])
    except Exception:
        return []
    return [v for v in arr if isinstance(v, dict)]


def classify(findings: list[dict], provider: str, model: str,
             key: str, dry: bool) -> dict[int, dict]:
    verdicts: dict[int, dict] = {}
    batches = [findings[i:i + BATCH] for i in range(0, len(findings), BATCH)]
    for n, batch in enumerate(batches, 1):
        lines = []
        for idx, f in enumerate(batch, 1):
            sec = f["secret"]
            if len(sec) > SECRET_MAX:
                sec = sec[:SECRET_MAX] + "…"
            lines.append("%d|%s|%s:%s|%s" %
                         (idx, f["rule"], f["file"], f["line"], sec))
        prompt = ("Классифицируй находки (формат: номер|правило|файл:строка|"
                  "секрет):\n" + "\n".join(lines))
        if dry:
            got = [{"i": i, "v": "UNKNOWN", "r": "dry-run: API не вызывался"}
                   for i in range(1, len(batch) + 1)]
        else:
            raw = provider_request(provider, model, key, prompt)
            got = parse_verdicts(raw)
        for v in got:
            try:
                i = int(v.get("i"))
            except Exception:
                continue
            if 1 <= i <= len(batch):
                verdicts[(n - 1) * BATCH + i - 1] = {
                    "v": str(v.get("v", "UNKNOWN")).upper()[:8],
                    "r": str(v.get("r", ""))[:200],
                }
        print("AI: пакет %d/%d — вердиктов %d" % (n, len(batches), len(got)))
        if not dry and n < len(batches):
            time.sleep(1)
    return verdicts


def write_html(scan_dir: str, findings: list[dict],
               verdicts: dict[int, dict]) -> str:
    order = {"REAL": 0, "UNKNOWN": 1, "FAKE": 2}
    color = {"REAL": "#ff5252", "UNKNOWN": "#ffb300", "FAKE": "#66bb6a"}
    rows, counts = [], {"REAL": 0, "UNKNOWN": 0, "FAKE": 0}
    enriched = []
    for i, f in enumerate(findings):
        v = verdicts.get(i) or {"v": "UNKNOWN", "r": "вердикта нет"}
        v["v"] = v["v"] if v["v"] in counts else "UNKNOWN"
        counts[v["v"]] += 1
        enriched.append((order[v["v"]], i, f, v))
    enriched.sort(key=lambda x: (x[0], x[1]))
    for _, i, f, v in enriched:
        rows.append(
            "<tr><td style='color:%s;font-weight:bold'>%s</td>"
            "<td>%s</td><td style='word-break:break-all'>%s:%s</td>"
            "<td style='word-break:break-all'>%s</td>"
            "<td style='color:#aaa'>%s</td><td>%s</td></tr>" % (
                color[v["v"]], html.escape(v["v"]),
                html.escape(f["rule"]),
                html.escape(f["file"]), f["line"],
                html.escape(f["secret"][:200]),
                html.escape(f["commit"]),
                html.escape(v["r"])))
    page = (
        "<!DOCTYPE html><html><head><meta charset='utf-8'>"
        "<title>AI-вердикт</title><style>"
        "body{background:#111;color:#2ee05a;font-family:monospace;padding:12px}"
        "table{border-collapse:collapse;width:100%%}"
        "td,th{border:1px solid #333;padding:4px;font-size:12px;text-align:left}"
        "th{background:#222;position:sticky;top:0}</style></head><body>"
        "<h1>AI-разбор находок: REAL %d | UNKNOWN %d | FAKE %d (всего %d)</h1>"
        "<table><tr><th>вердикт</th><th>правило</th><th>где</th>"
        "<th>секрет</th><th>коммит</th><th>причина</th></tr>%s</table>"
        "</body></html>") % (
        counts["REAL"], counts["UNKNOWN"], counts["FAKE"], len(findings),
        "".join(rows))
    out = os.path.join(scan_dir, "_ai_verdict.html")
    with open(out, "w", encoding="utf-8") as f:
        f.write(page)
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="AI-разбор находок gitleaks")
    ap.add_argument("--dir", required=True, help="папка скана (reports/scan_*)")
    ap.add_argument("--provider", default="groq",
                    choices=sorted(PROVIDERS), help="провайдер LLM")
    ap.add_argument("--model", default="", help="модель (по умолчанию из провайдера)")
    ap.add_argument("--key", default="", help="API-ключ (или env/preferences)")
    ap.add_argument("--dry-run", action="store_true",
                    help="без запроса к API — проверка пайплайна")
    args = ap.parse_args()

    if not os.path.isdir(args.dir):
        print("[ERROR] нет папки: %s" % args.dir)
        return 2

    findings = collect_findings(args.dir)
    if not findings:
        print("[ERROR] в %s нет находок (JSON пуст)" % args.dir)
        return 1
    print("AI: находок %d, провайдер %s" % (len(findings), args.provider))

    key = (args.key or os.environ.get("AI_API_KEY")
           or prefs_key(args.provider))
    if not key and not args.dry_run:
        print("[ERROR] нет API-ключа (ключ AI/провайдер не задан). "
              "Введи ключ в поле AI на вкладке сканера.")
        return 1

    model = args.model or PROVIDERS[args.provider][1]
    try:
        verdicts = classify(findings, args.provider, model, key,
                            args.dry_run)
    except Exception as e:
        print("[ERROR] LLM: %s" % e)
        return 1

    out = write_html(args.dir, findings, verdicts)
    cnt = {"REAL": 0, "UNKNOWN": 0, "FAKE": 0}
    for v in verdicts.values():
        if v["v"] in cnt:
            cnt[v["v"]] += 1
    print("AI: REAL=%d UNKNOWN=%d FAKE=%d" %
          (cnt["REAL"], cnt["UNKNOWN"], cnt["FAKE"]))
    print("AI: отчёт %s" % out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
