#!/usr/bin/env python3
"""Кнопки для проверки ключей: hex / WIF / мнемоника / XPRV / авто.

Вкладки-кнопки вверху, поле ввода, вывод внизу.
Дополнительно:
  [ПРОВЕРИТЬ ОТЧЁТЫ] — вытащить все ключи из reports/*/*.json и проверить
  [БАЛАНС И TX]      — для последних полученных адресов сходить по RPC
"""
from __future__ import annotations

import glob
import os
import re
import sys
import threading
import tkinter as tk
from tkinter import messagebox, ttk

import keytools

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

# адреса, полученные при проверке (для кнопки баланса)
_last_addrs: list[tuple[str, str]] = []  # (coin, addr)


def _fmt(res: list[dict]) -> str:
    lines = []
    for r in res:
        if "ok" in r:
            lines.append(("  OK   " if r["ok"] else "  FAIL ") + r["reason"])
        else:
            extra = ("  [%s]" % r["extra"]) if r.get("extra") else ""
            lines.append("  %-5s %-24s %s%s" % (
                r.get("coin", "?"), r.get("fmt", ""), r.get("addr", ""), extra))
    return "\n".join(lines)


def check_text(text: str, kind: str = "auto") -> str:
    """Проверка произвольного текста: ищем ключи внутри строки/абзаца."""
    out = []
    global _last_addrs
    found_addrs: list[tuple[str, str]] = []
    # режем на кандидатов: строки + известные паттерны внутри
    chunks = [c for c in text.splitlines() if c.strip()]
    if kind == "auto":
        pats = [
            re.compile(r"(0x)?[0-9a-fA-F]{64}"),
            re.compile(r"\b[5KL9][1-9A-HJ-NP-Za-km-z]{50,51}\b"),
            re.compile(r"\b[xyz]prv[1-9A-HJ-NP-Za-km-z]{100,}\b"),
        ]
        seen = set()
        for c in chunks:
            cands = []
            for p in pats:
                cands += p.findall(c) if p.groups else []
            # findall с группой возвращает группы — берём через finditer
            cands = []
            for p in pats:
                for m in p.finditer(c):
                    cands.append(m.group(0))
            words = c.split()
            if len(words) in (12, 15, 18, 21, 24) and \
                    all(w in keytools.WORDLIST for w in words):
                cands.append(c.strip())
            for cand in cands:
                if cand in seen:
                    continue
                seen.add(cand)
                k, res = keytools.check_any(cand)
                if k == "unknown" and not any("ok" in r and r["ok"] for r in res):
                    continue
                out.append("→ %s\n%s" % (cand[:80], _fmt(res)))
                for r in res:
                    if "addr" in r and r.get("ok") is None:
                        found_addrs.append((r.get("coin", "?"), r["addr"]))
    else:
        k, res = keytools.check_any(text.strip())
        out.append("тип: %s\n%s" % (k, _fmt(res)))
        for r in res:
            if "addr" in r:
                found_addrs.append((r.get("coin", "?"), r["addr"]))
    if not out:
        out.append("  ничего не найдено (ожидается hex64 / WIF / мнемоника / xprv)")
    _last_addrs = found_addrs
    return "\n".join(out)


def check_reports() -> str:
    """Все ключи из отчётов сканера + eth_candidates.txt."""
    found: dict[str, set[str]] = {}

    def add(val: str, src: str):
        found.setdefault(val, set()).add(src)

    for path in sorted(glob.glob(os.path.join(HERE, "reports", "*", "*.json"))):
        try:
            import json
            items = json.load(open(path, encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(items, list):
            continue
        scan = os.path.basename(os.path.dirname(path))
        for it in items:
            s = (it.get("Secret") or "").strip()
            if re.fullmatch(r"[0-9a-fA-F]{64}", s) or \
                    re.fullmatch(r"[5KL9][1-9A-HJ-NP-Za-km-z]{50,51}", s) or \
                    re.fullmatch(r"[xyz]prv[1-9A-HJ-NP-Za-km-z]{100,}", s):
                add(s, "%s/%s" % (scan, it.get("RuleID")))
            elif it.get("RuleID") == "bip39-mnemonic":
                words = s.split()
                if len(words) in (12, 15, 18, 21, 24) and \
                        all(w.lower() in keytools.WORDLIST for w in words):
                    add(" ".join(w.lower() for w in words), "%s/bip39-mnemonic" % scan)
    cand = os.path.join(HERE, "eth_candidates.txt")
    if os.path.exists(cand):
        for line in open(cand, encoding="utf-8", errors="replace"):
            s = line.strip()
            if re.fullmatch(r"[0-9a-fA-F]{64}", s):
                add(s, "eth_candidates.txt")

    if not found:
        return "  ключей не найдено"
    out = ["кандидатов: %d" % len(found), ""]
    global _last_addrs
    found_addrs: list[tuple[str, str]] = []
    valid = 0
    for val, srcs in sorted(found.items()):
        k, res = keytools.check_any(val)
        ok = any(r.get("ok") for r in res)
        valid += ok
        out.append("%s %s  [%s]" % ("OK  " if ok else "FAIL", val[:48],
                                    "; ".join(sorted(srcs))[:60]))
        if not ok:
            out.append("      " + (res[0].get("reason", "") if res else ""))
        for r in res:
            if "addr" in r and r.get("ok") is None:
                found_addrs.append((r.get("coin", "?"), r["addr"]))
                out.append("      %-5s %s" % (r["coin"], r["addr"]))
    _last_addrs = found_addrs
    out.append("")
    out.append("валидных ключей: %d из %d | адресов для проверки баланса: %d"
               % (valid, len(found), len(found_addrs)))
    return "\n".join(out)


# ------------------------------------------------------------------ баланс

def check_balances() -> str:
    import requests
    addrs = [a for c, a in _last_addrs if c in ("ETH",)]
    utxo = [a for c, a in _last_addrs if c in ("BTC", "LTC", "DOGE")]
    if not addrs and not utxo:
        return "  сначала проверьте ключи — адресов нет"
    out = []
    for a in dict.fromkeys(addrs):
        res = None
        for url in ("https://cloudflare-eth.com", "https://eth.llamarpc.com",
                    "https://ethereum.publicnode.com"):
            try:
                r = requests.post(url, timeout=12, json={
                    "jsonrpc": "2.0", "id": 1, "method": "eth_getBalance",
                    "params": [a, "latest"]})
                res = r.json().get("result")
                if res:
                    break
            except Exception:
                continue
        if res:
            bal = int(res, 16) / 10**18
            cnt = None
            try:
                r = requests.post("https://ethereum.publicnode.com", timeout=12,
                                  json={"jsonrpc": "2.0", "id": 1,
                                        "method": "eth_getTransactionCount",
                                        "params": [a, "latest"]})
                cnt = int(r.json()["result"], 16)
            except Exception:
                pass
            out.append("ETH %s  bal=%.6f  tx=%s%s" % (
                a, bal, cnt, "  ***" if (bal > 0 or (cnt or 0) > 0) else ""))
        else:
            out.append("ETH %s  RPC недоступен" % a)
    # UTXO пачкой
    coin_of: dict[str, str] = {}
    for c, a in _last_addrs:
        if c in ("BTC", "LTC", "DOGE"):
            coin_of[a] = c
    base = {"BTC": "bitcoin", "LTC": "litecoin", "DOGE": "dogecoin"}
    for coin in ("BTC", "LTC", "DOGE"):
        addrs2 = [a for a, c in coin_of.items() if c == coin]
        if not addrs2:
            continue
        for i in range(0, len(addrs2), 40):
            part = addrs2[i:i + 40]
            try:
                r = requests.get(
                    "https://api.blockchair.com/%s/dashboards/address/%s"
                    % (base[coin], ",".join(part)), timeout=25)
                data = r.json().get("data") or {}
            except Exception as e:
                out.append("%s: blockchair %s" % (coin, e))
                continue
            for a in part:
                entry = data.get(a)
                s = (entry or {}).get("address") if isinstance(entry, dict) else None
                if not s:
                    out.append("%s %s  нет активности" % (coin, a))
                    continue
                bal = int(s.get("balance", 0)) / 10**8
                tx = s.get("transaction_count")
                mark = " ***" if (bal > 0 or tx) else ""
                out.append("%s %s  bal=%.8f  tx=%s%s" % (coin, a, bal, tx, mark))
    return "\n".join(out) if out else "  адресов нет"


# ------------------------------------------------------------------ GUI

def main() -> None:
    root = tk.Tk()
    root.title("Проверка ключей — hex / WIF / мнемоника / XPRV")
    root.geometry("980x680")

    top = tk.Frame(root)
    top.pack(fill="x", padx=8, pady=6)

    inp = tk.Text(root, height=5, wrap="word", font=("TkFixedFont", 10))
    inp.pack(fill="x", padx=8)
    inp.insert("1.0", "Вставь сюда ключ или текст с ключом")

    out = tk.Text(root, wrap="word", font=("TkFixedFont", 10))
    out.pack(fill="both", expand=True, padx=8, pady=6)

    scroll = ttk.Scrollbar(out, command=out.yview)
    out.configure(yscrollcommand=scroll.set)

    busy = {"v": False}
    status = None  # создаётся ниже в bottom-фрейме, кнопки смотрят на closure

    def save_out():
        """Сохранить вывод в reports/key_check_<время>.txt и показать путь."""
        import datetime
        text = out.get("1.0", "end")
        if not text.strip():
            status.config(text="нет данных для сохранения")
            return
        os.makedirs(os.path.join(HERE, "reports"), exist_ok=True)
        name = "key_check_%s.txt" % datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        path = os.path.join(HERE, "reports", name)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        status.config(text="сохранено: %s" % path, fg="#8f8")
        try:
            import subprocess
            subprocess.Popen(["xdg-open", path])
        except Exception:
            pass

    def run(fn, label: str):
        if busy["v"]:
            return
        busy["v"] = True
        status.config(text="%s..." % label)
        out.delete("1.0", "end")
        out.insert("end", "%s, подожди...\n" % label)

        def worker():
            try:
                text = fn()
            except Exception as e:
                text = "  ОШИБКА: %r" % e
            def done():
                out.delete("1.0", "end")
                out.insert("end", text)
                status.config(text="готово")
                busy["v"] = False
            root.after(0, done)

        threading.Thread(target=worker, daemon=True).start()

    def btn(parent, text, cmd, w=18):
        b = tk.Button(parent, text=text, command=cmd, width=w,
                      bg="#202020", fg="#2ee05a", activebackground="#303030",
                      activeforeground="#2ee05a", relief="flat", bd=1,
                      font=("TkDefaultFont", 9, "bold"))
        b.pack(side="left", padx=3)
        return b

    btn(top, "АВТО (тип сам)",
        lambda: run(lambda: check_text(inp.get("1.0", "end")), "авто"))
    btn(top, "HEX64",
        lambda: run(lambda: check_text(inp.get("1.0", "end").strip(),
                                       "hex"), "hex"))
    btn(top, "WIF",
        lambda: run(lambda: check_text(inp.get("1.0", "end").strip(),
                                       "wif"), "wif"))
    btn(top, "МНЕМОНИКА",
        lambda: run(lambda: check_text(inp.get("1.0", "end").strip(),
                                       "mnemonic"), "мнемоника"))
    btn(top, "XPRV",
        lambda: run(lambda: check_text(inp.get("1.0", "end").strip(),
                                       "xprv"), "xprv"))
    btn(top, "ОТЧЁТЫ СКАНЕРА",
        lambda: run(check_reports, "отчёты"), 20)
    btn(top, "БАЛАНС И TX",
        lambda: run(check_balances, "баланс"), 16)
    btn(top, "СОХРАНИТЬ", save_out, 12)
    btn(top, "ОЧИСТИТЬ",
        lambda: (out.delete("1.0", "end"), inp.delete("1.0", "end"),
                 status.config(text="")), 12)

    bottom = tk.Frame(root)
    bottom.pack(fill="x", padx=8, pady=(0, 6))
    status = tk.Label(bottom, text="готово", anchor="w", fg="#8f8")
    status.pack(side="left")
    tk.Label(bottom,
             text="типы: hex64 | WIF (BTC/LTC/DOGE) | мнемоника BIP39 | xprv BIP32",
             fg="#888").pack(side="right")

    root.mainloop()


if __name__ == "__main__":
    main()
