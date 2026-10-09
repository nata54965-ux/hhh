#!/usr/bin/env python3
"""Проверка найденных ключей: приватник -> адрес (валидация) -> баланс -> транзакции.

Источники кандидатов:
  1. hex64-секреты из reports/*/*.json (правила gitleaks)
  2. eth_candidates.txt (64-hex строки)
  3. WIF-ключи из отчётов -> BTC-адрес

Валидация:
  - скаляр приватного ключа: 1 <= k < n (порядок secp256k1)
  - EIP-55 checksum адреса (пересчитываем хеши, сравняем регистр)
  - WIF: base58check, версия 0x80, контрольный байт

Баланс/транзакции: публичные RPC (ETH) + blockchair (BTC/ETH детали).
"""
from __future__ import annotations

import glob
import json
import os
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from eth_hash.auto import keccak
from eth_keys import keys
from eth_utils import to_checksum_address

HERE = os.path.dirname(os.path.abspath(__file__))
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

ETH_RPCS = [
    "https://cloudflare-eth.com",
    "https://eth.llamarpc.com",
    "https://rpc.ankr.com/eth",
    "https://ethereum.publicnode.com",
]


def collect_hex64() -> dict[str, set[str]]:
    """hex64-секреты: значение -> множество источников (файл отчёта/правило)."""
    out: dict[str, set[str]] = {}
    for path in sorted(glob.glob(os.path.join(HERE, "reports", "*", "*.json"))):
        try:
            items = json.load(open(path, encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(items, list):
            continue
        for it in items:
            sec = (it.get("Secret") or "").strip()
            if re.fullmatch(r"[0-9a-fA-F]{64}", sec):
                out.setdefault(sec.lower(), set()).add(
                    "%s/%s:%s" % (os.path.basename(os.path.dirname(path)),
                                  it.get("RuleID"), it.get("File"))
                )
    cand = os.path.join(HERE, "eth_candidates.txt")
    if os.path.exists(cand):
        for line in open(cand, encoding="utf-8", errors="replace"):
            s = line.strip().lower()
            if re.fullmatch(r"[0-9a-fA-F]{64}", s):
                out.setdefault(s, set()).add("eth_candidates.txt")
    return out


def collect_wif() -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for path in sorted(glob.glob(os.path.join(HERE, "reports", "*", "*.json"))):
        try:
            items = json.load(open(path, encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(items, list):
            continue
        for it in items:
            if it.get("RuleID") != "wif-key":
                continue
            sec = (it.get("Secret") or "").strip()
            if re.fullmatch(r"[5KL][1-9A-HJ-NP-Za-km-z]{49,51}", sec):
                out.setdefault(sec, set()).add(
                    "%s:%s" % (it.get("RuleID"), it.get("File"))
                )
    return out


def validate_hex_key(h: str) -> tuple[bool, str, str | None, str | None]:
    """-> (валиден, причина, EIP-55 адрес или None, приватный сжатый или None)."""
    try:
        k = int(h, 16)
    except ValueError:
        return False, "не hex", None, None
    if k == 0 or k >= SECP256K1_N:
        return False, "скаляр вне [1, n) secp256k1", None, None
    try:
        pk = keys.PrivateKey(bytes.fromhex(h))
        addr = to_checksum_address("0x" + keccak(pk.public_key.to_bytes())[12:].hex())
    except Exception as e:  # pragma: no cover
        return False, "eth_keys: %s" % e, None, None
    if not eip55_ok(addr):
        return False, "EIP-55 checksum не сошёлся", None, None
    return True, "ok", addr, pk.public_key.to_compressed_bytes().hex()


def eip55_ok(addr: str) -> bool:
    body = addr[2:].lower()
    checksummed = addr[2:]
    if len(body) != 40 or len(checksummed) != 40:
        return False
    digest = keccak(body.encode()).hex()
    for c, d in zip(checksummed, digest):
        if c in "0123456789":
            continue
        # EIP-55: цифра хеша >= 8 -> заглавная, иначе строчная.
        if d in "89abcdef" and not c.isupper():
            return False
        if d in "01234567" and not c.islower():
            return False
    return True


def wif_to_address(wif: str) -> tuple[bool, str, str | None]:
    import base58
    import hashlib

    try:
        raw = base58.b58decode(wif)
    except Exception as e:
        return False, "base58decode: %s" % e, None
    if len(raw) not in (37, 38):
        return False, "длина %d (ожидалось 37/38)" % len(raw), None
    payload, chk = raw[:-4], raw[-4:]
    expect = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    if expect != chk:
        return False, "контрольная сумма base58check не сошлась", None
    ver, body = payload[0], payload[1:]
    if ver != 0x80:
        return False, "версия 0x%02x != 0x80 (не Bitcoin mainnet)" % ver, None
    compressed = len(body) == 33
    if not compressed and len(body) != 32:
        return False, "длина payload %d (ожидалось 32/33)" % len(body), None
    h160 = hashlib.sha256(hashlib.sha256(body).digest()).digest()[:20]
    addr = base58.b58encode_check(bytes([0x00]) + h160).decode()
    return True, ("ok, compressed" if compressed else "ok, uncompressed"), addr


def eth_rpc(method: str, params: list) -> object | None:
    payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    for url in ETH_RPCS:
        try:
            r = requests.post(url, json=payload, timeout=12)
            if r.status_code == 200:
                d = r.json()
                if "result" in d and d["result"] is not None:
                    return d["result"]
        except Exception:
            continue
    return None


def eth_check(addr: str) -> dict:
    bal = eth_rpc("eth_getBalance", [addr, "latest"])
    cnt = eth_rpc("eth_getTransactionCount", [addr, "latest"])
    return {
        "balance_eth": int(bal, 16) / 10**18 if bal else None,
        "tx_count": int(cnt, 16) if cnt else None,
    }


BLOCKSCOUT_TOK = "https://eth.blockscout.com/api/v2/addresses/%s/token-balances"


def eth_tokens(addr: str) -> list[dict]:
    """ERC-20 балансы адреса через Blockscout (без API-ключа).
    Возвращает [{symbol, amount, usd}] только по токенам с ненулевой суммой.
    """
    try:
        r = requests.get(BLOCKSCOUT_TOK % addr, timeout=15)
        if r.status_code != 200:
            return []
        out = []
        for t in r.json() or []:
            tok = t.get("token") or {}
            try:
                raw = int(t.get("value") or 0)
            except (TypeError, ValueError):
                continue
            dec = int(tok.get("decimals") or 18)
            amt = raw / 10**dec
            if amt <= 0:
                continue
            rate = tok.get("exchange_rate")
            try:
                usd = amt * float(rate) if rate else 0.0
            except (TypeError, ValueError):
                usd = 0.0
            out.append({"symbol": tok.get("symbol") or "?",
                        "amount": amt, "usd": usd})
        return out
    except Exception:
        return []


def blockchair_eth(addr: str) -> dict | None:
    try:
        r = requests.get(
            "https://api.blockchair.com/ethereum/dashboards/address/%s" % addr,
            timeout=15)
        if r.status_code != 200:
            return None
        d = (r.json().get("data") or {}).get(addr) or {}
        s = d.get("address") or {}
        return {
            "balance_eth": (int(s.get("balance", 0)) / 10**18) if s else None,
            "tx_count": s.get("transaction_count"),
        }
    except Exception:
        return None


def blockchair_btc(addr: str) -> dict | None:
    try:
        r = requests.get(
            "https://api.blockchair.com/bitcoin/dashboards/address/%s" % addr,
            timeout=15)
        if r.status_code != 200:
            return None
        d = (r.json().get("data") or {}).get(addr) or {}
        s = d.get("address") or {}
        return {
            "balance_btc": int(s.get("balance", 0)) / 10**8,
            "tx_count": s.get("transaction_count"),
        }
    except Exception:
        return None


# --- семейство UTXO (BTC/LTC/DOGE): те же ключи secp256k1, другие версии ---

P2PKH_VERSION = {"BTC": 0x00, "LTC": 0x30, "DOGE": 0x1E}
BLOCKCHAIR_COIN = {"BTC": "bitcoin", "LTC": "litecoin", "DOGE": "dogecoin"}


def hash160(data: bytes) -> bytes:
    import hashlib
    try:
        ripemd = hashlib.new("ripemd160")
    except Exception:
        from Crypto.Hash import RIPEMD160  # pycryptodome
        ripemd = RIPEMD160.new()
    ripemd.update(hashlib.sha256(data).digest())
    return ripemd.digest()


def p2pkh(pub_bytes: bytes, version: int) -> str:
    import base58
    import hashlib
    h160 = hash160(pub_bytes)
    payload = bytes([version]) + h160
    chk = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return base58.b58encode(payload + chk).decode()


def utxo_addresses(hexkey: str) -> dict[str, list[tuple[str, str]]]:
    """{coin: [(формат, адрес), ...]} для приватного ключа."""
    from eth_keys import keys
    pk = keys.PrivateKey(bytes.fromhex(hexkey))
    pub = pk.public_key
    out: dict[str, list[tuple[str, str]]] = {}
    for coin, ver in P2PKH_VERSION.items():
        out[coin] = [
            ("compressed", p2pkh(pub.to_compressed_bytes(), ver)),
            ("uncompressed", p2pkh(pub.to_bytes(), ver)),
        ]
    return out


def blockchair_bulk(coin: str, addrs: list[str], chunk: int = 50) -> dict[str, dict]:
    """Баланс/tx_count для списка адресов одним запросом (Blockchair делает до 100)."""
    res: dict[str, dict] = {}
    base = BLOCKCHAIR_COIN[coin]
    for i in range(0, len(addrs), chunk):
        part = addrs[i:i + chunk]
        try:
            r = requests.get(
                "https://api.blockchair.com/%s/dashboards/address/%s"
                % (base, ",".join(part)), timeout=25)
            if r.status_code != 200:
                continue
            data = r.json().get("data") or {}
            for a in part:
                s = (data.get(a) or {}).get("address")
                if not s:
                    continue
                res[a] = {
                    "balance": int(s.get("balance", 0)) / 10**8,
                    "tx_count": s.get("transaction_count"),
                }
        except Exception:
            continue
    return res



def main() -> int:
    hexes = collect_hex64()
    wifs = collect_wif()
    print("hex64-кандидатов: %d | WIF: %d\n" % (len(hexes), len(wifs)))

    hits = []
    print("%-44s %-8s %s" % ("АДРЕС", "СТАТУС", "БАЛАНС / TX"))
    print("-" * 100)

    def check_hex(item):
        h, srcs = item
        ok, reason, addr, _ = validate_hex_key(h)
        if not ok or addr is None:
            return ("hex", h, addr, reason, None, srcs)
        info = eth_check(addr) or {}
        if info.get("balance_eth") is None:
            info = blockchair_eth(addr) or info
        info["tokens"] = eth_tokens(addr)  # ERC-20: баланс ETH не видит токены
        return ("hex", h, addr, reason, info, srcs)

    with ThreadPoolExecutor(max_workers=8) as ex:
        futs = [ex.submit(check_hex, it) for it in hexes.items()]
        for f in as_completed(futs):
            kind, h, addr, reason, info, srcs = f.result()
            if addr is None:
                continue
            bal = info.get("balance_eth")
            tx = info.get("tx_count")
            line = "%-44s %-8s bal=%s ETH tx=%s" % (
                addr, "VALID", ("%.6f" % bal) if bal is not None else "?",
                tx if tx is not None else "?")
            print(line)
            toks = info.get("tokens") or []
            if toks:
                for t in sorted(toks, key=lambda x: -x["usd"])[:8]:
                    print("      токен %-12s %18.6f  $%.2f%s" % (
                        t["symbol"], t["amount"], t["usd"],
                        " ***" if t["usd"] > 0 else ""))
            tok_usd = sum(t["usd"] for t in toks)
            if (bal and bal > 0) or (tx and tx > 0) or tok_usd > 0:
                hits.append((addr, bal if (bal and bal > 0) else
                             ("токены $%.2f" % tok_usd if tok_usd > 0 else bal),
                             tx, sorted(srcs)[:2]))

        # WIF -> BTC
        for wif, srcs in wifs.items():
            ok, reason, addr = wif_to_address(wif)
            if not ok or addr is None:
                print("%-44s %-8s %s" % ("WIF " + wif[:16] + "...", "BAD", reason))
                continue
            info = blockchair_btc(addr) or {}
            bal, tx = info.get("balance_btc"), info.get("tx_count")
            print("%-44s %-8s bal=%s BTC tx=%s" % (
                addr, "VALID", bal if bal is not None else "?",
                tx if tx is not None else "?"))
            if (bal and bal > 0) or (tx and tx > 0):
                hits.append((addr, bal, tx, sorted(srcs)[:2]))

    # --- UTXO: те же приватники -> BTC / LTC / DOGE (P2PKH compressed+uncompressed)
    valid = [(h, s) for h, s in hexes.items() if validate_hex_key(h)[2] is not None]
    want: dict[str, dict[str, tuple[str, list[str]]]] = {}  # coin -> addr -> (формат, srcs)
    for h, srcs in valid:
        try:
            for coin, lst in utxo_addresses(h).items():
                for fmt, addr in lst:
                    want.setdefault(coin, {}).setdefault(
                        addr, (fmt, sorted(srcs)[:2]))
        except Exception:
            continue

    print("\n--- UTXO (BTC/LTC/DOGE): %d ключей -> %s адресов ---" % (
        len(valid), {c: len(v) for c, v in want.items()}))
    for coin in ("BTC", "LTC", "DOGE"):
        amap = want.get(coin, {})
        if not amap:
            continue
        info = blockchair_bulk(coin, list(amap))
        live = 0
        for addr, (fmt, srcs) in sorted(amap.items()):
            s = info.get(addr)
            if not s:
                continue  # Blockchair не знает адрес (нет активности)
            bal, tx = s.get("balance"), s.get("tx_count")
            if (bal and bal > 0) or (tx and tx > 0):
                live += 1
                print("%-44s %-8s bal=%s %s tx=%s (%s)" % (
                    addr, "LIVE", bal, coin, tx, fmt))
                hits.append(("%s %s" % (addr, coin), bal, tx, srcs))
        print("  %s: проверено %d адресов, с балансом/историей: %d"
              % (coin, len(amap), live))

    print("\n" + "=" * 100)
    if not hits:
        print("ПОЗИЦИИ С НЕНУЛЕВЫМ БАЛАНСОМ ИЛИ ТРАНЗАКЦИЯМИ: 0")
        return 0
    print("ПОЗИЦИИ (баланс > 0 или были транзакции): %d" % len(hits))
    for addr, bal, tx, srcs in hits:
        print("  %s  bal=%s  tx=%s  <- %s" % (addr, bal, tx, "; ".join(srcs)))
    return 1


if __name__ == "__main__":
    sys.exit(main())
