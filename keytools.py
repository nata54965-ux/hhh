#!/usr/bin/env python3
"""Разбор и валидация всех типов приватных ключей, которые умеет находить сканер.

Типы (auto-detect по строке):
  hex      — 64 hex-символа (±0x): ETH-ключ, он же ключ BTC/LTC/DOGE (secp256k1)
  wif      — WIF Bitcoin/Litecoin/Dogecoin (base58check, версии 0x80/0xB0/0x9E)
  mnemonic — BIP39 (12/15/18/21/24 слова, контрольная сумма)
  xprv     — BIP32 HD-ключ (xprv/yprv/zprv/tprv...), из него деривируются
             ETH m/44'/60'/0'/0/0 и BTC m/44'/0'/0'/0/0

Каждый тип возвращает список позиций: (coin, формат, адрес, доп. валидация).
"""
from __future__ import annotations

import hashlib
import hmac
import re
import struct

import base58
from coincurve import PrivateKey, PublicKey
from eth_hash.auto import keccak
from mnemonic import Mnemonic

SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
P2PKH_VERSION = {"BTC": 0x00, "LTC": 0x30, "DOGE": 0x1E}
WIF_VERSION = {0x80: "BTC", 0xB0: "LTC", 0x9E: "DOGE"}
WORDLIST = [w.strip() for w in open(
    __file__.replace("keytools.py", "bip39_english.txt"), encoding="utf-8")
    if w.strip()]


def sha256d(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def hash160(b: bytes) -> bytes:
    try:
        r = hashlib.new("ripemd160")
    except Exception:
        from Crypto.Hash import RIPEMD160
        r = RIPEMD160.new()
    r.update(hashlib.sha256(b).digest())
    return r.digest()


def p2pkh(pub_bytes: bytes, version: int) -> str:
    payload = bytes([version]) + hash160(pub_bytes)
    return base58.b58encode(payload + sha256d(payload)[:4]).decode()


def eth_address(pub_uncompressed: bytes) -> str:
    """pub_uncompressed: 65 байт 0x04||X||Y."""
    return "0x" + keccak(pub_uncompressed[1:])[12:].hex()


def checksum_addr(addr: str) -> bool:
    return to_checksum(addr) == addr


def to_checksum(addr: str) -> str:
    body = addr.lower().removeprefix("0x")
    d = keccak(body.encode()).hex()
    out = "".join(c.upper() if c.isalpha() and int(h, 16) >= 8 else c
                  for c, h in zip(body, d))
    return "0x" + out


# ---------------------------------------------------------------- детект

HEX_RE = re.compile(r"^(0x)?[0-9a-fA-F]{64}$")
WIF_RE = re.compile(r"^[5KL9c][1-9A-HJ-NP-Za-km-z]{50,51}$")
XPRV_RE = re.compile(r"^[xyz]prv[1-9A-HJ-NP-Za-km-z]{100,}$")
MNEMONIC_SIZES = {12, 15, 18, 21, 24}


def detect(s: str) -> str:
    t = s.strip()
    if HEX_RE.match(t):
        return "hex"
    if XPRV_RE.match(t):
        return "xprv"
    if WIF_RE.match(t):
        return "wif"
    words = t.split()
    if len(words) in MNEMONIC_SIZES and all(w.isalpha() and w in WORDLIST
                                            for w in words):
        return "mnemonic"
    # мнемоника может быть записана вперемешку с мусором — ищем последовательность
    return "unknown"


# ---------------------------------------------------------------- hex

def check_hex(s: str) -> list[dict]:
    t = s.strip().lower().removeprefix("0x")
    if not re.fullmatch(r"[0-9a-f]{64}", t):
        return [{"ok": False, "reason": "не hex64"}]
    k = int(t, 16)
    if k == 0 or k >= SECP256K1_N:
        return [{"ok": False, "reason": "скаляр вне [1, n) secp256k1"}]
    pk = PrivateKey(bytes.fromhex(t))
    pub_c = pk.public_key.format(compressed=True)
    pub_u = pk.public_key.format(compressed=False)
    out = [{"ok": True, "reason": "secp256k1 ok"}]
    addr = eth_address(pub_u)
    addr = to_checksum(addr)
    out.append({"coin": "ETH", "fmt": "address", "addr": addr,
                "extra": "EIP-55 ok"})
    for coin, ver in P2PKH_VERSION.items():
        out.append({"coin": coin, "fmt": "compressed", "addr": p2pkh(pub_c, ver)})
        out.append({"coin": coin, "fmt": "uncompressed", "addr": p2pkh(pub_u, ver)})
    return out


# ---------------------------------------------------------------- wif

def check_wif(s: str) -> list[dict]:
    t = s.strip()
    try:
        raw = base58.b58decode(t)
    except Exception as e:
        return [{"ok": False, "reason": "base58: %s" % e}]
    if len(raw) not in (37, 38):
        return [{"ok": False, "reason": "длина %d" % len(raw)}]
    payload, chk = raw[:-4], raw[-4:]
    if sha256d(payload)[:4] != chk:
        return [{"ok": False, "reason": "base58check: контрольная сумма"}]
    ver, body = payload[0], payload[1:]
    coin = WIF_VERSION.get(ver)
    if coin is None:
        return [{"ok": False, "reason": "версия 0x%02x неизвестна" % ver}]
    if len(body) == 33 and body[-1] == 0x01:
        body, compressed = body[:32], True
    elif len(body) == 32:
        compressed = False
    else:
        return [{"ok": False, "reason": "длина payload %d" % len(body)}]
    k = int.from_bytes(body, "big")
    if k == 0 or k >= SECP256K1_N:
        return [{"ok": False, "reason": "скаляр вне [1, n)"}]
    pk = PrivateKey(body)
    out = [{"ok": True, "reason": "WIF %s %s" %
            (coin, "compressed" if compressed else "uncompressed")}]
    pub_u = pk.public_key.format(compressed=False)
    out.append({"coin": "ETH", "fmt": "address",
                "addr": to_checksum(eth_address(pub_u)), "extra": "EIP-55 ok"})
    for c, ver2 in P2PKH_VERSION.items():
        pub = pk.public_key.format(compressed=compressed)
        out.append({"coin": c, "fmt": "compressed" if compressed
                    else "uncompressed", "addr": p2pkh(pub, ver2)})
    return out


# ---------------------------------------------------------------- BIP32

def bip32_master(seed: bytes) -> tuple[bytes, bytes]:
    i = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    return i[:32], i[32:]


def bip32_ckd(k: bytes, c: bytes, idx: int) -> tuple[bytes, bytes]:
    if idx >= 0x80000000:
        data = b"\x00" + k + struct.pack(">I", idx)
    else:
        data = PrivateKey(k).public_key.format(compressed=True) \
            + struct.pack(">I", idx)
    i = hmac.new(c, data, hashlib.sha512).digest()
    il, ir = int.from_bytes(i[:32], "big"), i[32:]
    child = (il + int.from_bytes(k, "big")) % SECP256K1_N
    if il >= SECP256K1_N or child == 0:
        raise ValueError("невалидный child key (skip)")
    return child.to_bytes(32, "big"), ir


def bip32_derive(k: bytes, c: bytes, path: str) -> tuple[bytes, bytes]:
    for part in path.split("/")[1:]:
        hard = part.endswith("'") or part.endswith("h")
        idx = int(part.rstrip("'h")) + (0x80000000 if hard else 0)
        k, c = bip32_ckd(k, c, idx)
    return k, c


XPRV_VERSIONS = {
    0x0488ADE4: ("xprv", "BTC mainnet"),
    0x04358394: ("yprv", "BTC testnet"),
    0x04b2430C: ("zprv", "BTC script"),
    0x04358397: ("tprv", "BTC testnet"),
    0x019da462: ("Ltpv", "LTC mainnet"),
    0x0436ef7d: ("dgpv", "DOGE mainnet"),
}


def parse_xprv(s: str) -> tuple[bytes, bytes, str] | None:
    try:
        raw = base58.b58decode(s.strip())
    except Exception:
        return None
    if len(raw) != 82 or sha256d(raw[:-4])[:4] != raw[-4:]:
        return None
    # raw = ver(4) || depth(1) || fp(4) || child(4) || chain(32) || key(33) || chk(4)
    body = raw[4:-4]
    if len(body) != 74:
        return None
    chain, key = body[9:41], body[41:]
    if len(key) != 33 or key[0] != 0x00:
        return None
    ver = int.from_bytes(raw[:4], "big")
    name = XPRV_VERSIONS.get(ver, ("xprv", "неизвестная версия"))[1]
    return key[1:], chain, name


def check_xprv(s: str) -> list[dict]:
    parsed = parse_xprv(s)
    if parsed is None:
        return [{"ok": False, "reason": "xprv: base58check/структура"}]
    k, c, net = parsed
    if int.from_bytes(k, "big") >= SECP256K1_N:
        return [{"ok": False, "reason": "xprv: скаляр вне [1, n)"}]
    out = [{"ok": True, "reason": "BIP32 xprv ok (%s)" % net}]
    for coin, path in (("ETH", "m/44'/60'/0'/0/0"),
                       ("BTC", "m/44'/0'/0'/0/0")):
        try:
            dk, _ = bip32_derive(k, c, path)
        except ValueError as e:
            out.append({"ok": False, "reason": "%s: %s" % (coin, e)})
            continue
        pk = PrivateKey(dk)
        pub_u = pk.public_key.format(compressed=False)
        if coin == "ETH":
            addr = to_checksum(eth_address(pub_u))
            out.append({"coin": "ETH", "fmt": path, "addr": addr,
                        "extra": "EIP-55 ok"})
        else:
            out.append({"coin": "BTC", "fmt": path,
                        "addr": p2pkh(pk.public_key.format(compressed=True), 0x00)})
    return out


# ---------------------------------------------------------------- BIP39

def check_mnemonic(s: str) -> list[dict]:
    words = [w.lower() for w in s.strip().split() if w]
    if len(words) not in MNEMONIC_SIZES:
        return [{"ok": False, "reason": "слов %d (нужно 12/15/18/21/24)"
                % len(words)}]
    bad = [w for w in words if w not in WORDLIST]
    if bad:
        return [{"ok": False, "reason": "не из словаря: %s" % ", ".join(bad[:5])}]
    mn = Mnemonic("english")
    phrase = " ".join(words)
    if not mn.check(phrase):
        return [{"ok": False, "reason": "BIP39 контрольная сумма не сошлась"}]
    seed = Mnemonic.to_seed(phrase, passphrase="")
    out = [{"ok": True, "reason": "BIP39 ok (entropy checksum)"}]
    k, c = bip32_master(seed)
    for coin, path in (("ETH", "m/44'/60'/0'/0/0"),
                       ("BTC", "m/44'/0'/0'/0/0"),
                       ("BTC", "m/44'/0'/0'/0/1")):
        dk, _ = bip32_derive(k, c, path)
        pk = PrivateKey(dk)
        if coin == "ETH":
            addr = to_checksum(eth_address(pk.public_key.format(compressed=False)))
            out.append({"coin": "ETH", "fmt": path, "addr": addr,
                        "extra": "EIP-55 ok"})
        else:
            out.append({"coin": "BTC", "fmt": path,
                        "addr": p2pkh(pk.public_key.format(compressed=True), 0x00)})
    return out


# ---------------------------------------------------------------- entry

def check_any(s: str) -> tuple[str, list[dict]]:
    kind = detect(s)
    if kind == "hex":
        return kind, check_hex(s)
    if kind == "wif":
        return kind, check_wif(s)
    if kind == "mnemonic":
        return kind, check_mnemonic(s)
    if kind == "xprv":
        return kind, check_xprv(s)
    return kind, [{"ok": False, "reason": "тип не распознан "
                   "(hex64 / WIF / мнемоника BIP39 / xprv)"}]


if __name__ == "__main__":
    import sys
    for a in sys.argv[1:]:
        kind, res = check_any(a)
        print(kind)
        for r in res:
            print("   ", r)
