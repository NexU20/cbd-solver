#!/usr/bin/env python3
import argparse
import base64
import html
import re
import ssl
import sys
import urllib.parse
import urllib.request


KNOWN_ORDER = b"item=enterprise_gold&price=004800&buyer=guest&ship=standard"
TARGET_ORDER = b"item=celestial_waifu&price=000000&buyer=guest&ship=standard"


def normalize_url(target):
    if not target.startswith(("http://", "https://")):
        target = "http://" + target
    return target.rstrip("/")


def post_form(base_url, path, fields, context=None):
    data = urllib.parse.urlencode(fields).encode()
    req = urllib.request.Request(
        base_url + path,
        data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10, context=context) as resp:
        return resp.read().decode("utf-8", errors="replace")


def b64u_decode(token):
    return base64.urlsafe_b64decode(token + "=" * (-len(token) % 4))


def b64u_encode(raw):
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def xor3(a, b, c):
    if not (len(a) == len(b) == len(c)):
        raise ValueError("ciphertext, known plaintext, and target plaintext lengths differ")
    return bytes(x ^ y ^ z for x, y, z in zip(a, b, c))


def extract_order_token(page):
    match = re.search(r'name=["\']order_token["\'][^>]*value=["\']([^"\']+)', page)
    if not match:
        raise RuntimeError("order_token not found in /order response")
    return html.unescape(match.group(1))


def extract_code(page):
    match = re.search(r"<code>(.*?)</code>", page, re.DOTALL | re.IGNORECASE)
    if match:
        return html.unescape(match.group(1)).strip()
    return page.strip()


def solve(base_url, insecure=False):
    context = ssl._create_unverified_context() if insecure else None
    order_page = post_form(base_url, "/order", {"item": "enterprise_gold"}, context)
    known_token = extract_order_token(order_page)
    known_ct = b64u_decode(known_token)

    forged_ct = xor3(known_ct, KNOWN_ORDER, TARGET_ORDER)
    forged_token = b64u_encode(forged_ct)

    claim_page = post_form(base_url, "/claim", {"order_token": forged_token}, context)
    return forged_token, extract_code(claim_page)


def main():
    parser = argparse.ArgumentParser(
        description="Exploit AES-CTR nonce reuse in crypto/waifu-shop."
    )
    parser.add_argument("target", help="target base URL, e.g. http://host:5000")
    parser.add_argument(
        "-k",
        "--insecure",
        action="store_true",
        help="disable TLS certificate verification",
    )
    args = parser.parse_args()

    base_url = normalize_url(args.target)
    forged_token, result = solve(base_url, args.insecure)
    print(f"[+] forged token: {forged_token}")
    print(f"[+] result: {result}")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"[-] {exc}", file=sys.stderr)
        sys.exit(1)
