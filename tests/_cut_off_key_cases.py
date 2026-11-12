"""Synthetic cut-off private-key inputs shared by the Python and JS tests (#1555).

The bodies are random base64 from a fixed seed; none is a real key.
"""

from __future__ import annotations

import random

_RNG = random.Random(1555)
_B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def body(lines: int, width: int = 64, last: int | None = None) -> list[str]:
    """``lines`` base64 lines of ``width`` characters; the last is ``last`` long."""
    out = ["".join(_RNG.choice(_B64) for _ in range(width)) for _ in range(lines)]
    if last is not None:
        out[-1] = out[-1][:last]
    return out


BEGIN = "-----BEGIN RSA PRIVATE KEY-----"
BEGIN_OSSH = "-----BEGIN OPENSSH PRIVATE KEY-----"
BEGIN_PGP = "-----BEGIN PGP PRIVATE KEY BLOCK-----"
MARK = "[REDACTED:private_key]"
_HEAD = body(20)
_SSH = body(5, 70, last=12)


def _slashed(lines: list[str]) -> list[str]:
    """Lines with a JSON-escaped slash (backslash, slash) inside each."""
    return [x[:20] + "\\/" + x[22:] for x in lines]


_CUT = "[900 chars truncated \u2014 line exceeded 500 char limit]"

# (id, text, expected output of redact_credentials)
POSITIVE = [
    ("head-n-20", BEGIN + "\n" + "\n".join(_HEAD) + "\n", MARK + "\n"),
    (
        "keeps-trailing-text",
        BEGIN + "\n" + "\n".join(_HEAD) + "\n$ echo done\ndone",
        MARK + "\n$ echo done\ndone",
    ),
    (
        "mid-line-cut-then-marker",
        BEGIN + "\n" + "\n".join(body(3)) + "\n" + body(1, 64)[0][:9] + "\n[truncated: 99 chars]",
        MARK + "\n[truncated: 99 chars]",
    ),
    ("crlf", BEGIN + "\r\n" + "\r\n".join(_HEAD) + "\r\n$ after", MARK + "\r\n$ after"),
    (
        "proc-type-headers",
        BEGIN
        + "\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,0123456789ABCDEF\n\n"
        + "\n".join(body(4))
        + "\n$ next",
        MARK + "\n$ next",
    ),
    (
        "pgp-armor",
        BEGIN_PGP + "\nVersion: GnuPG v2\n\n" + "\n".join(body(4)) + "\n=AbCd\nnext",
        MARK + "\n=AbCd\nnext",
    ),
    ("openssh-70", BEGIN_OSSH + "\n" + "\n".join(_SSH) + "\n$ after", MARK + "\n$ after"),
    (
        "json-escaped",
        '{"stdout": "' + BEGIN + "\\n" + "\\n".join(body(4)) + '\\n", "rc": 0}',
        '{"stdout": "' + MARK + '\\n", "rc": 0}',
    ),
    (
        "json-escaped-crlf",
        '{"s": "' + BEGIN + "\\r\\n" + "\\r\\n".join(body(3)) + '", "rc": 0}',
        '{"s": "' + MARK + '", "rc": 0}',
    ),
    (
        "json-escaped-slashes",
        '{"stdout": "' + BEGIN + "\\n" + "\\n".join(_slashed(body(4))) + '\\n", "rc": 0}',
        '{"stdout": "' + MARK + '\\n", "rc": 0}',
    ),
    (
        "json-escaped-slashes-short-last-line",
        '{"s": "' + BEGIN + "\\n" + "\\n".join(_slashed(body(3))) + "\\n" + "ab\\/cd" + '"}',
        '{"s": "' + MARK + '"}',
    ),
    (
        "marker-after-cut-line",
        BEGIN + "\n" + body(1)[0] + "\n" + body(1, 40)[0] + " ... " + _CUT + " ... ",
        MARK + " ... " + _CUT + " ... ",
    ),
    (
        "marker-after-first-cut-line",
        BEGIN + "\n" + body(1, 40)[0] + " ... [900 chars truncated]",
        MARK + " ... [900 chars truncated]",
    ),
    (
        "search-suffix-marker",
        BEGIN + "\n" + body(1)[0] + "\n" + body(1, 30)[0] + "...[truncated",
        MARK + "...[truncated",
    ),
    ("ends-at-end-of-text", BEGIN + "\n" + body(1)[0] + "\n" + body(1, 30)[0], MARK),
    ("single-16-char-line-at-end", BEGIN + "\n" + body(1, 16)[0], MARK),
    (
        "at-most-one-short-final-line",
        BEGIN + "\n" + body(1)[0] + "\nAAAA\nBBBB\n",
        MARK + "\nBBBB\n",
    ),
    ("blanks-after-the-begin-line", BEGIN + " \t\n" + body(1)[0] + "\n", MARK + "\n"),
    ("trailing-padding", BEGIN + "\n" + "\n".join(body(2)) + "==\n", MARK + "\n"),
]

# Text that must come back unchanged.
NEGATIVE = [
    ("inline-in-prose", f"the header line {BEGIN} marks a key file"),
    ("followed-by-prose", BEGIN + "\nThis file holds the deploy key.\nSee the docs."),
    ("followed-by-example", BEGIN + "\nExample\n"),
    ("elided-body", BEGIN + "\nMIIEvQIBADANBg...\n"),
    ("example-on-begin-line", BEGIN + " (example)\n" + "\n".join(body(3)) + "\n"),
    ("elided-long-line", BEGIN + "\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC...\n"),
    ("prose-with-an-ellipsis", BEGIN + "\nTheConfigurationLoader... reads it"),
    ("example-with-dots", BEGIN + "\nExample ...\n"),
    ("text-after-the-begin-dashes", BEGIN + " x\n" + body(1)[0] + "\n"),
    ("setext-underline", BEGIN + "\n=====\n"),
    ("fifteen-chars", BEGIN + "\n" + body(1, 15)[0] + "\n"),
    (
        "numbered-lines",
        BEGIN + "\n" + "\n".join(f"{i + 2}:" + x for i, x in enumerate(body(3))) + "\n",
    ),
]
