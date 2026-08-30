#!/usr/bin/env python3
"""
Generate conformance vectors for Orisan canonical JSON.

The reference behaviour is the TypeScript implementation:
  JSON.stringify(sortKeys(value))  with sortKeys built on Object.create(null)

This script reimplements that in Python and emits vectors.json so Go, Python and
TypeScript test suites can all assert byte-identical canonical output and hashes.

Two JS behaviours that trip up naive ports and are encoded here deliberately:

1. JS sorts object keys by UTF-16 CODE UNIT, not Unicode code point. For
   characters outside the BMP (emoji, rare CJK) these orders DIFFER. Python's
   sorted() uses code points. Go's sort.Strings uses UTF-8 bytes, which happens
   to match code-point order. So a naive Go or Python port can order keys
   differently from TypeScript on exactly the inputs users are most likely to
   paste in.

2. JSON.stringify does NOT escape non-ASCII, DOES escape control characters
   with short forms (\\b \\f \\n \\r \\t), and escapes lone surrogates as
   \\udXXX to keep output well-formed.
"""

import hashlib
import json
import os
import re


def utf16_code_units(s: str):
    """Key ordering as JS sees it: UTF-16 code units."""
    return s.encode("utf-16-be", errors="surrogatepass")


def sort_keys(value):
    if isinstance(value, list):
        return [sort_keys(v) for v in value]
    if isinstance(value, dict):
        return {k: sort_keys(value[k]) for k in sorted(value.keys(), key=utf16_code_units)}
    return value


ESCAPES = {
    '"': '\\"',
    "\\": "\\\\",
    "\b": "\\b",
    "\f": "\\f",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
}


def js_quote(s: str) -> str:
    """Match JSON.stringify's string escaping exactly."""
    out = ['"']
    for ch in s:
        if ch in ESCAPES:
            out.append(ESCAPES[ch])
        elif ord(ch) < 0x20:
            out.append(f"\\u{ord(ch):04x}")
        elif 0xD800 <= ord(ch) <= 0xDFFF:
            # lone surrogate: JSON.stringify emits it escaped, lowercase hex
            out.append(f"\\u{ord(ch):04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def canonical(value) -> str:
    """Byte-for-byte equivalent of JSON.stringify(sortKeys(value))."""
    v = sort_keys(value)
    return _ser(v)


def _ser(v) -> str:
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, str):
        return js_quote(v)
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        raise ValueError("floats are not permitted in hashed fields")
    if isinstance(v, list):
        return "[" + ",".join(_ser(x) for x in v) + "]"
    if isinstance(v, dict):
        return "{" + ",".join(f"{js_quote(k)}:{_ser(x)}" for k, x in v.items()) + "}"
    raise TypeError(f"unsupported type {type(v)}")


def escape_lone_surrogates(text: str) -> str:
    """Escape unpaired surrogates so the emitted file is valid UTF-8 and valid JSON.

    A lone surrogate is a legal Python str element and a legal JSON *escape*, but
    it is not encodable as UTF-8. json.dumps(ensure_ascii=False) would leave it
    raw and the write would then fail — or, worse on some paths, emit bytes no
    strict UTF-8 reader accepts. Emitting the \\udXXX escape keeps the file
    readable by every JSON parser while JSON.parse and json.loads both hand the
    consumer back the same lone code unit.

    Applied to the whole document, which is safe: every other string in it is
    already free of unpaired surrogates, so this is a no-op for them.
    """
    return re.sub(r"[\ud800-\udfff]", lambda m: "\\u%04x" % ord(m.group(0)), text)


# ---------------------------------------------------------------------------
# The vectors. Each one exists because a specific port gets it wrong.
# ---------------------------------------------------------------------------

VECTORS = [
    {
        "name": "empty_object",
        "why": "baseline",
        "input": {},
    },
    {
        "name": "empty_array",
        "why": "baseline",
        "input": [],
    },
    {
        "name": "key_sorting_basic",
        "why": "keys must be reordered, not preserved in insertion order",
        "input": {"z": 1, "a": 2, "m": 3},
    },
    {
        "name": "proto_key",
        "why": (
            "TS: a normal object literal makes __proto__ hit Object.prototype's "
            "setter, no own property is created, and the key VANISHES from the "
            "canonical string while surviving in the file. Content could be "
            "parked in an anchored event uncommitted by the hash. "
            "Object.create(null) is mandatory."
        ),
        "input": {"a": 1, "__proto__": {"evil": True}},
    },
    {
        "name": "constructor_key",
        "why": "same class of prototype-pollution hazard as __proto__",
        "input": {"constructor": "x", "b": 2},
    },
    {
        "name": "html_chars",
        "why": (
            "Go's encoding/json escapes < > & by default as \\u003c etc. "
            "SetEscapeHTML(false) is REQUIRED or Go diverges from TS."
        ),
        "input": {"html": "<script>a && b</script>"},
    },
    {
        "name": "non_ascii",
        "why": (
            "Python's json.dumps defaults to ensure_ascii=True and escapes all "
            "non-ASCII. ensure_ascii=False is REQUIRED."
        ),
        "input": {"text": "café ☕ naïve Ünicode"},
    },
    {
        "name": "cjk",
        "why": "multi-byte UTF-8, no escaping in TS",
        "input": {"name": "日本語テスト"},
    },
    {
        "name": "emoji_surrogate_pair",
        "why": (
            "Outside the BMP. JS strings are UTF-16 so this is a surrogate "
            "pair; affects both encoding and key ordering."
        ),
        "input": {"emoji": "🔐 secure 👍"},
    },
    {
        "name": "key_sorting_astral",
        "why": (
            "THE ordering trap. JS sorts by UTF-16 code unit, Python by code "
            "point, Go by UTF-8 byte. An astral-plane key sorts DIFFERENTLY "
            "under JS than under a naive port, producing a different canonical "
            "string and a different hash."
        ),
        "input": {"🔐": 1, "\uffff": 2, "a": 3},
    },
    {
        "name": "control_characters",
        "why": "short escapes (\\n \\t) vs \\u00XX form must match exactly",
        "input": {"s": "line1\nline2\ttabbed\r\nend\bx\fy"},
    },
    {
        "name": "control_char_low",
        "why": "sub-0x20 characters with no short form use lowercase \\u00xx",
        "input": {"s": "\u0000\u0001\u001f"},
    },
    {
        "name": "quotes_and_backslashes",
        "why": "escaping order errors double-escape",
        "input": {"s": 'he said "hi" \\ then left'},
    },
    {
        "name": "solidus_not_escaped",
        "why": "JSON permits \\/ but JSON.stringify does NOT escape it",
        "input": {"path": "a/b/c"},
    },
    {
        "name": "nested_deep",
        "why": "recursion must sort at every level, not just the root",
        "input": {"b": {"z": 1, "a": {"y": 2, "b": [{"q": 1, "p": 2}]}}, "a": 1},
    },
    {
        "name": "array_order_preserved",
        "why": "arrays must NOT be sorted; order is semantic",
        "input": {"list": [3, 1, 2, "z", "a"]},
    },
    {
        "name": "nulls_and_bools",
        "why": "literal spelling",
        "input": {"n": None, "t": True, "f": False},
    },
    {
        "name": "integers",
        "why": "no float formatting divergence; large ints must not gain exponents",
        "input": {"zero": 0, "neg": -42, "big": 9007199254740991},
    },
    {
        "name": "empty_string_key",
        "why": "empty key is legal and sorts first",
        "input": {"": 1, "a": 2},
    },
    {
        "name": "realistic_event_v3",
        "why": "a full RecordedEvent shape, hash field excluded from its own input",
        "input": {
            "v": 3,
            "seq": 42,
            "event_id": "018f3a2b-7c4d-7e8f-9a0b-1c2d3e4f5a6b",
            "session_id": "sess-01H",
            "ts": "2026-08-29T14:23:45.123Z",
            "clock_source": "host_wall_clock",
            "actor": {
                "human": "rakesh",
                "agent_id": "spiffe://orisan/agent/claude-code",
                "tool": "claude-code",
            },
            "kind": "tool_call",
            "target": "filesystem/read_file",
            "args_digest": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "payload_ref": None,
            "outcome": "ok",
            "duration_ms": 17,
            "prev_hash": "0" * 64,
        },
    },
    {
        "name": "lone_surrogate",
        "why": (
            "An unpaired UTF-16 code unit. JSON.stringify has been well-formed "
            "since ES2019: it emits a lone surrogate as a \\udXXX escape, "
            "lowercase, rather than producing unencodable output. A port that "
            "passes the string through raw emits invalid UTF-8; one that "
            "substitutes U+FFFD changes the bytes and therefore the hash."
        ),
        "input": {"s": "\ud800"},
    },
    {
        "name": "lone_surrogate_key",
        "why": (
            "The same unpaired unit as an object KEY, beside an astral key and "
            "an ASCII one, so UTF-16 ordering is exercised on a code unit that "
            "is not part of a pair. Sorting by code POINT has to decode, and a "
            "lone surrogate has no code point to decode to; sorting by UTF-8 "
            "byte cannot encode it at all. Only a code-unit sort orders these "
            "three the way JS does: a, then U+D800, then U+1F510 (whose first "
            "unit is U+D83D)."
        ),
        "input": {"\ud800": 1, "🔐": 2, "a": 3},
    },
]


# ---------------------------------------------------------------------------
# Coercions: values canonicalJson does NOT reject.
#
# These were written expecting canonicalJson to refuse them. It does not - it is
# JSON.stringify underneath, which coerces rather than throws. They are recorded
# here as measured behaviour so a port matches the reference instead of matching
# an intention, and `emits` below is asserted against the real implementation.
#
# They cannot be JSON literals (JSON has no NaN, no Infinity, and cannot tell -0
# from 0), so each entry names a value the consumer builds in its own language.
# `build: "float"` means the double 1.5 specifically.
# ---------------------------------------------------------------------------

COERCIONS = [
    {
        "name": "nan",
        "build": "NaN",
        "emits": "null",
        "why": (
            "JSON.stringify(NaN) is \"null\". Nothing throws, so a NaN reaching a "
            "hashed field is indistinguishable from a null one: argsDigest({n:NaN}) "
            "and argsDigest({n:null}) are the same digest. Unreachable from "
            "JSON.parse, which is why SECURITY-REVIEW-R1 rules it out as a "
            "collision, but reachable from any in-language caller."
        ),
    },
    {
        "name": "infinity",
        "build": "Infinity",
        "emits": "null",
        "why": "JSON.stringify(Infinity) is \"null\", same collapse as NaN.",
    },
    {
        "name": "negative_infinity",
        "build": "-Infinity",
        "emits": "null",
        "why": "JSON.stringify(-Infinity) is \"null\"; the sign is lost too.",
    },
    {
        "name": "negative_zero",
        "build": "-0",
        "emits": "0",
        "why": (
            "-0 is here because JSON.stringify(-0) emits \"0\" while Python emits "
            "\"-0.0\": a silent cross-language divergence, which is exactly why "
            "floats are rejected rather than serialized. Note the rejecting is done "
            "by THIS GENERATOR (_ser raises on float), not by canonicalJson, which "
            "emits \"0\" and moves on. RFC 8785 also canonicalises -0 to 0, so the "
            "reference behaviour is defensible - it is the unstated asymmetry "
            "between the two implementations that bites."
        ),
    },
    {
        "name": "float",
        "build": "float",
        "emits": "1.5",
        "why": (
            "The double 1.5. This generator raises ValueError on any float, so no "
            "float can appear in `vectors` above; canonicalJson serialises it "
            "happily. A port that mirrors this generator's strictness will reject "
            "inputs the reference accepts."
        ),
    },
]


def main():
    out = {
        "spec": "orisan-canonical-json",
        "spec_version": "0.1",
        "reference": "orisan-recorder/src/schema.ts canonicalJson()",
        "hash": "sha256 of the UTF-8 bytes of canonical_json",
        "notes": [
            "Object keys sort by UTF-16 code unit (JS semantics), not code point.",
            "Go: json.Encoder.SetEscapeHTML(false) is required.",
            "Python: json.dumps(ensure_ascii=False, separators=(',',':'), sort_keys=...) "
            "with a UTF-16-aware key sort.",
            "TypeScript: build the sorted object with Object.create(null).",
            "canonicalJson COERCES non-finite and non-integer numbers rather than "
            "rejecting them - see the `coercions` array for the exact output of each. "
            "Nothing in schema.ts throws on them.",
        ],
        "vectors": [],
        "coercions": COERCIONS,
    }

    for v in VECTORS:
        c = canonical(v["input"])
        h = hashlib.sha256(c.encode("utf-8")).hexdigest()
        out["vectors"].append({
            "name": v["name"],
            "why": v["why"],
            "input": v["input"],
            "canonical_json": c,
            "sha256": h,
        })

    text = json.dumps(out, ensure_ascii=False, indent=2) + "\n"
    text = escape_lone_surrogates(text)
    dest = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "..", "test", "fixtures", "canonical-json-vectors.json",
    )
    dest = os.path.normpath(dest)
    with open(dest, "w", encoding="utf-8") as f:
        f.write(text)
    print(f"wrote {dest}")

    print(
        f"wrote vectors.json with {len(out['vectors'])} vectors "
        f"and {len(out['coercions'])} coercions\n"
    )
    for v in out["vectors"]:
        print(f"  {v['name']:<28} {v['sha256'][:16]}...  {v['canonical_json'][:52]}")


if __name__ == "__main__":
    main()
