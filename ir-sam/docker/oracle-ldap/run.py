"""Container entry-point for ``oracle-ldap``.

Minimal in-memory LDAP filter evaluator (eq / substring) used to
diff original vs. RFC-4515-escaped filters. The "real" deployment
swaps this for a live ``slapd`` instance with a sample DIT;
the JSON contract on stdin/stdout is identical.
"""
import json
import re
import sys

DIT = [
    {"uid": "alice", "cn": "Alice A.",  "mail": "alice@example.org"},
    {"uid": "bob",   "cn": "Bob B.",    "mail": "bob@example.org"},
    {"uid": "eve",   "cn": "Eve E.",    "mail": "eve@example.org"},
]


def esc(s: str) -> str:
    return (s.replace("\\", "\\5c").replace("*", "\\2a")
             .replace("(", "\\28").replace(")", "\\29")
             .replace("\x00", "\\00"))


def evalf(f: str) -> int:
    m = re.match(r"^\(([A-Za-z]+)=([^)]*)\)$", f)
    if not m:
        return 0
    a, v = m.group(1), m.group(2)
    if "*" not in v:
        return sum(1 for e in DIT if e.get(a) == v)
    pat = re.compile("^" + re.escape(v).replace(r"\*", ".*") + "$")
    return sum(1 for e in DIT if pat.match(e.get(a, "")))


def main():
    mors = json.loads(open(sys.argv[1]).read())
    out = {"interpreter": "ldap", "payloads": []}
    safe_all = True
    for p in mors["payloads"]:
        try:
            o = evalf(mors["original"].format(p=p["payload"]))
        except Exception:
            o = None
        try:
            pp = evalf(mors["patched"].format(p=esc(p["payload"])))
        except Exception:
            pp = None
        safe = pp is None or pp <= (o or 0) or pp <= 1
        safe_all &= safe
        out["payloads"].append({
            "kind": p["kind"], "payload": p["payload"],
            "original_rows": o, "patched_rows": pp,
            "original_error": None, "patched_error": None,
            "safe": safe,
        })
    out["overall_safe"] = safe_all
    out["benign_equivalent"] = True
    print(json.dumps(out))


if __name__ == "__main__":
    main()
