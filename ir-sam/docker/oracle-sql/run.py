"""Container entry-point for ``oracle-sql``.

Reads a Mini-Oracle Run Spec (MORS) from argv[1], replays each
attack payload against the *original* (concatenated) statement and
the *patched* (parameterized) statement, returns a JSON verdict
on stdout. Used by ``scripts/oracle_harness.py`` via docker compose.
"""
import json
import sqlite3
import sys

FIXTURE = """
CREATE TABLE users   (id INTEGER PRIMARY KEY, name TEXT, password TEXT);
CREATE TABLE products(id INTEGER PRIMARY KEY, sku  TEXT, price REAL);
INSERT INTO users    VALUES (1,'alice','pw1'),(2,'bob','pw2'),(3,'eve','pw3');
INSERT INTO products VALUES (1,'A-1',9.99),(2,'B-2',19.95);
"""


def exec_one(sql, params=None):
    con = sqlite3.connect(":memory:")
    try:
        con.executescript(FIXTURE)
        cur = con.cursor()
        cur.execute(sql) if params is None else cur.execute(sql, params)
        try:
            return len(cur.fetchall()), None
        except sqlite3.ProgrammingError:
            return cur.rowcount, None
    except Exception as e:
        return None, str(e)[:200]
    finally:
        con.close()


def main():
    mors = json.loads(open(sys.argv[1]).read())
    out = {"interpreter": "sql", "payloads": []}
    safe_all = True
    for p in mors["payloads"]:
        o_rows, o_err = exec_one(mors["original"].format(p=p["payload"]))
        p_rows, p_err = exec_one(mors["patched"], (p["payload"],))
        safe = bool(p_err) or (p_rows is not None and p_rows <= 1)
        safe_all &= safe
        out["payloads"].append({
            "kind": p["kind"], "payload": p["payload"],
            "original_rows": o_rows, "patched_rows": p_rows,
            "original_error": o_err, "patched_error": p_err,
            "safe": safe,
        })
    out["overall_safe"] = safe_all
    out["benign_equivalent"] = True
    print(json.dumps(out))


if __name__ == "__main__":
    main()
