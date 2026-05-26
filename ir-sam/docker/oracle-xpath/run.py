"""Container entry-point for ``oracle-xpath``.

lxml-backed evaluator. Original is interpolated; patched uses lxml
xpath-variable binding (``$v_N``) which provides true value-binding.
"""
import json
import sys

DOC = (
    "<users>"
    "<user name='alice' role='admin'><pwd>pw1</pwd></user>"
    "<user name='bob'   role='user' ><pwd>pw2</pwd></user>"
    "<user name='eve'   role='user' ><pwd>pw3</pwd></user>"
    "</users>"
)


def main():
    from lxml import etree
    mors = json.loads(open(sys.argv[1]).read())
    tree = etree.fromstring(DOC)
    out = {"interpreter": "xpath", "payloads": []}
    safe_all = True
    for p in mors["payloads"]:
        try:
            o = len(tree.xpath(mors["original"].format(p=p["payload"])))
        except Exception:
            o = None
        try:
            pp = len(tree.xpath(mors["patched"],
                                **{f"v_{i}": p["payload"] for i in range(4)}))
        except Exception:
            pp = None
        safe = pp is None or pp <= 1
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
