import tree_sitter_java as tsj
from tree_sitter import Language, Parser

L = Language(tsj.language())
p = Parser(L)
src = b'class X { void m(String name) { String s = "hi " + name; stmt.executeQuery(s); } }'
t = p.parse(src)
print("ROOT:", t.root_node.type)
print(t.root_node.sexp()[:500])
