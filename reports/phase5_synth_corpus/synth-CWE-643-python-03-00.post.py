from lxml import etree
def find_user(tree, name0):
    return tree.xpath("//user[@name0=$v_0]", v_0=name0)
