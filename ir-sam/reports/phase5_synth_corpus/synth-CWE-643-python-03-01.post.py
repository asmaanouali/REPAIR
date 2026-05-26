from lxml import etree
def find_user(tree, name1):
    return tree.xpath("//user[@name1=$v_0]", v_0=name1)
