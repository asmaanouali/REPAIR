from lxml import etree
def find_user(tree, name2):
    return tree.xpath("//user[@name2=$v_0]", v_0=name2)
