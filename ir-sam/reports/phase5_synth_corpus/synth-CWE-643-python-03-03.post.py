from lxml import etree
def find_user(tree, name3):
    return tree.xpath("//user[@name3=$v_0]", v_0=name3)
