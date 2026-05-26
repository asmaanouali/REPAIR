from lxml import etree
def find_user(tree, name0):
    return tree.xpath("//user[@name0='" + name0 + "']")
