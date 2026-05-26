from lxml import etree
def find_user(tree, name2):
    return tree.xpath("//user[@name2='" + name2 + "']")
