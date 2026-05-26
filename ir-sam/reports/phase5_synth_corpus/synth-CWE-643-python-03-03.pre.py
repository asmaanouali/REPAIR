from lxml import etree
def find_user(tree, name3):
    return tree.xpath("//user[@name3='" + name3 + "']")
