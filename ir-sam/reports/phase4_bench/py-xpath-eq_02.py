from lxml import etree
def find_user(tree, name: str):
    return tree.xpath("//user[@name='" + name + "']")
