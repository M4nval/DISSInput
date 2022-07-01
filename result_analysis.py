import json

from pyecharts import options as opts
from pyecharts.charts import Tree


def trim_children(tree_node):
    box = set()
    if not tree_node.__contains__("children") or len(tree_node["children"]) <= 0:
        return
    for i in range(len(tree_node["children"])-1, -1, -1):
        node = tree_node["children"][i]
        if node.__contains__("children") and len(node["children"]) > 0:
            box.add(node["name"])
            # recurse call
            trim_children(node)
            continue
        if box.__contains__(node["name"]):
            tree_node["children"].remove(node)
            continue
        box.add(node["name"])


def draw():
    opts.InitOpts.width = "100%"
    tags_map_by_id = {}
    tree_nodes = {}

    # read tag list from file
    root_node = {"id": 0, "name": "root", "children": []}
    with open("tagList.out", "r", encoding="utf-8") as f:
        for line in f.readlines():
            tag = json.loads(line)
            tags_map_by_id[tag["id"]] = tag
    for s in tags_map_by_id.values():
        name = "[" + str(s["begin"]) + "~" + str(s["end"]) + "]"
        tempNode = {"id": s["id"], "name": name, "parent": s["parent"], "children": []}
        tree_nodes[s["id"]] = tempNode

    # build the tree
    for i in reversed(tree_nodes.keys()):
        s = tree_nodes[i]
        if s["parent"] == 0:
            root_node["children"].append(s)
        elif tree_nodes.__contains__(s["parent"]):
            tree_nodes[s["parent"]]["children"].append(s)

    # trim duplicate node
    trim_children(root_node)

    # draw
    c = (
        Tree(
            init_opts=opts.InitOpts(width="1800px", height="1000px")
        ).add(
            "",
            [root_node],
            collapse_interval=2,
            initial_tree_depth=-1,
            pos_right="10%"
        ).set_global_opts(
            title_opts=opts.TitleOpts(title="Tree-左右方向")
        ).render("tree_left_right.html")
    )


def draw_org():
    with open("flare.json", "r", encoding="utf-8") as f:
        j = json.load(f)
    c = (
        Tree()
            .add("", [j], collapse_interval=2)
            .set_global_opts(title_opts=opts.TitleOpts(title="Tree-左右方向"))
            .render("result.html")
    )


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    # drawOrg()
    draw()

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
