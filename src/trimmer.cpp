#include "trimmer.h"
#include "unistd.h"
#include "stdio.h"
#include "string.h"
#include "debug.h"
#include "time.h"
#include "iostream"
#include "stack"
#include "queue"
#include "list"
#include "unordered_set"
#include "unordered_map"
#include <cstdlib>
#include <fstream>
#include "cJSON.h"



using namespace std;

extern std::vector<SegTag*> tags;
// list<input_trim_seg*> trimSegList;
hdd_tree_node* tree = nullptr;


hdd_tree_node* createChildNode(SegTag* childTag){
    hdd_tree_node* newNode = new hdd_tree_node{ 0 };
    newNode->id = childTag->id;
    newNode->begin = childTag->begin;
    newNode->end = childTag->end;
    newNode->callstack = childTag->callstack;
    return newNode;
}

void buildTree(vector<SegTag*> tags){
    LOGD("Start build tree\n");
    tree = new hdd_tree_node{ 0 };
    unordered_set<std::string> exists_node;
    unordered_map<node_id, hdd_tree_node*> nodeMap;
    nodeMap.insert(make_pair(0, tree));
    
    stack<SegTag*> tagStack;
    for (auto i : tags){
        if (i->temp){
            continue;
        }
        
        string tag_key = to_string(i->begin) + "-" + to_string(i->end) + "-" + to_string(i->parent);
        if (exists_node.count(tag_key) > 0){
            continue;
        } else {
            exists_node.insert(tag_key);
        }
        nodeMap.insert(make_pair(i->id, createChildNode(i)));
        tagStack.push(i);
    }

    while (!tagStack.empty()){
        SegTag* tag = tagStack.top();
        unordered_map<node_id, hdd_tree_node*>::iterator parentIter = nodeMap.find(tag->parent);
        if (parentIter != nodeMap.end()) {
            parentIter->second->children.push_back(nodeMap.find(tag->id)->second);
        }
        tagStack.pop();
    }
}

cJSON* node2Json(hdd_tree_node *treeNode){
    cJSON *json = cJSON_CreateObject();
    cJSON_AddNumberToObject(json, "begin", treeNode->begin);
    cJSON_AddNumberToObject(json, "end", treeNode->end);
    cJSON *childrenArray = cJSON_CreateArray();
    cJSON_AddItemToObject(json, "children", childrenArray);
    for (auto i : treeNode->children){
        cJSON_AddItemToArray(childrenArray, node2Json(i));
    }
    return json;
}

bool reduceSeperateNode(hdd_tree_node *treeNode, int deep){
    if (treeNode->children.size() == 0){
        LOGD("%*s", deep * 2, "");
        LOGD("reduce tag finish id=%u r=1", treeNode->id);
        return true;
    }
    unordered_set<uint32_t> callstack_set;
    unordered_set<uint32_t> dup_callstack_set;
    LOGD("%*s", deep * 2, "");
    LOGD("start reduce tag:{%u, %u, %u, %ld}\n", treeNode->id, treeNode->begin, treeNode->end, treeNode->children.size());
    for (auto i : treeNode->children){
        if (callstack_set.count(i->callstack) > 0){
            dup_callstack_set.insert(i->callstack);
        } else {
            callstack_set.insert(i->callstack);
        }
    }
    bool r = true;
    for (vector<hdd_tree_node*>::iterator i = treeNode->children.begin(); i != treeNode->children.end(); i++){
        LOGD("%*s", deep * 2, "");
        LOGD("  child tag loop:{%u, %u, %u}\n", (*i)->id, (*i)->begin, (*i)->end);
        bool child_r = reduceSeperateNode(*i, deep + 1);
        if (child_r && dup_callstack_set.count((*i)->callstack) <= 0){
            treeNode->children.erase(i--);
        } else {
            r = false;
        }
    }
    LOGD("%*s", deep * 2, "");
    LOGD("reduce tag finish id=%u r=%d\n", treeNode->id, r);
    return r;
}


void startTrim() {
    buildTree(tags);

    reduceSeperateNode(tree, 0);
    
    cJSON *json = node2Json(tree);

    char *buf = cJSON_PrintUnformatted(json);

    FILE *fp = fopen("input_tree.json", "w");

    fwrite(buf, strlen(buf), 1, fp);

    fclose(fp);

    cJSON_Delete(json);

}
