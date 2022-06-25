#include "pin.H"
#include "debug.h"
#include "tag_traits.h"
#include <string.h>


std::vector<SegTag*> tags;
tag_id tag_traits::cleared_val = 0;

SegTag* tag_combine(SegTag* lhs, SegTag* rhs, bool lr) {
  if (lhs == NULL || rhs == NULL){
    return NULL;
  }
  if (lr == L){
    lhs->end = rhs->end;
    rhs->temp = 1;
    return lhs;
  } else {
    rhs->begin = lhs->begin;
    lhs->temp = 1;
    return rhs;
  }
}

std::string tag_sprint(SegTag* tag) {
  if (tag == NULL)
  {
    return "{}";
  }
  
  return tag->toString();
}

SegTag* tag_alloc(tag_off begin, tag_off end, tag_id parent) {
  SegTag* newTag = new SegTag(begin, end, parent);
  tags.push_back(newTag);
  LOGD("[gen new tag!] tag:%s\n", newTag->toString().c_str());
  return newTag;
}


void printAllTags(){
  printf("start print all tags(size=%ldd):\n", tags.size());
  for(auto i : tags){
    printf("%s\n", i->toString().c_str());
  }
}


SegTag* tag_get(tag_id t) {
   if (t == 0){
      return NULL;
   }
   return tags.at(t-1);
}