#include <stdint.h>
#include <string>
#include <vector>


typedef uint32_t tag_id;
typedef uint32_t tag_off;
static tag_id g_index = 1;

class SegTag {
public:
  tag_id id;
  tag_id parent;
  tag_off begin;
  tag_off end;
  bool temp = false;
  SegTag(){
  }
  SegTag(tag_off begin_, tag_off end_, tag_id parent_) {
    begin = begin_;
    end = end_;
    parent = parent_;
    id = g_index++;
  };
  std::string toString(){
      char buf[64];
      sprintf(buf, "{\"id\":%d, \"begin\":%d, \"end\":%d, \"parent\":%d, \"temp\":%d}", id, begin, end, parent, temp);
      std::string s(buf);
      return s;
  }
  size_t getLen() { return (end - begin); }
};