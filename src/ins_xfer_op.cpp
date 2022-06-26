#include "ins_xfer_op.h"
#include "ins_clear_op.h"
#include "ins_helper.h"

/* threads context */
extern thread_ctx_t *threads_ctx;

void PIN_FAST_ANALYSIS_CALL r2r_xfer_opb_ul(THREADID tid, uint32_t dst,
                                            uint32_t src) {
  tag_t src_tag = RTAG[src][0];

  RTAG[dst][1] = src_tag;
}

void PIN_FAST_ANALYSIS_CALL r2r_xfer_opb_lu(THREADID tid, uint32_t dst,
                                            uint32_t src) {
  tag_t src_tag = RTAG[src][1];

  RTAG[dst][0] = src_tag;
}

void PIN_FAST_ANALYSIS_CALL r2r_xfer_opb_u(THREADID tid, uint32_t dst,
                                           uint32_t src) {
  tag_t src_tag = RTAG[src][1];

  RTAG[dst][1] = src_tag;
}

void PIN_FAST_ANALYSIS_CALL r2r_xfer_opb_l(THREADID tid, uint32_t dst,
                                           uint32_t src) {
  tag_t src_tag = RTAG[src][0];

  RTAG[dst][0] = src_tag;
}

void PIN_FAST_ANALYSIS_CALL r2r_xfer_opw(THREADID tid, uint32_t dst,
                                         uint32_t src) {
  for (size_t i = 0; i < 2; i++) {
    RTAG[dst][i] = RTAG[src][i];
    /*
    if (!tag_is_empty(RTAG[src][i]))
      LOGD("[xfer_w] i%ld: src: %d (%d) -> dst: %d (%d)\n", i, src,
           RTAG[src][i], dst, RTAG[dst][i]);
           */
  }
}

void PIN_FAST_ANALYSIS_CALL r2r_xfer_opl(THREADID tid, uint32_t dst,
                                         uint32_t src) {
  for (size_t i = 0; i < 4; i++) {
    RTAG[dst][i] = RTAG[src][i];
  }
}

void PIN_FAST_ANALYSIS_CALL r2r_xfer_opq(THREADID tid, uint32_t dst,
                                         uint32_t src) {
  for (size_t i = 0; i < 8; i++) {
    RTAG[dst][i] = RTAG[src][i];
  }
}

void PIN_FAST_ANALYSIS_CALL r2r_xfer_opx(THREADID tid, uint32_t dst,
                                         uint32_t src) {
  for (size_t i = 0; i < 16; i++)
    RTAG[dst][i] = RTAG[src][i];
}

void PIN_FAST_ANALYSIS_CALL r2r_xfer_opy(THREADID tid, uint32_t dst,
                                         uint32_t src) {
  for (size_t i = 0; i < 32; i++)
    RTAG[dst][i] = RTAG[src][i];
}

tag_t get_m2r_tag(ADDRINT src, size_t len){
  tag_t src_tag_id = MTAG(src);
  if (!src_tag_id)
  {
    return 0;
  }
  tag_entity* src_tag = tag_get(src_tag_id);
  ADDRINT firstAddr = getFirstAddr(src, src_tag_id);
  ADDRINT finalAddr = getFinalAddr(src, src_tag_id);

  LOGD("[m2r taint!]  src=%p, len=%ld, src_tag=%s, src_tag_address=[%p,%p)\n", (void*)src, len, tag_sprint(src_tag).c_str(), (void*)firstAddr, (void*)finalAddr);
  tag_off newOffsetBegin = src - firstAddr + src_tag->begin;
  tag_off newOffsetEnd = (newOffsetBegin + len) >= src_tag->end ? src_tag->end : (newOffsetBegin + len);
  if (newOffsetBegin == src_tag->begin && newOffsetEnd == src_tag->end)
  {
    return src_tag_id;
  }
  tag_entity* newTag = tag_alloc(newOffsetBegin, newOffsetEnd, src_tag_id);
  newTag->temp = true;
  return newTag->id;
}

void PIN_FAST_ANALYSIS_CALL m2r_xfer_opb_u(THREADID tid, uint32_t dst,
                                           ADDRINT src) {
  tag_t src_tag = get_m2r_tag(src, 8);
  RTAG[dst][1] = src_tag;
}

void PIN_FAST_ANALYSIS_CALL m2r_xfer_opb_l(THREADID tid, uint32_t dst,
                                           ADDRINT src) {
  tag_t src_tag = get_m2r_tag(src, 8);
  RTAG[dst][0] = src_tag;
}

void PIN_FAST_ANALYSIS_CALL m2r_xfer_opw(THREADID tid, uint32_t dst,
                                         ADDRINT src) {
  tag_t src_tag = get_m2r_tag(src, 16); 
  for (size_t i = 0; i < 2; i++)
    RTAG[dst][i] = src_tag;
}

void PIN_FAST_ANALYSIS_CALL m2r_xfer_opl(THREADID tid, uint32_t dst,
                                         ADDRINT src) {
  tag_t src_tag = get_m2r_tag(src, 32); 
  for (size_t i = 0; i < 4; i++)
    RTAG[dst][i] = src_tag;
}

void PIN_FAST_ANALYSIS_CALL m2r_xfer_opq(THREADID tid, uint32_t dst,
                                         ADDRINT src) {
  tag_t src_tag = get_m2r_tag(src, 64); 
  for (size_t i = 0; i < 8; i++)
    RTAG[dst][i] = src_tag;
}

void PIN_FAST_ANALYSIS_CALL m2r_xfer_opx(THREADID tid, uint32_t dst,
                                         ADDRINT src) {
  tag_t src_tag = get_m2r_tag(src, 128); 
  for (size_t i = 0; i < 16; i++)
    RTAG[dst][i] = src_tag;
}

void PIN_FAST_ANALYSIS_CALL m2r_xfer_opy(THREADID tid, uint32_t dst,
                                         ADDRINT src) {
  tag_t src_tag = get_m2r_tag(src, 256); 
  for (size_t i = 0; i < 32; i++)
    RTAG[dst][i] = src_tag;
}

void x2m_op(ADDRINT dst, tag_t src_tag_id, size_t len){
  if (!src_tag_id)
  {
    return;
  }

  tag_entity* src_tag = tag_get(src_tag_id);
  tag_entity* pre_tag = tag_get(MTAG(dst-1));
  tag_entity* next_tag = NULL;

  bool isFullMove = src_tag->getLen() >= len;
  ADDRINT firstAddr = dst;
  ADDRINT finalAddr = isFullMove ? (dst + len) : (dst + src_tag->getLen());

  LOGD("[x2m taint!] fullMov=%d, src_tag_orig=%s", isFullMove, tag_sprint(src_tag).c_str());
  if (pre_tag && src_tag->begin == pre_tag->end){
    firstAddr = getFirstAddr(dst, pre_tag->id);
    src_tag = tag_combine(pre_tag, src_tag, R);
  }
  if (isFullMove){
    next_tag = tag_get(MTAG(dst + src_tag->getLen()));
    if(next_tag && src_tag->end == next_tag->begin){
      finalAddr = getFinalAddr(dst+len, next_tag->id);
      src_tag = tag_combine(src_tag, next_tag, L);
    }
  }
  src_tag->temp = false;
  ADDRINT i = firstAddr;
  for (; i < finalAddr; i++){
    tagmap_setb(i, src_tag->id);
  }
  if (!isFullMove){
    for (; i < (dst + len); i++){
      tagmap_setb(i, tag_traits::cleared_val);
    }
  }
  LOGD(", dst=%p, lent=%ld, src_tag_after=%s, pre_tag=%s, next_tag=%s, updateAddr=[%p,%p)\n", 
      (void*)dst, len, tag_sprint(src_tag).c_str(), tag_sprint(pre_tag).c_str(), tag_sprint(next_tag).c_str(), (void*)firstAddr, (void*)finalAddr);
}

void PIN_FAST_ANALYSIS_CALL r2m_xfer_opb_u(THREADID tid, ADDRINT dst,
                                           uint32_t src) {
  
  tag_t src_tag = RTAG[src][1];
  x2m_op(dst, src_tag, 8);
}

void PIN_FAST_ANALYSIS_CALL r2m_xfer_opb_l(THREADID tid, ADDRINT dst,
                                           uint32_t src) {
  tag_t src_tag = RTAG[src][0];

  x2m_op(dst, src_tag, 8);
}

void PIN_FAST_ANALYSIS_CALL r2m_xfer_opw(THREADID tid, ADDRINT dst,
                                         uint32_t src) {
  x2m_op(dst, RTAG[src][0], 16);
}

void PIN_FAST_ANALYSIS_CALL r2m_xfer_opl(THREADID tid, ADDRINT dst,
                                         uint32_t src) {
  x2m_op(dst, RTAG[src][0], 32);
}

void PIN_FAST_ANALYSIS_CALL r2m_xfer_opq(THREADID tid, ADDRINT dst,
                                         uint32_t src) {
  x2m_op(dst, RTAG[src][0], 64);
}

void PIN_FAST_ANALYSIS_CALL r2m_xfer_opx(THREADID tid, ADDRINT dst,
                                         uint32_t src) {
  x2m_op(dst, RTAG[src][0], 128);
}

void PIN_FAST_ANALYSIS_CALL r2m_xfer_opy(THREADID tid, ADDRINT dst,
                                         uint32_t src) {
  x2m_op(dst, RTAG[src][0], 256);
}

void PIN_FAST_ANALYSIS_CALL m2m_xfer_opb(ADDRINT dst, ADDRINT src) {
  tag_t src_tag = MTAG(src);

  x2m_op(dst, src_tag, 8);
}

void PIN_FAST_ANALYSIS_CALL m2m_xfer_opw(ADDRINT dst, ADDRINT src) {
  x2m_op(dst, MTAG(src), 16);
}

void PIN_FAST_ANALYSIS_CALL m2m_xfer_opl(ADDRINT dst, ADDRINT src) {
  x2m_op(dst, MTAG(src), 32);
}

void PIN_FAST_ANALYSIS_CALL m2m_xfer_opq(ADDRINT dst, ADDRINT src) {
  x2m_op(dst, MTAG(src), 64);
}

void PIN_FAST_ANALYSIS_CALL m2r_xfer_opq_h(THREADID tid, uint32_t dst,
                                           ADDRINT src) {
  tag_t src_tag = get_m2r_tag(src, 64); 
  for (size_t i = 0; i < 8; i++)
    RTAG[dst][i + 8] = src_tag;
}

void PIN_FAST_ANALYSIS_CALL r2m_xfer_opq_h(THREADID tid, ADDRINT dst,
                                           uint32_t src) {
  tag_t *src_tags = RTAG[src];

  for (size_t i = 0; i < 8; i++)
    x2m_op(dst + i, src_tags[i + 8], 8);
}

static void PIN_FAST_ANALYSIS_CALL r2m_xfer_opbn(THREADID tid, ADDRINT dst,
                                                 ADDRINT count,
                                                 ADDRINT eflags) {
  tag_t src_tag = RTAG[DFT_REG_RAX][0];
  if (likely(EFLAGS_DF(eflags) == 0)) {
    /* EFLAGS.DF = 0 */
    x2m_op(dst, src_tag, 8 * count);
  } else {
    /* EFLAGS.DF = 1 */
    x2m_op(dst, src_tag, 8 * count);
  }
}

static void PIN_FAST_ANALYSIS_CALL r2m_xfer_opwn(THREADID tid, ADDRINT dst,
                                                 ADDRINT count,
                                                 ADDRINT eflags) {
  tag_t src_tag[] = R16TAG(DFT_REG_RAX);
  if (likely(EFLAGS_DF(eflags) == 0)) {
    /* EFLAGS.DF = 0 */
    for (size_t i = 0; i < (count << 1); i++) {
      x2m_op(dst + i, src_tag[i % 2], 16);
    }
  } else {
    /* EFLAGS.DF = 1 */
    for (size_t i = 0; i < (count << 1); i++) {
      x2m_op(dst, src_tag[i % 2], 16);
    }
  }
}

static void PIN_FAST_ANALYSIS_CALL r2m_xfer_opln(THREADID tid, ADDRINT dst,
                                                 ADDRINT count,
                                                 ADDRINT eflags) {
  tag_t src_tag[] = R32TAG(DFT_REG_RAX);
  if (likely(EFLAGS_DF(eflags) == 0)) {
    /* EFLAGS.DF = 0 */
    for (size_t i = 0; i < (count << 2); i++) {
      x2m_op(dst + i, src_tag[i % 4], 32);
    }
  } else {
    /* EFLAGS.DF = 1 */
    for (size_t i = 0; i < (count << 2); i++) {
      x2m_op(dst + i, src_tag[i % 4], 32);
    }
  }
}

static void PIN_FAST_ANALYSIS_CALL r2m_xfer_opqn(THREADID tid, ADDRINT dst,
                                                 ADDRINT count,
                                                 ADDRINT eflags) {
  tag_t src_tag[] = R64TAG(DFT_REG_RAX);
  if (likely(EFLAGS_DF(eflags) == 0)) {
    /* EFLAGS.DF = 0 */
    for (size_t i = 0; i < (count << 3); i++) {
      x2m_op(dst + i, src_tag[i % 8], 64);
    }
  } else {
    /* EFLAGS.DF = 1 */
    for (size_t i = 0; i < (count << 3); i++) {
      x2m_op(dst + i, src_tag[i % 8], 64);
    }
  }
}

static ADDRINT PIN_FAST_ANALYSIS_CALL rep_predicate(BOOL first_iteration) {
  /* return the flag; typically this is true only once */
  return first_iteration;
}

void ins_xfer_op(INS ins) {
  REG reg_dst, reg_src;
  if (INS_MemoryOperandCount(ins) == 0) {
    reg_dst = INS_OperandReg(ins, OP_0);
    reg_src = INS_OperandReg(ins, OP_1);
    if (REG_is_gr64(reg_dst)) {
      R2R_CALL(r2r_xfer_opq, reg_dst, reg_src);
    } else if (REG_is_gr32(reg_dst)) {
      R2R_CALL(r2r_xfer_opl, reg_dst, reg_src);
    } else if (REG_is_gr16(reg_dst)) {
      R2R_CALL(r2r_xfer_opw, reg_dst, reg_src);
    } else if (REG_is_xmm(reg_dst)) {
      R2R_CALL(r2r_xfer_opx, reg_dst, reg_src);
    } else if (REG_is_ymm(reg_dst)) {
      R2R_CALL(r2r_xfer_opy, reg_dst, reg_src);
    } else if (REG_is_mm(reg_dst)) {
      R2R_CALL(r2r_xfer_opq, reg_dst, reg_src);
    } else {
      if (REG_is_Lower8(reg_dst) && REG_is_Lower8(reg_src)) {
        R2R_CALL(r2r_xfer_opb_l, reg_dst, reg_src);
      } else if (REG_is_Upper8(reg_dst) && REG_is_Upper8(reg_src)) {
        R2R_CALL(r2r_xfer_opb_u, reg_dst, reg_src);
      } else if (REG_is_Lower8(reg_dst)) {
        R2R_CALL(r2r_xfer_opb_lu, reg_dst, reg_src);
      } else {
        R2R_CALL(r2r_xfer_opb_ul, reg_dst, reg_src);
      }
    }
  } else if (INS_OperandIsMemory(ins, OP_1)) {
    reg_dst = INS_OperandReg(ins, OP_0);
    if (REG_is_gr64(reg_dst)) {
      M2R_CALL(m2r_xfer_opq, reg_dst);
    } else if (REG_is_gr32(reg_dst)) {
      M2R_CALL(m2r_xfer_opl, reg_dst);
    } else if (REG_is_gr16(reg_dst)) {
      M2R_CALL(m2r_xfer_opw, reg_dst);
    } else if (REG_is_xmm(reg_dst)) {
      M2R_CALL(m2r_xfer_opx, reg_dst);
    } else if (REG_is_ymm(reg_dst)) {
      M2R_CALL(m2r_xfer_opy, reg_dst);
    } else if (REG_is_mm(reg_dst)) {
      M2R_CALL(m2r_xfer_opq, reg_dst);
    } else if (REG_is_Upper8(reg_dst)) {
      M2R_CALL(m2r_xfer_opb_u, reg_dst);
    } else {
      M2R_CALL(m2r_xfer_opb_l, reg_dst);
    }
  } else {
    reg_src = INS_OperandReg(ins, OP_1);
    if (REG_is_gr64(reg_src)) {
      R2M_CALL(r2m_xfer_opq, reg_src);
    } else if (REG_is_gr32(reg_src)) {
      R2M_CALL(r2m_xfer_opl, reg_src);
    } else if (REG_is_gr16(reg_src)) {
      R2M_CALL(r2m_xfer_opw, reg_src);
    } else if (REG_is_xmm(reg_src)) {
      R2M_CALL(r2m_xfer_opx, reg_src);
    } else if (REG_is_ymm(reg_src)) {
      R2M_CALL(r2m_xfer_opy, reg_src);
    } else if (REG_is_mm(reg_src)) {
      R2M_CALL(r2m_xfer_opq, reg_src);
    } else if (REG_is_Upper8(reg_src)) {
      R2M_CALL(r2m_xfer_opb_u, reg_src);
    } else {
      R2M_CALL(r2m_xfer_opb_l, reg_src);
    }
  }
}

void ins_xfer_op_predicated(INS ins) {
  REG reg_dst, reg_src;
  if (INS_MemoryOperandCount(ins) == 0) {
    reg_dst = INS_OperandReg(ins, OP_0);
    reg_src = INS_OperandReg(ins, OP_1);
    if (REG_is_gr64(reg_dst)) {
      R2R_CALL_P(r2r_xfer_opq, reg_dst, reg_src);
    } else if (REG_is_gr32(reg_dst)) {
      R2R_CALL_P(r2r_xfer_opl, reg_dst, reg_src);
    } else {
      R2R_CALL_P(r2r_xfer_opw, reg_dst, reg_src);
    }
  } else {
    reg_dst = INS_OperandReg(ins, OP_0);
    if (REG_is_gr64(reg_dst)) {
      M2R_CALL_P(m2r_xfer_opq, reg_dst);
    } else if (REG_is_gr32(reg_dst)) {
      M2R_CALL_P(m2r_xfer_opl, reg_dst);
    } else {
      M2R_CALL_P(m2r_xfer_opw, reg_dst);
    }
  }
}

void ins_push_op(INS ins) {
  REG reg_src;
  if (INS_OperandIsReg(ins, OP_0)) {
    reg_src = INS_OperandReg(ins, OP_0);
    if (REG_is_gr64(reg_src)) {
      R2M_CALL(r2m_xfer_opq, reg_src);
    } else if (REG_is_gr32(reg_src)) {
      R2M_CALL(r2m_xfer_opl, reg_src);
    } else {
      R2M_CALL(r2m_xfer_opw, reg_src);
    }
  } else if (INS_OperandIsMemory(ins, OP_0)) {
    if (INS_MemoryWriteSize(ins) == BIT2BYTE(MEM_64BIT_LEN)) {
      M2M_CALL(m2m_xfer_opq);
    } else if (INS_MemoryWriteSize(ins) == BIT2BYTE(MEM_LONG_LEN)) {
      M2M_CALL(m2m_xfer_opl);
    } else {
      M2M_CALL(m2m_xfer_opw);
    }
  } else {
    INT32 n = INS_OperandWidth(ins, OP_0) / 8;
    M_CLEAR_N(n);
  }
}

void ins_pop_op(INS ins) {
  REG reg_dst;
  if (INS_OperandIsReg(ins, OP_0)) {
    reg_dst = INS_OperandReg(ins, OP_0);
    if (REG_is_gr64(reg_dst)) {
      M2R_CALL(m2r_xfer_opq, reg_dst);
    } else if (REG_is_gr32(reg_dst)) {
      M2R_CALL(m2r_xfer_opl, reg_dst);
    } else {
      M2R_CALL(m2r_xfer_opw, reg_dst);
    }
  } else if (INS_OperandIsMemory(ins, OP_0)) {
    if (INS_MemoryWriteSize(ins) == BIT2BYTE(MEM_64BIT_LEN)) {
      M2M_CALL(m2m_xfer_opq);
    } else if (INS_MemoryWriteSize(ins) == BIT2BYTE(MEM_LONG_LEN)) {
      M2M_CALL(m2m_xfer_opl);
    } else {
      M2M_CALL(m2m_xfer_opw);
    }
  }
}

void ins_stos_ins(INS ins, AFUNPTR fn) {
  INS_InsertIfPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)rep_predicate,
                             IARG_FAST_ANALYSIS_CALL, IARG_FIRST_REP_ITERATION,
                             IARG_END);
  INS_InsertThenPredicatedCall(
      ins, IPOINT_BEFORE, fn, IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
      IARG_MEMORYWRITE_EA, IARG_REG_VALUE, INS_RepCountRegister(ins),
      IARG_REG_VALUE, INS_OperandReg(ins, OP_4), IARG_END);
}

void ins_stosb(INS ins) {
  if (INS_RepPrefix(ins)) {
    ins_stos_ins(ins, (AFUNPTR)r2m_xfer_opbn);
  } else {
    R2M_CALL(r2m_xfer_opb_l, REG_AL);
  }
}

void ins_stosw(INS ins) {
  if (INS_RepPrefix(ins)) {
    ins_stos_ins(ins, (AFUNPTR)r2m_xfer_opwn);
  } else {
    R2M_CALL(r2m_xfer_opw, REG_AX);
  }
}

void ins_stosd(INS ins) {
  if (INS_RepPrefix(ins)) {
    ins_stos_ins(ins, (AFUNPTR)r2m_xfer_opln);
  } else {
    R2M_CALL(r2m_xfer_opw, REG_EAX);
  }
}

void ins_stosq(INS ins) {
  if (INS_RepPrefix(ins)) {
    ins_stos_ins(ins, (AFUNPTR)r2m_xfer_opqn);
  } else {
    R2M_CALL(r2m_xfer_opw, REG_RAX);
  }
}

void ins_movlp(INS ins) {
  if (INS_OperandIsMemory(ins, OP_0)) {
    REG reg_src = INS_OperandReg(ins, OP_1);
    R2M_CALL(r2m_xfer_opq, reg_src);
  } else {
    REG reg_dst = INS_OperandReg(ins, OP_0);
    M2R_CALL(m2r_xfer_opq, reg_dst);
  }
}

void ins_movhp(INS ins) {
  if (INS_OperandIsMemory(ins, OP_0)) {
    REG reg_src = INS_OperandReg(ins, OP_1);
    R2M_CALL(r2m_xfer_opq_h, reg_src);
  } else {
    REG reg_dst = INS_OperandReg(ins, OP_0);
    M2R_CALL(m2r_xfer_opq_h, reg_dst);
  }
}

void ins_lea(INS ins) {
  REG reg_base = INS_MemoryBaseReg(ins);
  REG reg_indx = INS_MemoryIndexReg(ins);
  REG reg_dst = INS_OperandReg(ins, OP_0);
  if (reg_base == REG_INVALID() && reg_indx == REG_INVALID()) {
    ins_clear_op(ins);
  }
  if (reg_base != REG_INVALID() && reg_indx == REG_INVALID()) {
    if (REG_is_gr64(reg_dst)) {
      R2R_CALL(r2r_xfer_opq, reg_dst, reg_base);
    } else if (REG_is_gr32(reg_dst)) {
      R2R_CALL(r2r_xfer_opl, reg_dst, reg_base);
    } else if (REG_is_gr16(reg_dst)) {
      R2R_CALL(r2r_xfer_opw, reg_dst, reg_base);
    }
  }
  if (reg_base == REG_INVALID() && reg_indx != REG_INVALID()) {
    if (REG_is_gr64(reg_dst)) {
      R2R_CALL(r2r_xfer_opq, reg_dst, reg_indx);
    } else if (REG_is_gr32(reg_dst)) {
      R2R_CALL(r2r_xfer_opl, reg_dst, reg_indx);
    } else if (REG_is_gr16(reg_dst)) {
      R2R_CALL(r2r_xfer_opw, reg_dst, reg_indx);
    }
  }
}

void PIN_FAST_ANALYSIS_CALL m2r_xfer_opw_rev(THREADID tid, uint32_t dst,
                                             ADDRINT src) {
  m2r_xfer_opw(tid, dst, src);
}

void PIN_FAST_ANALYSIS_CALL m2r_xfer_opl_rev(THREADID tid, uint32_t dst,
                                             ADDRINT src) {
  m2r_xfer_opl(tid, dst, src);
}

void PIN_FAST_ANALYSIS_CALL m2r_xfer_opq_rev(THREADID tid, uint32_t dst,
                                             ADDRINT src) {
  m2r_xfer_opq(tid, dst, src);
}

void PIN_FAST_ANALYSIS_CALL r2m_xfer_opw_rev(THREADID tid, ADDRINT dst,
                                             uint32_t src) {
  tag_t *src_tags = RTAG[src];
  x2m_op(dst, src_tags[0], 8);
  x2m_op(dst + 1, src_tags[1], 8);
}

void PIN_FAST_ANALYSIS_CALL r2m_xfer_opl_rev(THREADID tid, ADDRINT dst,
                                             uint32_t src) {
  tag_t *src_tags = RTAG[src];
  for (size_t i = 0; i < 4; i++)
    x2m_op(dst + i, src_tags[i], 8);
}

void PIN_FAST_ANALYSIS_CALL r2m_xfer_opq_rev(THREADID tid, ADDRINT dst,
                                             uint32_t src) {
  tag_t *src_tags = RTAG[src];
  for (size_t i = 0; i < 8; i++)
    x2m_op(dst + i, src_tags[i], 8);
}

void ins_movbe_op(INS ins) {
  if (INS_OperandIsMemory(ins, OP_1)) {
    REG reg_dst = INS_OperandReg(ins, OP_0);
    if (REG_is_gr64(reg_dst)) {
      M2R_CALL(m2r_xfer_opq_rev, reg_dst);
    } else if (REG_is_gr32(reg_dst)) {
      M2R_CALL(m2r_xfer_opl_rev, reg_dst);
    } else if (REG_is_gr16(reg_dst)) {
      M2R_CALL(m2r_xfer_opw_rev, reg_dst);
    }
  } else {
    REG reg_src = INS_OperandReg(ins, OP_1);
    if (REG_is_gr64(reg_src)) {
      R2M_CALL(r2m_xfer_opq_rev, reg_src);
    } else if (REG_is_gr32(reg_src)) {
      R2M_CALL(r2m_xfer_opl_rev, reg_src);
    } else if (REG_is_gr16(reg_src)) {
      R2M_CALL(r2m_xfer_opw_rev, reg_src);
    }
  }
}