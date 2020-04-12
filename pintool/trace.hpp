#ifndef INTRIGUER_TRACE_HPP_
#define INTRIGUER_TRACE_HPP_

#include <list>
#include <fstream>

#include "pin.H"
#include "instrument.hpp"

void printTraceLogReg(REG_TAINT* reg, UINT64 size);
void printTraceLogMem(MEM_TAINT_MAP* map, UINT64 size);
//print value
void printTraceLogVal(UINT8* val, UINT64 size);
//trace reg
void printTraceLog(UINT64 insAddr, string insDis, REG_TAINT* reg, UINT64 val, UINT64 size);
//trace reg imm
void printTraceLog(UINT64 insAddr, string insDis, REG_TAINT* reg, UINT64 val, UINT64 imm, UINT64 size);
//trace reg reg
void printTraceLog(UINT64 insAddr, string insDis, REG_TAINT* reg, UINT64 val1, REG_TAINT* reg2, UINT64 val2, UINT64 size);
//trace reg reg imm
void printTraceLog(UINT64 insAddr, string insDis, REG_TAINT* reg, UINT64 val, REG_TAINT* reg2, UINT64 val2, UINT64 imm, UINT64 size);
//trace reg mem imm
void printTraceLog(UINT64 insAddr, string insDis, REG_TAINT* reg, UINT64 val, MEM_TAINT_MAP* map, UINT8* val2, UINT64 imm, UINT64 size);
//trace reg mem
void printTraceLog(UINT64 insAddr, string insDis, REG_TAINT* reg, UINT64 val1, MEM_TAINT_MAP* map, UINT8* val2, UINT64 size);
//trace mem reg
void printTraceLog(UINT64 insAddr, string insDis, MEM_TAINT_MAP* map, UINT8* val1, REG_TAINT* reg, UINT64 val2, UINT64 size);
//trace mem mem
void printTraceLog(UINT64 insAddr, string insDis, MEM_TAINT_MAP* map1, UINT8* val1, MEM_TAINT_MAP* map2, UINT8* val2, UINT64 size);
//trace mem
void printTraceLog(UINT64 insAddr, string insDis, MEM_TAINT_MAP* map, UINT8* val,UINT64 size);
//trace mem imm
void printTraceLog(UINT64 insAddr, string insDis, MEM_TAINT_MAP* map, UINT8* val1, UINT64 val2, UINT64 size);
//trace reg reg SIMD
void printTraceLog(UINT64 insAddr, string insDis, REG_TAINT* reg, UINT8* val1, REG_TAINT* reg2, UINT8* val2, UINT64 size);
//trace reg mem SIMD
void printTraceLog(UINT64 insAddr, string insDis, REG_TAINT* reg, UINT8* val1, MEM_TAINT_MAP* map, UINT8* val2, UINT64 size);

#endif