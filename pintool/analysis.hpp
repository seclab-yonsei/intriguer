#ifndef INTRIGURE_ANALYSIS_HPP_
#define INTRIGURE_ANALYSIS_HPP_

#include "pin.H"

VOID Instruction(INS ins, VOID *v);

#define OP_0    0
#define OP_1    1
#define OP_2    2
#define OP_3    3

extern bool isTaintStart;

#endif