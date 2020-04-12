#ifndef INTRIGUER_INSTRUMENT_HPP_
#define INTRIGUER_INSTRUMENT_HPP_

#include "pin.H"

#define REG_SIZE_1  1
#define REG_SIZE_2  2
#define REG_SIZE_4  4
#define REG_SIZE_8  8
#define REG_SIZE_16 16
#define REG_SIZE_32 32

struct REG_TAINT{
    REG reg;
    UINT64 bitmap;
    UINT64 offset[32];
};

struct MEM_TAINT{
    UINT64 address;
    UINT64 offset;
};

struct MEM_TAINT_MAP{
    UINT64 address;
    UINT64 bitmap;
    UINT64 offset[32];
};

struct MEM_TAINT_BASE{
    UINT64 base;
    vector<MEM_TAINT*> vecAddressTainted;
};

bool checkAlreadyRegTaintedOffset(REG reg, UINT8 offset);
bool checkAlreadyRegTainted(REG reg);

MEM_TAINT* getTaintMemPointer(UINT64 address);
bool checkAlreadyMemTainted(UINT64 address);

VOID removeMemTainted(UINT64 address);
VOID removeMemTainted(UINT64 address, UINT64 size);
VOID addMemTainted(UINT64 address, UINT64 offset);
VOID addMemTainted(UINT64 address, UINT64 size, UINT64 bitmap, UINT64 offset[]);

REG_TAINT* getTaintRegPointer(REG reg);
void pushTaintReg(REG reg, UINT64 bitmap, UINT64 offset[], UINT64 size);
bool taintReg(REG reg, UINT64 bitmap, UINT64 offset[]);
bool removeRegTainted(REG reg);

extern ofstream output;

#endif
