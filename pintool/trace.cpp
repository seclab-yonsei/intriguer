#include "trace.hpp"

ofstream trace;

void printTraceLogReg(REG_TAINT* reg, UINT64 size){
    trace << "{";

    if(reg != NULL){
        for(UINT64 i=0; i < size; i++){
            if((reg->bitmap & (0x1 << i)) != 0)
                trace << "0x" << reg->offset[i];

            trace << ",";
        }
    }

    trace << "}";
}

void printTraceLogMem(MEM_TAINT_MAP* map, UINT64 size){
    trace << "{";

    if(map != NULL){
        for(UINT64 i=0; i < size; i++){
            if((map->bitmap & (0x1 << i)) != 0)
                trace << "0x" << map->offset[i];

            trace << ",";
        }
    }

    trace << "}";
}

//print value
void printTraceLogVal(UINT8* val, UINT64 size){
    for(UINT64 c=0; c < size; c++){
        trace << setw(2) << setfill('0') << hex << int(*(val+c));
    }
}

//trace reg
void printTraceLog(UINT64 insAddr, string insDis, REG_TAINT* reg, UINT64 val, UINT64 size){
    trace << hex << "0x" << insAddr << "." << insDis << ".";

    printTraceLogReg(reg, size);

    trace << ".";

    printTraceLogVal((UINT8*)&val, size);

    trace << "." << endl;
}

//trace reg imm
void printTraceLog(UINT64 insAddr, string insDis, REG_TAINT* reg, UINT64 val, UINT64 imm, UINT64 size){
    trace << hex << "0x" << insAddr << "." << insDis << ".";

    printTraceLogReg(reg, size);

    trace << ".";

    printTraceLogVal((UINT8*)&val, size);

    trace << ".";

    printTraceLogVal((UINT8*)&imm, size);

    trace << "." << endl;
}

//trace reg reg
void printTraceLog(UINT64 insAddr, string insDis, REG_TAINT* reg, UINT64 val1, REG_TAINT* reg2, UINT64 val2, UINT64 size){
    trace << hex << "0x" << insAddr << "." << insDis << ".";

    printTraceLogReg(reg, size);
    printTraceLogReg(reg2, size);

    trace << ".";

    printTraceLogVal((UINT8*)&val1, size);

    trace << ".";    
    
    printTraceLogVal((UINT8*)&val2, size);

    trace << "." << endl;
}

//trace reg reg imm
void printTraceLog(UINT64 insAddr, string insDis, REG_TAINT* reg, UINT64 val, REG_TAINT* reg2, UINT64 val2, UINT64 imm, UINT64 size){
    trace << hex << "0x" << insAddr << "." << insDis << ".";

    printTraceLogReg(reg, size);
    printTraceLogReg(reg2, size);

    trace << ".";

    printTraceLogVal((UINT8*)&val, size);

    trace << ".";

    printTraceLogVal((UINT8*)&val2, size);

    trace << ".";

    printTraceLogVal((UINT8*)&imm, size);

    trace << "." << endl;
}

//trace reg mem imm
void printTraceLog(UINT64 insAddr, string insDis, REG_TAINT* reg, UINT64 val, MEM_TAINT_MAP* map, UINT8* val2, UINT64 imm, UINT64 size){
    trace << hex << "0x" << insAddr << "." << insDis << ".";

    printTraceLogReg(reg, size);
    printTraceLogMem(map, size);

    trace << ".";

    printTraceLogVal((UINT8*)&val, size);

    trace << ".";

    printTraceLogVal(val2, size);

    trace << ".";

    printTraceLogVal((UINT8*)&imm, size);

    trace << "." << endl;
}

//trace reg mem
void printTraceLog(UINT64 insAddr, string insDis, REG_TAINT* reg, UINT64 val1, MEM_TAINT_MAP* map, UINT8* val2, UINT64 size){
    trace << hex << "0x" << insAddr << "." << insDis << ".";

    printTraceLogReg(reg, size);
    printTraceLogMem(map, size);

    trace << ".";

    printTraceLogVal((UINT8*)&val1, size);

    trace << ".";

    printTraceLogVal(val2, size);

    trace << "." << endl;
}

//trace mem reg
void printTraceLog(UINT64 insAddr, string insDis, MEM_TAINT_MAP* map, UINT8* val1, REG_TAINT* reg, UINT64 val2, UINT64 size){
    trace << hex << "0x" << insAddr << "." << insDis << ".";

    printTraceLogMem(map, size);
    printTraceLogReg(reg, size);

    trace << ".";

    printTraceLogVal(val1, size);

    trace << ".";

    printTraceLogVal((UINT8*)&val2, size);
    
    trace << "." << endl;
}

//trace mem mem
void printTraceLog(UINT64 insAddr, string insDis, MEM_TAINT_MAP* map1, UINT8* val1, MEM_TAINT_MAP* map2, UINT8* val2, UINT64 size){
    trace << hex << "0x" << insAddr << "." << insDis << ".";

    printTraceLogMem(map1, size);
    printTraceLogMem(map2, size);

    trace << ".";

    printTraceLogVal(val1, size);

    trace << ".";

    printTraceLogVal(val2, size);

    trace << "." << endl;
}

//trace mem
void printTraceLog(UINT64 insAddr, string insDis, MEM_TAINT_MAP* map, UINT8* val,UINT64 size){
    trace << hex << "0x" << insAddr << "." << insDis << ".";

    printTraceLogMem(map, size);

    trace << ".";

    printTraceLogVal(val, size); 

    trace << "." << endl;
}

//trace mem imm
void printTraceLog(UINT64 insAddr, string insDis, MEM_TAINT_MAP* map, UINT8* val1, UINT64 val2, UINT64 size){
    trace << hex << "0x" << insAddr << "." << insDis << ".";

    printTraceLogMem(map, size);

    trace << ".";

    printTraceLogVal(val1, size);

    trace << ".";

    printTraceLogVal((UINT8*)&val2, size);

    trace << "." << endl;
}

//trace reg reg SIMD
void printTraceLog(UINT64 insAddr, string insDis, REG_TAINT* reg, UINT8* val1, REG_TAINT* reg2, UINT8* val2, UINT64 size){
    trace << hex << "0x" << insAddr << "." << insDis << ".";

    printTraceLogReg(reg, size);
    printTraceLogReg(reg2, size);

    trace << ".";

    printTraceLogVal(val1, size);

    trace << ".";    
    
    printTraceLogVal(val2, size);

    trace << "." << endl;
}

//trace reg mem SIMD
void printTraceLog(UINT64 insAddr, string insDis, REG_TAINT* reg, UINT8* val1, MEM_TAINT_MAP* map, UINT8* val2, UINT64 size){
    trace << hex << "0x" << insAddr << "." << insDis << ".";

    printTraceLogReg(reg, size);
    printTraceLogMem(map, size);

    trace << ".";

    printTraceLogVal(val1, size);

    trace << ".";

    printTraceLogVal(val2, size);

    trace << "." << endl;
}