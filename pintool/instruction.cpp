#include <iostream>
#include <list>

#include "instruction.hpp"
#include "instrument.hpp"
#include "trace.hpp"

void initMemTaint(MEM_TAINT_MAP* map, ADDRINT addr, UINT32 size){
    map->bitmap = 0;

    for(UINT64 i = 0; i < 32; i++){
        map->offset[i] = -1;
    }

    for(UINT64 i = 0; i < size; i++){
        MEM_TAINT* tempMem;

        if((tempMem = getTaintMemPointer(addr + i))){
            map->bitmap |= (0x1 << i);
            map->offset[i] = tempMem->offset;            
        }
    }
}

void initMemTaint(MEM_TAINT_MAP* map1, ADDRINT addr1, MEM_TAINT_MAP* map2, ADDRINT addr2, UINT32 size, UINT32 count){
    map1->bitmap = 0;
    map2->bitmap = 0;

    for(UINT64 i = 0; i < 32; i++){
        map1->offset[i] = -1;
        map2->offset[i] = -1;
    }

    for(UINT64 i = 0; i < size*count; i++){
        MEM_TAINT* tempMem;

        if((tempMem = getTaintMemPointer(addr1+i))){
            map1->bitmap |= (0x1 << i);
            map1->offset[i] = tempMem->offset;
        }

        if((tempMem = getTaintMemPointer(addr2+i))){
            map2->bitmap |= (0x1 << i);
            map2->offset[i] = tempMem->offset;
        }    
    }
}

void traceUnsupport(ADDRINT insAddr, std::string insDis){
    output << "[Unsupport]" << " insDis: " << insDis << endl;
}

VOID taintMOVS(ADDRINT insAddr, string insDis, UINT32 opCount, ADDRINT memOp1, UINT32 readSize, ADDRINT memOp2, UINT32 writeSize)
{
    list<MEM_TAINT*>::iterator i;
    UINT64 readAddr = memOp1;
    UINT64 writeAddr = memOp2;

    if (opCount < 2) {
        return;
    }

    for (UINT64 i = 0; i < writeSize; i++){
        bool isReadMemTainted = checkAlreadyMemTainted(readAddr+i);
        bool isWriteMemTainted = checkAlreadyMemTainted(writeAddr+i);

        MEM_TAINT* tempMem = getTaintMemPointer(readAddr + i);

        // if read mem tainted -> taint write mem
        if(isReadMemTainted){
            addMemTainted(writeAddr+i, tempMem->offset);
        } 
        // if read mem not tainted && write mem tainted -> free memory
        else if(isWriteMemTainted){
            removeMemTainted(writeAddr+i);
        } 
        // if read mem not tainted && write mem not tainted -> do nothing
        else {
        }
    }
}

void taintRegReg(ADDRINT insAddr, string insDis, UINT32 opCount, REG reg1, REG reg2, ADDRINT val, UINT32 size)
{
    if(checkAlreadyRegTainted(reg1)){
        REG_TAINT* tempReg1 = getTaintRegPointer(reg1);

        taintReg(reg2, tempReg1->bitmap, tempReg1->offset);
        
        // printTraceLog(insAddr, insDis, tempReg1, val, size);
    } 
    // read reg not tainted
    else {
        // write reg tainted -> remove taint
        if(checkAlreadyRegTainted(reg2)){
            removeRegTainted(reg2);
        } 
        // write reg not tainted -> do nothing
        else{
        }
    }
}

VOID taintRegImm(ADDRINT insAddr, string insDis, UINT32 opCount, REG reg1, UINT32 size)
{
    if(checkAlreadyRegTainted(reg1)){
        // REG_TAINT* tempReg = getTaintRegPointer(reg1);

        // if(tempReg->bitmap != 0){
        //      printTraceLog(insAddr, insDis, tempReg, size);
        // }

        removeRegTainted(reg1);
    } 
}

VOID taintMemReg(ADDRINT insAddr, string insDis, UINT32 opCount, ADDRINT addr, REG reg1, ADDRINT val, UINT32 size)
{
    if(checkAlreadyRegTainted(reg1)){
        REG_TAINT* tempReg = getTaintRegPointer(reg1);

        for(UINT64 i = 0; i < size; i++){
            //taint mem if reg offset tainted
            if((tempReg->bitmap & (0x1 << i))){
                if(checkAlreadyMemTainted(addr+i)){
                    removeMemTainted(addr+i);
                }

                addMemTainted(addr+i, tempReg->offset[i]);
            }
            //remove mem taint if reg offset is not taint
            else{
                if(checkAlreadyMemTainted(addr+i)){
                    removeMemTainted(addr+i);
                }
            }
        }

        // if(tempReg->bitmap != 0){
        //     printTraceLog(insAddr, insDis, tempReg, val, size);
        // }
    } 
    else {
        for(UINT64 i = 0; i < size; i++){
            if(checkAlreadyMemTainted(addr+i)){
                removeMemTainted(addr+i);
            }
        }
    }
}

VOID taintRegMem(ADDRINT insAddr, string insDis, UINT32 opCount, ADDRINT addr, REG reg1, UINT32 size)
{
    UINT64 offset[32];

    for(UINT64 i=0; i < 32; i++) offset[i] = -1;

    UINT64 bitmap = 0;

    for (UINT64 i = 0; i < size; i++){
        
        // mem tainted && reg offset not tainted -> taint reg offset
        if(checkAlreadyMemTainted(addr+i)){
            MEM_TAINT* tempMem = getTaintMemPointer(addr + i);

            bitmap = bitmap | (0x1 << i);
            offset[i] = tempMem->offset;
        } 

    }

    if(bitmap != 0){
        taintReg(reg1, bitmap, offset);

        // REG_TAINT* tempReg = getTaintRegPointer(reg1);
        // printTraceLog(insAddr, insDis, tempReg, 0x0, size);
    } else {
        if(checkAlreadyRegTainted(reg1)){
            removeRegTainted(reg1);
        }
    }
}

VOID taintMemImm(ADDRINT insAddr, string insDis, UINT32 opCount, ADDRINT addr, UINT32 size)
{
    MEM_TAINT_MAP map;

    initMemTaint(&map, addr, size);
    
    // if(map.bitmap != 0){
    //     printTraceLog(insAddr, insDis, &map,size);
    // }

    for(UINT64 i = 0; i < size; i++){

        if(checkAlreadyMemTainted(addr+i)){
            removeMemTainted(addr+i);
        }
    }
}

/* [TODO] */
VOID taintMemMem(ADDRINT insAddr, string insDis, UINT32 opCount, ADDRINT readAddr, UINT32 readSize, ADDRINT writeAddr, UINT32 writeSize)
{
    for (UINT64 i = 0; i < writeSize; i++){

        bool isReadMemTainted = checkAlreadyMemTainted(readAddr+i);
        bool isWriteMemTainted = checkAlreadyMemTainted(writeAddr+i);

        MEM_TAINT* tempMem = getTaintMemPointer(readAddr + i);

        // if read mem tainted -> taint write mem
        if(isReadMemTainted){
            addMemTainted(writeAddr+i, tempMem->offset);
        } 
        // if read mem not tainted && write mem tainted -> free memory
        else if(isWriteMemTainted){
            removeMemTainted(writeAddr+i);
        } 
        // if read mem not tainted && write mem not tainted -> do nothing
        else {
        }
    }
}

void taintSTOS(ADDRINT insAddr, string insDis, UINT32 opCount, ADDRINT memOp, UINT32 writeSize)
{
    REG reg;
    UINT64 addr = memOp;

    switch(writeSize){
        #if defined(TARGET_IA32E)
        case REG_SIZE_8:
            reg = REG_RAX;
            break;
        #endif
        case REG_SIZE_4:
            reg = REG_EAX;
            break;
        case REG_SIZE_2:
            reg = REG_AX;
            break;
        case REG_SIZE_1:
            reg = REG_AL;
            break;
        default:
            //error
            return;
    }

    REG_TAINT* tempReg = getTaintRegPointer(reg);

    for (UINT64 i = 0; i < writeSize; i++){
        UINT64 regOffset = i;

        bool isMemTainted = checkAlreadyMemTainted(addr+i);
        bool isRegOffsetTainted = checkAlreadyRegTaintedOffset(reg, regOffset);

        // if reg offset not tainted && mem tainted  -> free memory
        if(!isRegOffsetTainted && isMemTainted){
            removeMemTainted(addr+i);
        }
        // if reg offset tainted && mem not tainted -> taint memory
        else if(isRegOffsetTainted && !isMemTainted){
            addMemTainted(addr+i, tempReg->offset[regOffset]);
        } 
        // if reg offset tainted && mem tainted     -> update taint offset
        else if(isRegOffsetTainted && isMemTainted){
            removeMemTainted(addr+i);
            addMemTainted(addr+i, tempReg->offset[regOffset]);
        } 
        // if reg offset not tainted && mem not tainted -> nothing
        else if(!isRegOffsetTainted && !isMemTainted){

        }
    }
}

VOID taintLODS(ADDRINT insAddr, string insDis, UINT32 opCount, ADDRINT memOp, UINT32 readSize)
{
    REG reg;
    UINT64 addr = memOp;

    switch(readSize){
        #if defined(TARGET_IA32E)
        case REG_SIZE_8:
            reg = REG_RAX;
            break;
        #endif
        case REG_SIZE_4:
            reg = REG_EAX;
            break;
        case REG_SIZE_2:
            reg = REG_AX;
            break;
        case REG_SIZE_1:
            reg = REG_AL;
            break;
        default:
            //error
            return;
    }

    UINT64 offset[32];

    for(UINT64 i=0; i < 32; i++) offset[i] = -1;

    UINT64 bitmap = 0;

    for (UINT64 i = 0; i < readSize; i++){
        bool isMemTainted = checkAlreadyMemTainted(addr+i);
        
        // mem tainted && reg offset not tainted -> taint reg offset
        if(isMemTainted){
            MEM_TAINT* tempMem = getTaintMemPointer(addr + i);

            bitmap = bitmap | (0x1 << i);
            offset[i] = tempMem->offset;
        }
    }

    taintReg(reg, bitmap, offset);
}

/* TODO */
VOID taintLEA(ADDRINT insAddr, string insDis, UINT32 opCount, REG reg1, UINT32 size)
{
    if(checkAlreadyRegTainted(reg1)){
        removeRegTainted(reg1);
    } 
}

VOID traceCMPRegReg(ADDRINT insAddr, string insDis, UINT32 opCount, REG reg1, ADDRINT val1, REG reg2, ADDRINT val2, UINT32 size)
{
    if(checkAlreadyRegTainted(reg1)){
        REG_TAINT* tempReg = getTaintRegPointer(reg1);

        // reg1, reg2 both tainted
        if(checkAlreadyRegTainted(reg2)){
            REG_TAINT* tempReg2 = getTaintRegPointer(reg2);

            if(tempReg->bitmap != 0 || tempReg2->bitmap != 0){
                printTraceLog(insAddr, insDis, tempReg, val1, tempReg2, val2, size);
            }

        // reg1 tainted
        } else {
            if(tempReg->bitmap != 0){
                printTraceLog(insAddr, insDis, tempReg, val1, (REG_TAINT*) NULL, val2, size);
            }
        }
    }
    // reg2 tainted
    else if(checkAlreadyRegTainted(reg2)){
        REG_TAINT* tempReg = getTaintRegPointer(reg2);

        if(tempReg->bitmap != 0){
            printTraceLog(insAddr, insDis, (REG_TAINT*) NULL, val1, tempReg, val2, size);
        }
    }
}

VOID tracePCMPRegReg(ADDRINT insAddr, string insDis, CONTEXT* ctx, UINT32 opCount, REG reg1, REG reg2, UINT32 size)
{
    UINT8 val1[REG_Size(reg1)];
    UINT8 val2[REG_Size(reg2)];

    for (UINT64 i = 0; i < REG_Size(reg1); i++){
        val1[i] = '\0';
        val2[i] = '\0';
    }

    PIN_GetContextRegval(ctx, reg1, val1);
    PIN_GetContextRegval(ctx, reg2, val2);

    if(checkAlreadyRegTainted(reg1)){
        REG_TAINT* tempReg = getTaintRegPointer(reg1);

        // reg1, reg2 both tainted
        if(checkAlreadyRegTainted(reg2)){
            REG_TAINT* tempReg2 = getTaintRegPointer(reg2);

            if(tempReg->bitmap != 0 || tempReg2->bitmap != 0){
                printTraceLog(insAddr, insDis, tempReg, val1, tempReg2, val2, REG_Size(reg1));
            }
        // reg1 tainted
        } else {
            if(tempReg->bitmap != 0){
                printTraceLog(insAddr, insDis, tempReg, val1, (REG_TAINT*) NULL, val2, REG_Size(reg1));
            }
        }
    }
    // reg2 tainted
    else if(checkAlreadyRegTainted(reg2)){
        REG_TAINT* tempReg = getTaintRegPointer(reg2);

        if(tempReg->bitmap != 0){
            printTraceLog(insAddr, insDis, (REG_TAINT*) NULL, val1, tempReg, val2, REG_Size(reg1));
        }
    }
}

VOID traceCMPRegImm(ADDRINT insAddr, string insDis, UINT32 opCount, REG reg1, ADDRINT val, UINT32 size, UINT64 imm)
{
    if(checkAlreadyRegTainted(reg1)){
        REG_TAINT* tempReg = getTaintRegPointer(reg1);

        if(tempReg->bitmap != 0){
            printTraceLog(insAddr, insDis, tempReg, val, imm, size);
        }
    } 
}

VOID traceCMPRegMem(ADDRINT insAddr, string insDis, UINT32 opCount, REG reg1, ADDRINT val, ADDRINT addr, UINT32 size)
{
    MEM_TAINT_MAP map;
    
    initMemTaint(&map, addr, size);

    if(checkAlreadyRegTainted(reg1)){
        REG_TAINT* tempReg = getTaintRegPointer(reg1);

        printTraceLog(insAddr, insDis, tempReg, val, &map, (UINT8*) addr, size);
    } else if(map.bitmap != 0){
        printTraceLog(insAddr, insDis, (REG_TAINT*) NULL, val, &map, (UINT8*) addr, size);
    }
}

VOID tracePCMPRegMem(ADDRINT insAddr, string insDis, CONTEXT* ctx, UINT32 opCount, REG reg1, ADDRINT addr, UINT32 size)
{
    UINT8 val[REG_Size(reg1)];

    for (UINT64 i = 0; i < REG_Size(reg1); i++){
        val[i] = '\0';
    }

    MEM_TAINT_MAP map;

    initMemTaint(&map, addr, size);
    
    if(checkAlreadyRegTainted(reg1)){
        REG_TAINT* tempReg = getTaintRegPointer(reg1);

        printTraceLog(insAddr, insDis, tempReg, val, &map, (UINT8*) addr, size);
    } else if(map.bitmap != 0){
        printTraceLog(insAddr, insDis, (REG_TAINT*) NULL, val, &map, (UINT8*) addr, size);
    }
}

VOID traceCMPMemReg(ADDRINT insAddr, string insDis, UINT32 opCount, ADDRINT addr, REG reg1, ADDRINT val, UINT32 size)
{
    MEM_TAINT_MAP map;

    initMemTaint(&map, addr, size);

    if(checkAlreadyRegTainted(reg1)){
        REG_TAINT* tempReg = getTaintRegPointer(reg1);

        printTraceLog(insAddr, insDis, &map, (UINT8*) addr, tempReg, val, size);
    } else if(map.bitmap != 0){
        printTraceLog(insAddr, insDis, &map, (UINT8*) addr, (REG_TAINT*) NULL, val, size);
    }
}

VOID traceCMPMemImm(ADDRINT insAddr, string insDis, UINT32 opCount, ADDRINT addr, UINT32 size, UINT64 imm)
{
    MEM_TAINT_MAP map;

    initMemTaint(&map, addr, size);

    if(map.bitmap != 0)
        printTraceLog(insAddr, insDis, &map, (UINT8*) addr, imm, size);
}

VOID traceCMPS(ADDRINT insAddr, string insDis, UINT32 opCount, BOOL isFirst , ADDRINT addr1, ADDRINT addr2, UINT32 size, UINT32 count)
{
    if(!isFirst){
        return ;
    }
    
    MEM_TAINT_MAP map1;
    MEM_TAINT_MAP map2;

    initMemTaint(&map1, addr1, &map2, addr2, size, count);
    
    if(map1.bitmap != 0 || map2.bitmap != 0){
        printTraceLog(insAddr, insDis, &map1, (UINT8*)addr1, &map2, (UINT8*)addr2, size*count);
    }
}

VOID traceArithRegReg(ADDRINT insAddr, string insDis, UINT32 opCount, REG reg1, ADDRINT val1, REG reg2, ADDRINT val2, UINT32 size)
{
    UINT64 offset[32];

    for(UINT64 i=0; i < 32; i++) offset[i] = -1;

    UINT64 bitmap = 0;

    if(checkAlreadyRegTainted(reg1)){
        REG_TAINT* tempReg1 = getTaintRegPointer(reg1);

        // reg1, reg2 both tainted
        if(checkAlreadyRegTainted(reg2)){
            REG_TAINT* tempReg2 = getTaintRegPointer(reg2);

            if(tempReg1->bitmap != 0 || tempReg2 != 0)
                printTraceLog(insAddr, insDis, tempReg1, val1, tempReg2, val2, size);

            for(UINT i=0; i < size; i++){
                if((tempReg1->bitmap & (0x1 << i)) == 0 && (tempReg2->bitmap & (0x1 << i)) != 0){
                    tempReg1->offset[i] = tempReg2->offset[i];
                }
            }

            tempReg1->bitmap |= tempReg2->bitmap;

        // reg1 tainted
        } else {
            if(tempReg1->bitmap != 0)
                printTraceLog(insAddr, insDis, tempReg1, val1, (REG_TAINT*) NULL, val2, size);
        }
    }
    // reg2 tainted
    else if(checkAlreadyRegTainted(reg2)){
        REG_TAINT* tempReg2 = getTaintRegPointer(reg2);

        taintReg(reg1, bitmap, offset);

        REG_TAINT* tempReg1 = getTaintRegPointer(reg1);

        printTraceLog(insAddr, insDis, tempReg1, val1, tempReg2, val2, size);

        for(UINT i=0; i < size; i++){
            if((tempReg1->bitmap & (0x1 << i)) == 0 && (tempReg2->bitmap & (0x1 << i)) != 0){
                tempReg1->offset[i] = tempReg2->offset[i];
            }
        }

        tempReg1->bitmap |= tempReg2->bitmap;
    }
}

VOID traceXORRegReg(ADDRINT insAddr, string insDis, UINT32 opCount, REG reg1, ADDRINT val1, REG reg2, ADDRINT val2, UINT32 size)
{
    if(checkAlreadyRegTainted(reg1)){
        REG_TAINT* tempReg = getTaintRegPointer(reg1);
        
        // if reg1 == reg2 -> free
        if(reg1 == reg2){
            removeRegTainted(reg1);
        }
        // reg1, reg2 both tainted
        else if(checkAlreadyRegTainted(reg2)){
            REG_TAINT* tempReg2 = getTaintRegPointer(reg2);

            if(tempReg->bitmap != 0 || tempReg2 != 0)
                printTraceLog(insAddr, insDis, tempReg, val1, tempReg2, val2, size);
        
        } 
        // reg1 tainted
        else {
            if(tempReg->bitmap != 0)
                printTraceLog(insAddr, insDis, tempReg, val1, (REG_TAINT*) NULL, val2, size);
        }
    }
    // reg2 tainted
    else if(checkAlreadyRegTainted(reg2)){
        REG_TAINT* tempReg = getTaintRegPointer(reg2);

        if(tempReg->bitmap != 0)
            printTraceLog(insAddr, insDis, (REG_TAINT*) NULL, val1, tempReg, val2, size);
    }
}

VOID traceArithRegImm(ADDRINT insAddr, string insDis, UINT32 opCount, REG reg1, ADDRINT val, UINT32 size, UINT64 imm)
{
    if(checkAlreadyRegTainted(reg1)){
        REG_TAINT* tempReg = getTaintRegPointer(reg1);

        if(tempReg->bitmap != 0)
            printTraceLog(insAddr, insDis, tempReg, val, imm, size);
    } 
}

VOID traceArithReg(ADDRINT insAddr, string insDis, UINT32 opCount, REG reg1, ADDRINT val, UINT32 size)
{
    if(checkAlreadyRegTainted(reg1)){
        REG_TAINT* tempReg = getTaintRegPointer(reg1);

        if(tempReg->bitmap != 0)
            printTraceLog(insAddr, insDis, tempReg, val, size);
    } 
}

VOID traceArithMemReg(ADDRINT insAddr, string insDis, UINT32 opCount, ADDRINT addr, REG reg1, ADDRINT val, UINT32 size)
{
    MEM_TAINT_MAP map;

    initMemTaint(&map, addr, size);

    if(checkAlreadyRegTainted(reg1)){
        REG_TAINT* tempReg = getTaintRegPointer(reg1);

        printTraceLog(insAddr, insDis, &map, (UINT8*)addr, tempReg, val, size);

    } else if(map.bitmap != 0){
        printTraceLog(insAddr, insDis, &map, (UINT8*)addr, (REG_TAINT*) NULL, val, size);
    }
}

VOID traceArithRegMem(ADDRINT insAddr, string insDis, UINT32 opCount, REG reg1, ADDRINT val, ADDRINT addr, UINT32 size)
{
    MEM_TAINT_MAP map;

    initMemTaint(&map, addr, size);

    if(checkAlreadyRegTainted(reg1)){
        REG_TAINT* tempReg = getTaintRegPointer(reg1);

        printTraceLog(insAddr, insDis, tempReg, val, &map, (UINT8*)addr, size);

        UINT64 bitmap = tempReg->bitmap | map.bitmap;

        for(UINT64 i = 0; i < size; i++){
            if((map.bitmap & (0x1 << i)) != 0x0){
                tempReg->offset[i] = map.offset[i];
            }
        }
        
        taintReg(reg1, bitmap, tempReg->offset);

    } else if(map.bitmap != 0){
        taintReg(reg1, map.bitmap, map.offset);
   
        printTraceLog(insAddr, insDis, (REG_TAINT*) NULL, val, &map, (UINT8*)addr, size);
    }
}

VOID traceArithMemImm(ADDRINT insAddr, string insDis, UINT32 opCount, ADDRINT addr, UINT32 size, UINT64 imm)
{
    MEM_TAINT_MAP map;

    initMemTaint(&map, addr, size);
    
    if(map.bitmap != 0)
        printTraceLog(insAddr, insDis, &map, (UINT8*) addr, imm, size);
}

VOID traceArithMem(ADDRINT insAddr, string insDis, UINT32 opCount, ADDRINT addr, UINT32 size)
{
    MEM_TAINT_MAP map;

    initMemTaint(&map, addr, size);
    
    if(map.bitmap != 0)
        printTraceLog(insAddr, insDis, &map, (UINT8*) addr, size);
}

VOID traceANDRegImm(ADDRINT insAddr, string insDis, UINT32 opCount, REG reg1, ADDRINT val, UINT32 size, UINT64 imm)
{
    if(checkAlreadyRegTainted(reg1)){
        REG_TAINT* tempReg = getTaintRegPointer(reg1);
        UINT64 bitmap = tempReg->bitmap;

        if(bitmap != 0){
            printTraceLog(insAddr, insDis, tempReg, val, imm, size);
        }

        for(UINT64 i=0; i < size; i++){    
            UINT64 byte = (imm >> (i*8)) & 0xff;

            if(byte == 0){
                bitmap &= ~(0x1 << i);
            }
        }

        if(bitmap != tempReg->bitmap){
            UINT64 offset[32];

            for(UINT64 i=0; i < 32; i++) {
                if((bitmap >> i) & 0x1){
                    offset[i] = tempReg->offset[i];
                } else{
                    offset[i] = -1;
                }
            }
            taintReg(reg1, bitmap, offset);
        }
    } 
}

VOID traceANDMemImm(ADDRINT insAddr, string insDis, UINT32 opCount, ADDRINT addr, UINT32 size, UINT64 imm)
{
    MEM_TAINT_MAP map;

    initMemTaint(&map, addr, size);

    if(map.bitmap != 0)
        printTraceLog(insAddr, insDis, &map, (UINT8*) addr, imm, size);
}

VOID traceORRegReg(ADDRINT insAddr, string insDis, UINT32 opCount, REG reg1, ADDRINT val1, REG reg2, ADDRINT val2, UINT32 size)
{
    UINT64 offset[32];

    for(UINT64 i=0; i < 32; i++) offset[i] = -1;

    UINT64 bitmap = 0;

    if(checkAlreadyRegTainted(reg2)){
        REG_TAINT* tempReg2 = getTaintRegPointer(reg2);

        if(!checkAlreadyRegTainted(reg1)){
            taintReg(reg1, bitmap, offset);
        }

        REG_TAINT* tempReg1 = getTaintRegPointer(reg1);

        printTraceLog(insAddr, insDis, tempReg1, val1, tempReg2, val2, size);

        for(UINT i=0; i < size; i++){
            if((tempReg1->bitmap & (0x1 << i)) == 0 && (tempReg2->bitmap & (0x1 << i)) != 0){
                tempReg1->offset[i] = tempReg2->offset[i];
            }
        }

        tempReg1->bitmap |= tempReg2->bitmap;
    }
    else if(checkAlreadyRegTainted(reg1)){
        REG_TAINT* tempReg = getTaintRegPointer(reg1);

        // reg1, reg2 both tainted
        if(checkAlreadyRegTainted(reg2)){
            REG_TAINT* tempReg2 = getTaintRegPointer(reg2);

            if(tempReg->bitmap != 0 || tempReg2 != 0)
                printTraceLog(insAddr, insDis, tempReg, val1, tempReg2, val2, size);

        // reg1 tainted
        } else {
            if(tempReg->bitmap != 0)
                printTraceLog(insAddr, insDis, tempReg, val1, (REG_TAINT*) NULL, val2, size);
        }
    }
}


VOID traceORMemReg(ADDRINT insAddr, string insDis, UINT32 opCount, ADDRINT addr, REG reg1, ADDRINT val, UINT32 size)
{
    MEM_TAINT_MAP map;
    
    initMemTaint(&map, addr, size);

    if(checkAlreadyRegTainted(reg1)){
        REG_TAINT* tempReg = getTaintRegPointer(reg1);

        printTraceLog(insAddr, insDis, &map, (UINT8*)addr, tempReg, val, size);

        for(UINT64 i = 0; i < size; i++){
            //taint mem if reg offset tainted 
            if((tempReg->bitmap & (0x1 << i))){

                if(checkAlreadyMemTainted(addr+i)){
                    removeMemTainted(addr+i);
                }

                addMemTainted(addr+i, tempReg->offset[i]);
            }
        }
    } else if(map.bitmap != 0){
        printTraceLog(insAddr, insDis, &map, (UINT8*)addr, (REG_TAINT*) NULL, val, size);
    }
}

VOID traceSHLRegImm(ADDRINT insAddr, string insDis, UINT32 opCount, REG reg1, ADDRINT val, UINT32 size, UINT64 imm)
{
    if(checkAlreadyRegTainted(reg1)){
        REG_TAINT* tempReg = getTaintRegPointer(reg1);

        if(tempReg->bitmap != 0)
            printTraceLog(insAddr, insDis, tempReg, val, imm, size);

        if ((imm % 8) == 0){
            UINT64 offset[32];
            UINT64 bitmap = 0;

            UINT64 count = (imm / 8);

            bitmap = tempReg->bitmap << count;

            for(UINT64 i=0; i < 32 - count; i++){
                offset[31 - i] = tempReg->offset[31 - i - count];
            }

            for(UINT64 i=0; i < count; i++){
                offset[i] = -1;
            }

            taintReg(reg1, bitmap, offset);
        } 
    } 
}

VOID traceSHLRegReg(ADDRINT insAddr, string insDis, UINT32 opCount, REG reg1, ADDRINT val, REG reg2, ADDRINT val2, UINT32 size)
{
    if(checkAlreadyRegTainted(reg1)){
        REG_TAINT* tempReg = getTaintRegPointer(reg1);
        REG_TAINT* tempReg2 = getTaintRegPointer(reg2);

        if(tempReg->bitmap != 0)
            printTraceLog(insAddr, insDis, tempReg, val, tempReg2, val2, size);

        if ((val2 % 8) == 0){
            UINT64 offset[32];
            UINT64 bitmap = 0;

            UINT64 count = (val2 / 8);

            bitmap = tempReg->bitmap << count;

            for(UINT64 i=0; i < 32 - count; i++){
                offset[31 - i] = tempReg->offset[31 - i - count];
            }

            for(UINT64 i=0; i < count; i++){
                offset[i] = -1;
            }

            taintReg(reg1, bitmap, offset);
        } 
    } 
}

VOID traceSHLMemReg(ADDRINT insAddr, string insDis, UINT32 opCount, ADDRINT addr, REG reg, ADDRINT val, UINT32 size)
{
    MEM_TAINT_MAP map;

    initMemTaint(&map, addr, size);

    if(map.bitmap != 0){
        REG_TAINT* tempReg = getTaintRegPointer(reg);

        printTraceLog(insAddr, insDis, &map, (UINT8*) addr, tempReg, val, size);

        UINT64 offset[32];
        UINT64 bitmap = 0;
        UINT64 count = (val / 8);

        bitmap = map.bitmap << count;

        for(UINT64 i=0; i < 32 - count; i++){
            offset[31 - i] = map.offset[31 - i - count];
        }

        for(UINT64 i=0; i < count; i++){
            offset[i] = -1;
        }

        for(UINT64 i=0; i < size; i++){
            if((bitmap & (1 << i)) != 0){
                addMemTainted(addr+i, offset[i]);
            } else{
                removeMemTainted(addr+i);
            }
        }
    }
}

VOID traceSHLMemImm(ADDRINT insAddr, string insDis, UINT32 opCount, ADDRINT addr, UINT32 size, UINT64 imm)
{
    MEM_TAINT_MAP map;

    initMemTaint(&map, addr, size);

    if(map.bitmap != 0){
        printTraceLog(insAddr, insDis, &map, (UINT8*) addr, imm, size);

        UINT64 offset[32];
        UINT64 bitmap = 0;
        UINT64 count = (imm / 8);

        bitmap = map.bitmap << count;

        for(UINT64 i=0; i < 32 - count; i++){
            offset[31 - i] = map.offset[31 - i - count];
        }

        for(UINT64 i=0; i < count; i++){
            offset[i] = -1;
        }

        for(UINT64 i=0; i < size; i++){
            if((bitmap & (1 << i)) != 0){
                addMemTainted(addr+i, offset[i]);
            } else{
                removeMemTainted(addr+i);
            }
        }
    }
}

VOID traceSHRRegImm(ADDRINT insAddr, string insDis, UINT32 opCount, REG reg1, ADDRINT val, UINT32 size, UINT64 imm)
{
    if(checkAlreadyRegTainted(reg1)){
        REG_TAINT* tempReg = getTaintRegPointer(reg1);

        if(tempReg->bitmap != 0)
            printTraceLog(insAddr, insDis, tempReg, val, imm, size);

        if((imm % 8) == 0){
            UINT64 offset[32];
            UINT64 bitmap = 0;

            UINT64 count = (imm / 8);

            bitmap = tempReg->bitmap >> count;

            for(UINT64 i=0; i < 32 - count; i++){
                offset[i] = tempReg->offset[i + count];
            }

            for(UINT64 i=0; i < count; i++){
                offset[31-i] = -1;
            }

            taintReg(reg1, bitmap, offset);            
        } 
    } 
}

VOID traceSHRRegReg(ADDRINT insAddr, string insDis, UINT32 opCount, REG reg1, ADDRINT val, REG reg2, ADDRINT val2, UINT32 size)
{
    if(checkAlreadyRegTainted(reg1)){
        REG_TAINT* tempReg = getTaintRegPointer(reg1);
        REG_TAINT* tempReg2 = getTaintRegPointer(reg2);

        if(tempReg->bitmap != 0)
            printTraceLog(insAddr, insDis, tempReg, val, tempReg2, val2, size);

        if((val2 % 8) == 0){
            UINT64 offset[32];
            UINT64 bitmap = 0;

            UINT64 count = (val2 / 8);

            bitmap = tempReg->bitmap >> count;

            for(UINT64 i=0; i < 32 - count; i++){
                offset[i] = tempReg->offset[i + count];
            }

            for(UINT64 i=0; i < count; i++){
                offset[31-i] = -1;
            }

            taintReg(reg1, bitmap, offset);            
        } 
    } 
}

VOID traceSHRMemReg(ADDRINT insAddr, string insDis, UINT32 opCount, ADDRINT addr, REG reg, ADDRINT val, UINT32 size)
{
    MEM_TAINT_MAP map;

    initMemTaint(&map, addr, size);

    if(map.bitmap != 0){
        REG_TAINT* tempReg = getTaintRegPointer(reg);

        printTraceLog(insAddr, insDis, &map, (UINT8*) addr, tempReg, val, size);

        UINT64 offset[32];
        UINT64 bitmap = 0;
        UINT64 count = (val / 8);

        bitmap = map.bitmap >> count;

        for(UINT64 i=0; i < 32 - count; i++){
            offset[i] = map.offset[i + count];
        }

        for(UINT64 i=0; i < count; i++){
            offset[31-i] = -1;
        }

        for(UINT64 i=0; i < size; i++){
            if((bitmap & (1 << i)) != 0){
                addMemTainted(addr+i, offset[i]);
            } else{
                removeMemTainted(addr+i);
            }
        }
    }
}

VOID traceSHRMemImm(ADDRINT insAddr, string insDis, UINT32 opCount, ADDRINT addr, UINT32 size, UINT64 imm)
{
    MEM_TAINT_MAP map;

    initMemTaint(&map, addr, size);

    if(map.bitmap != 0){
        printTraceLog(insAddr, insDis, &map, (UINT8*) addr, imm, size);

        UINT64 offset[32];
        UINT64 bitmap = 0;
        UINT64 count = (imm / 8);

        bitmap = map.bitmap << count;

        for(UINT64 i=0; i < 32 - count; i++){
            offset[i] = map.offset[i + count];
        }

        for(UINT64 i=0; i < count; i++){
            offset[31-i] = -1;
        }

        for(UINT64 i=0; i < size; i++){
            if((bitmap & (1 << i)) != 0){
                addMemTainted(addr+i, offset[i]);
            } else{
                removeMemTainted(addr+i);
            }
        }
    }
}

//????
VOID traceMULRegRegImm(ADDRINT insAddr, string insDis, UINT32 opCount, REG reg1, ADDRINT val, REG reg2, ADDRINT val2, UINT32 size, UINT64 imm)
{
    //output << hex << "[MUL]\t" << insAddr << ": " << insDis;
    //output << " " << REG_StringShort(reg1) << " " << REG_StringShort(reg2) << " " << imm << endl;
    //output << hex << "\t\t\tsize: " << size << endl; 

    if(checkAlreadyRegTainted(reg2)){
        // REG_TAINT* tempReg = getTaintRegPointer(reg1);
        REG_TAINT* tempReg2 = getTaintRegPointer(reg2);

        if(tempReg2->bitmap != 0)
            printTraceLog(insAddr, insDis, NULL, val, tempReg2, val2, imm, size);

        // taintReg(reg1, bitmap, offset);            
        taintReg(reg1, tempReg2->bitmap, tempReg2->offset);
    } 
}

VOID traceMULRegMemImm(ADDRINT insAddr, string insDis, UINT32 opCount, REG reg1, ADDRINT val, ADDRINT addr, UINT32 size, UINT64 imm)
{
    MEM_TAINT_MAP map;
    
    initMemTaint(&map, addr, size);

    if(map.bitmap != 0){
        printTraceLog(insAddr, insDis, NULL, val, &map, (UINT8*) addr, imm, size);
        taintReg(reg1, map.bitmap, map.offset);
    } 
}

VOID traceXCHGRegReg(ADDRINT insAddr, string insDis, UINT32 opCount, REG reg1, ADDRINT val1, REG reg2, ADDRINT val2, UINT32 size)
{
    REG_TAINT* tempReg1 = getTaintRegPointer(reg1);
    REG_TAINT* tempReg2 = getTaintRegPointer(reg2);

    UINT64 bitmap = 0;
    UINT64 offset[32];

    if(tempReg1 != NULL) {
      bitmap = tempReg1->bitmap;
      for(UINT64 i=0; i < 32; i++) offset[i] = tempReg1->offset[i];
    }

    if(tempReg1 != NULL || tempReg2 != NULL)
        printTraceLog(insAddr, insDis, tempReg1, val1, tempReg2, val2, size);

    if(tempReg2 != NULL)
        taintReg(reg1, tempReg2->bitmap, tempReg2->offset);
    else
        removeRegTainted(reg1);

    if(tempReg1 != NULL)
        taintReg(reg2, bitmap, offset);
    else
        removeRegTainted(reg2);
}

VOID traceXCHGMemReg(ADDRINT insAddr, string insDis, UINT32 opCount, ADDRINT addr, REG reg1, ADDRINT val, UINT32 size)
{
    MEM_TAINT_MAP map;

    initMemTaint(&map, addr, size);

    REG_TAINT* tempReg = getTaintRegPointer(reg1);

    if(map.bitmap != 0 || tempReg != NULL){
        printTraceLog(insAddr, insDis, &map, (UINT8*)addr, tempReg, val, size);
    }

    if(tempReg != NULL)
        addMemTainted(addr, size, tempReg->bitmap, tempReg->offset);
    else
        removeMemTainted(addr, size);

    if(map.bitmap != 0)
        taintReg(reg1, map.bitmap, map.offset);
    else
        removeRegTainted(reg1);
}

VOID traceXCHGRegMem(ADDRINT insAddr, string insDis, UINT32 opCount, REG reg1, ADDRINT val, ADDRINT addr, UINT32 size)
{
    MEM_TAINT_MAP map;

    initMemTaint(&map, addr, size);

    REG_TAINT* tempReg = getTaintRegPointer(reg1);

    if(map.bitmap != 0 || tempReg != NULL){
        printTraceLog(insAddr, insDis, &map, (UINT8*)addr, tempReg, val, size);
    }

    if(tempReg != NULL)
        addMemTainted(addr, size, tempReg->bitmap, tempReg->offset);
    else
        removeMemTainted(addr, size);

    if(map.bitmap != 0)
        taintReg(reg1, map.bitmap, map.offset);
    else
        removeRegTainted(reg1);
}

/* temp cmpxchg handler */
VOID traceCMPXCHGRegReg(ADDRINT insAddr, string insDis, CONTEXT* ctx, UINT32 opCount, REG reg1, ADDRINT val1, REG reg2, ADDRINT val2, UINT32 size)
{
    UINT64 valAX = 0;
    REG regAX = REG_EAX;

    switch(size){
        case REG_SIZE_1:
            regAX = REG_AL;
            break;
        case REG_SIZE_2:
            regAX = REG_AX;
            break;
        case REG_SIZE_4:
            regAX = REG_EAX;
            break;
        #if defined(TARGET_IA32E)
        case REG_SIZE_8:
            regAX = REG_RAX;
            break;
        #endif
        default:
            break;
    }
    
    PIN_GetContextRegval(ctx, regAX, (UINT8*) &valAX);

    REG_TAINT* tempReg = getTaintRegPointer(reg1);
    REG_TAINT* tempReg2 = getTaintRegPointer(reg2);

    if(checkAlreadyRegTainted(reg1)){
        // reg1, reg2 both tainted
        if(checkAlreadyRegTainted(reg2)){
            if(tempReg->bitmap != 0 || tempReg2->bitmap != 0)
                printTraceLog(insAddr, insDis, tempReg, val1, tempReg2, val2, size);

            if(valAX == val1)
                taintReg(reg1, tempReg2->bitmap, tempReg2->offset);
            else
                taintReg(regAX, tempReg->bitmap, tempReg->offset);

        } 
        // reg1 tainted
        else {
            if(tempReg->bitmap != 0)
                printTraceLog(insAddr, insDis, tempReg, val1, (REG_TAINT*) NULL, val2, size);

            if(valAX == val1)
                removeRegTainted(reg1);
            else
                taintReg(regAX, tempReg->bitmap, tempReg->offset);
        }
    }
    // reg2 tainted
    else if(checkAlreadyRegTainted(reg2)){
        if(tempReg2->bitmap != 0)
            printTraceLog(insAddr, insDis, (REG_TAINT*) NULL, val1, tempReg2, val2, size);

        if(valAX == val1)
            taintReg(reg1, tempReg2->bitmap, tempReg2->offset);
    }
}

VOID traceCMPXCHGMemReg(ADDRINT insAddr, string insDis, CONTEXT* ctx, UINT32 opCount, ADDRINT addr, REG reg1, ADDRINT val, UINT32 size)
{
    UINT64 valAX = 0;
    REG regAX = REG_EAX;

    switch(size){
        case REG_SIZE_1:
            regAX = REG_AL;
            break;
        case REG_SIZE_2:
            regAX = REG_AX;
            break;
        case REG_SIZE_4:
            regAX = REG_EAX;
            break;
        #if defined(TARGET_IA32E)
        case REG_SIZE_8:
            regAX = REG_RAX;
            break;
        #endif
        default:
            break;
    }
    
    PIN_GetContextRegval(ctx, regAX, (UINT8*) &valAX);

    REG_TAINT* tempReg = getTaintRegPointer(reg1);

    MEM_TAINT_MAP map;

    initMemTaint(&map, addr, size);

    if(checkAlreadyRegTainted(reg1)){
        printTraceLog(insAddr, insDis, &map, (UINT8*) addr, tempReg, val, size);

        if(!memcmp((UINT8*) &valAX, (UINT8*) addr, size))          
            addMemTainted(addr, size, tempReg->bitmap, tempReg->offset);
        else{
            if(map.bitmap != 0)
                taintReg(regAX, map.bitmap, map.offset);
            else
                removeRegTainted(regAX);
        }
    } 
    else if(map.bitmap != 0){
        printTraceLog(insAddr, insDis, &map, (UINT8*) addr, (REG_TAINT*) NULL, val, size);

        if(!memcmp((UINT8*) &valAX, (UINT8*) addr, size))
            addMemTainted(addr, size, tempReg->bitmap, tempReg->offset);
    }
}

VOID traceBSWAP(ADDRINT insAddr, string insDis, UINT32 opCount, REG reg1, ADDRINT val, UINT32 size)
{
    if(checkAlreadyRegTainted(reg1)){
        REG_TAINT* tempReg = getTaintRegPointer(reg1);

        UINT64 bitmap = 0;
        UINT64 offset[32];

        bitmap = tempReg->bitmap;

        for(UINT64 i=0; i < 32; i++) offset[i] = -1;

        for(UINT64 i=0; i < size; i++) offset[i] = tempReg->offset[size-i-1];

        taintReg(reg1, bitmap, offset);

        tempReg = getTaintRegPointer(reg1);

        if(tempReg->bitmap != 0)
            printTraceLog(insAddr, insDis, tempReg, val, size);
    }
}