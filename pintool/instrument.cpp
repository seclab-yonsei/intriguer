#include <stdio.h>
#include <iostream>
#include <fstream>
#include <list>

#if !defined(TARGET_WINDOWS)
#include <sys/syscall.h>
#endif

#include "instrument.hpp"

using namespace std;

list<MEM_TAINT_BASE*> listBaseAddress;
vector<MEM_TAINT*> addressTainted;

list<REG_TAINT*> regsTainted;

bool checkAlreadyRegTaintedOffset(REG reg, UINT8 offset){
    list<REG_TAINT*>::iterator i;

    for(i = regsTainted.begin(); i != regsTainted.end(); i++){
        if((*i)->reg == reg){
            UINT64 bitmap = (*i)->bitmap;

            if((bitmap & (0x1 << offset)) != 0){
                return true;
            }
        }
    }

    return false;
}

bool checkAlreadyRegTainted(REG reg)
{
    list<REG_TAINT*>::iterator i;

    for(i = regsTainted.begin(); i != regsTainted.end(); i++){
        if((*i)->reg == reg){
            return true;
        }
    }

    return false;
}

MEM_TAINT* getTaintMemPointer(UINT64 address){
    list<MEM_TAINT_BASE*>::iterator itBase;

    for(itBase = listBaseAddress.begin(); itBase != listBaseAddress.end(); itBase++){
        if((*itBase)->base == (address & 0xfffffffffffff000)){
           return (*itBase)->vecAddressTainted[address & 0xfff];
        }
    }

    return NULL;
}

bool checkAlreadyMemTainted(UINT64 address){
    list<MEM_TAINT_BASE*>::iterator itBase;

    for(itBase = listBaseAddress.begin(); itBase != listBaseAddress.end(); itBase++){
        if((*itBase)->base == (address & 0xfffffffffffff000)){
            if((*itBase)->vecAddressTainted[address & 0xfff] != NULL)
                return true;
            else
                return false;
        }
    }

    return false;
}

VOID removeMemTainted(UINT64 address)
{
    list<MEM_TAINT_BASE*>::iterator itBase;

    for(itBase = listBaseAddress.begin(); itBase != listBaseAddress.end(); itBase++){
        if((*itBase)->base == (address & 0xfffffffffffff000)){
           if((*itBase)->vecAddressTainted[address & 0xfff] != NULL){
                delete (*itBase)->vecAddressTainted[address & 0xfff];
                (*itBase)->vecAddressTainted[address & 0xfff] = NULL;
            }
        }
    }
}

VOID removeMemTainted(UINT64 address, UINT64 size)
{
    for(UINT64 i = 0; i < size; i++){
        removeMemTainted(address+i);
    }
}

VOID addMemTainted(UINT64 address, UINT64 offset)
{
    MEM_TAINT* mem = new MEM_TAINT;
    list<MEM_TAINT_BASE*>::iterator itBase;

    mem->address = address;
    mem->offset = offset;

    if((signed)mem->offset != -1){
        for(itBase = listBaseAddress.begin(); itBase != listBaseAddress.end(); itBase++){
            if((*itBase)->base == (address & 0xfffffffffffff000)){
                if((*itBase)->vecAddressTainted[address & 0xfff] != NULL){
                    delete (*itBase)->vecAddressTainted[address & 0xfff];
                    (*itBase)->vecAddressTainted[address & 0xfff] = NULL;
                }
                (*itBase)->vecAddressTainted[address & 0xfff] = mem;

                break;
            }
        }

        if(itBase == listBaseAddress.end()){
            MEM_TAINT_BASE* mem_base = new MEM_TAINT_BASE;

            mem_base->base = address & 0xfffffffffffff000;

            mem_base->vecAddressTainted.resize(0x1000);

            mem_base->vecAddressTainted[address & 0xfff] = mem;

            listBaseAddress.push_front(mem_base);
        }
    }
}

VOID addMemTainted(UINT64 address, UINT64 size, UINT64 bitmap, UINT64 offset[]){
    for(UINT64 i = 0; i < size; i++){

        //taint mem if reg offset tainted
        if((bitmap & (0x1 << i))){

            if(checkAlreadyMemTainted(address+i)){
                removeMemTainted(address+i);
            }

            addMemTainted(address+i, offset[i]);
        }
        //remove mem taint if reg offset is not taint
        else{
            if(checkAlreadyMemTainted(address+i)){
                removeMemTainted(address+i);
            }
        }
    }
}

REG_TAINT* getTaintRegPointer(REG reg){
    list<REG_TAINT*>::iterator i;

    for(i = regsTainted.begin(); i != regsTainted.end(); i++){
        if((*i)->reg == reg){
            return *i;
        }
    }

    return NULL;
}

void pushTaintReg(REG reg, UINT64 bitmap, UINT64 offset[], UINT64 size){
    REG_TAINT* tempReg = new REG_TAINT;

    tempReg->reg = reg;
    tempReg->bitmap = bitmap & ((0x1 << size) - 1);

    for(UINT64 i = 0; i < size; i++){
        if((tempReg->bitmap & (0x1 << i)) != 0)
            tempReg->offset[i] = offset[i];
        else
            tempReg->offset[i] = -1;
    }

    regsTainted.push_front(tempReg);

}

/* TODO: correctly handle registers*/
bool taintReg(REG reg, UINT64 bitmap, UINT64 offset[]){
    if(checkAlreadyRegTainted(reg) == true){
        removeRegTainted(reg);
    }

    REG_TAINT* tempReg;

    switch(reg){
        #if defined(TARGET_IA32E)
        case REG_RAX:  
            pushTaintReg(REG_RAX, bitmap, offset, REG_SIZE_8);
        #endif

        case REG_EAX:  
            pushTaintReg(REG_EAX, bitmap, offset, REG_SIZE_4);

        case REG_AX:   
            pushTaintReg(REG_AX, bitmap, offset, REG_SIZE_2);
     
        case REG_AH:   
            tempReg = new REG_TAINT;
            tempReg->reg = REG_AH;
            tempReg->bitmap = bitmap & 0x2;
            if(tempReg->bitmap != 0)
                tempReg->offset[1] = offset[1];
            else
                tempReg->offset[1] = -1;

            regsTainted.push_front(tempReg);

        case REG_AL: 
            if(reg == REG_AH) break;

            tempReg = new REG_TAINT;
            tempReg->reg = REG_AL;
            tempReg->bitmap = bitmap & 0x1;
            if(tempReg->bitmap != 0)
                tempReg->offset[0] = offset[0];
            else
                tempReg->offset[0] = -1;
            regsTainted.push_front(tempReg);
            
            break;

        #if defined(TARGET_IA32E)
        case REG_RBX:  
            pushTaintReg(REG_RBX, bitmap, offset, REG_SIZE_8);
        #endif

        case REG_EBX: 
            pushTaintReg(REG_EBX, bitmap, offset, REG_SIZE_4);

        case REG_BX: 
            pushTaintReg(REG_BX, bitmap, offset, REG_SIZE_2);

        case REG_BH:  
            tempReg = new REG_TAINT;
            tempReg->reg = REG_BH;
            tempReg->bitmap = bitmap & 0x2;
            if(tempReg->bitmap != 0)
                tempReg->offset[1] = offset[1];
            else
                tempReg->offset[1] = -1;
            regsTainted.push_front(tempReg);

        case REG_BL: 
            if(reg == REG_BH) break;

            tempReg = new REG_TAINT;
            tempReg->reg = REG_BL;
            tempReg->bitmap = bitmap & 0x1;
            if(tempReg->bitmap != 0)
                tempReg->offset[0] = offset[0];
            else
                tempReg->offset[0] = -1;
            regsTainted.push_front(tempReg);

            break;

        #if defined(TARGET_IA32E)
        case REG_RCX: 
            pushTaintReg(REG_RCX, bitmap, offset, REG_SIZE_8);
        #endif

        case REG_ECX: 
            pushTaintReg(REG_ECX, bitmap, offset, REG_SIZE_4);

        case REG_CX: 
            pushTaintReg(REG_CX, bitmap, offset, REG_SIZE_2);

        case REG_CH:  
            tempReg = new REG_TAINT;
            tempReg->reg = REG_CH;
            tempReg->bitmap = bitmap & 0x2;
            if(tempReg->bitmap != 0)
                tempReg->offset[1] = offset[1];
            else
                tempReg->offset[1] = -1;
            regsTainted.push_front(tempReg);

        case REG_CL: 
            if(reg == REG_CH) break;

            tempReg = new REG_TAINT;
            tempReg->reg = REG_CL;
            tempReg->bitmap = bitmap & 0x1;
            if(tempReg->bitmap != 0)
                tempReg->offset[0] = offset[0];
            else
                tempReg->offset[0] = -1;
            regsTainted.push_front(tempReg);

            break;

        #if defined(TARGET_IA32E)
        case REG_RDX:  
            pushTaintReg(REG_RDX, bitmap, offset, REG_SIZE_8);
        #endif

        case REG_EDX:  
            pushTaintReg(REG_EDX, bitmap, offset, REG_SIZE_4);

        case REG_DX:  
            pushTaintReg(REG_DX, bitmap, offset, REG_SIZE_2);

        case REG_DH:   
            tempReg = new REG_TAINT;
            tempReg->reg = REG_DH;
            tempReg->bitmap = bitmap & 0x2;
            if(tempReg->bitmap != 0)
                tempReg->offset[1] = offset[1];
            else
                tempReg->offset[1] = -1;
            regsTainted.push_front(tempReg);

        case REG_DL:
            if(reg == REG_DH) break;

            tempReg = new REG_TAINT;
            tempReg->reg = REG_DL;
            tempReg->bitmap = bitmap & 0x1;
            if(tempReg->bitmap != 0)
                tempReg->offset[0] = offset[0];
            else
                tempReg->offset[0] = -1;
            regsTainted.push_front(tempReg);
            break;

        #if defined(TARGET_IA32E)
        case REG_RDI: 
            pushTaintReg(REG_RDI, bitmap, offset, REG_SIZE_8);
        #endif

        case REG_EDI: 
            pushTaintReg(REG_EDI, bitmap, offset, REG_SIZE_4);

        case REG_DI:  
            pushTaintReg(REG_DI, bitmap, offset, REG_SIZE_2);

        #if defined(TARGET_IA32E)
        case REG_DIL:  
            pushTaintReg(REG_DIL, bitmap, offset, REG_SIZE_1);
        #endif

            break;

        #if defined(TARGET_IA32E)
        case REG_RSI:
            pushTaintReg(REG_RSI, bitmap, offset, REG_SIZE_8);
        #endif

        case REG_ESI: 
            pushTaintReg(REG_ESI, bitmap, offset, REG_SIZE_4);

        case REG_SI:  
            pushTaintReg(REG_SI, bitmap, offset, REG_SIZE_2);

        #if defined(TARGET_IA32E)
        case REG_SIL: 
            pushTaintReg(REG_SIL, bitmap, offset, REG_SIZE_1);
        #endif

            break;

        #if defined(TARGET_IA32E)
        case REG_R8:
            pushTaintReg(REG_R8, bitmap, offset, REG_SIZE_8);

        case REG_R8D: 
            pushTaintReg(REG_R8D, bitmap, offset, REG_SIZE_4);

        case REG_R8W:  
            pushTaintReg(REG_R8W, bitmap, offset, REG_SIZE_2);

        case REG_R8B: 
            pushTaintReg(REG_R8B, bitmap, offset, REG_SIZE_1);

            break;

        case REG_R9:
            pushTaintReg(REG_R9, bitmap, offset, REG_SIZE_8);

        case REG_R9D: 
            pushTaintReg(REG_R9D, bitmap, offset, REG_SIZE_4);

        case REG_R9W:  
            pushTaintReg(REG_R9W, bitmap, offset, REG_SIZE_2);

        case REG_R9B: 
            pushTaintReg(REG_R9B, bitmap, offset, REG_SIZE_1);

            break;

        case REG_R10:
            pushTaintReg(REG_R10, bitmap, offset, REG_SIZE_8);

        case REG_R10D: 
            pushTaintReg(REG_R10D, bitmap, offset, REG_SIZE_4);

        case REG_R10W:  
            pushTaintReg(REG_R10W, bitmap, offset, REG_SIZE_2);

        case REG_R10B: 
            pushTaintReg(REG_R10B, bitmap, offset, REG_SIZE_1);

            break;

        case REG_R11:
            pushTaintReg(REG_R11, bitmap, offset, REG_SIZE_8);

        case REG_R11D: 
            pushTaintReg(REG_R11D, bitmap, offset, REG_SIZE_4);

        case REG_R11W:  
            pushTaintReg(REG_R11W, bitmap, offset, REG_SIZE_2);

        case REG_R11B: 
            pushTaintReg(REG_R11B, bitmap, offset, REG_SIZE_1);

            break;

        case REG_R12:
            pushTaintReg(REG_R12, bitmap, offset, REG_SIZE_8);

        case REG_R12D: 
            pushTaintReg(REG_R12D, bitmap, offset, REG_SIZE_4);

        case REG_R12W:  
            pushTaintReg(REG_R12W, bitmap, offset, REG_SIZE_2);

        case REG_R12B: 
            pushTaintReg(REG_R12B, bitmap, offset, REG_SIZE_1);

            break;

        case REG_R13:
            pushTaintReg(REG_R13, bitmap, offset, REG_SIZE_8);

        case REG_R13D: 
            pushTaintReg(REG_R13D, bitmap, offset, REG_SIZE_4);

        case REG_R13W:  
            pushTaintReg(REG_R13W, bitmap, offset, REG_SIZE_2);

        case REG_R13B: 
            pushTaintReg(REG_R13B, bitmap, offset, REG_SIZE_1);

            break;

        case REG_R14:
            pushTaintReg(REG_R14, bitmap, offset, REG_SIZE_8);

        case REG_R14D: 
            pushTaintReg(REG_R14D, bitmap, offset, REG_SIZE_4);

        case REG_R14W:  
            pushTaintReg(REG_R14W, bitmap, offset, REG_SIZE_2);

        case REG_R14B: 
            pushTaintReg(REG_R14B, bitmap, offset, REG_SIZE_1);

            break;

        case REG_R15:
            pushTaintReg(REG_R15, bitmap, offset, REG_SIZE_8);

        case REG_R15D: 
            pushTaintReg(REG_R15D, bitmap, offset, REG_SIZE_4);

        case REG_R15W:  
            pushTaintReg(REG_R15W, bitmap, offset, REG_SIZE_2);

        case REG_R15B: 
            pushTaintReg(REG_R15B, bitmap, offset, REG_SIZE_1);

            break;
        #endif

        case REG_YMM0: 
            pushTaintReg(REG_YMM0, bitmap, offset, REG_SIZE_32);

        case REG_XMM0: 
            pushTaintReg(REG_XMM0, bitmap, offset, REG_SIZE_16);

            break;

        case REG_YMM1: 
            pushTaintReg(REG_YMM1, bitmap, offset, REG_SIZE_32);

        case REG_XMM1: 
            pushTaintReg(REG_XMM1, bitmap, offset, REG_SIZE_16);

            break;

        case REG_YMM2: 
            pushTaintReg(REG_YMM2, bitmap, offset, REG_SIZE_32);

        case REG_XMM2: 
            pushTaintReg(REG_XMM2, bitmap, offset, REG_SIZE_16);

            break;

        case REG_YMM3: 
            pushTaintReg(REG_YMM3, bitmap, offset, REG_SIZE_32);

        case REG_XMM3: 
            pushTaintReg(REG_XMM3, bitmap, offset, REG_SIZE_16);

            break;

        case REG_YMM4: 
            pushTaintReg(REG_YMM4, bitmap, offset, REG_SIZE_32);

        case REG_XMM4: 
            pushTaintReg(REG_XMM4, bitmap, offset, REG_SIZE_16);

            break;

        case REG_YMM5: 
            pushTaintReg(REG_YMM5, bitmap, offset, REG_SIZE_32);

        case REG_XMM5: 
            pushTaintReg(REG_XMM5, bitmap, offset, REG_SIZE_16);

            break;

        case REG_YMM6: 
            pushTaintReg(REG_YMM6, bitmap, offset, REG_SIZE_32);

        case REG_XMM6: 
            pushTaintReg(REG_XMM6, bitmap, offset, REG_SIZE_16);

            break;

        case REG_YMM7: 
            pushTaintReg(REG_YMM7, bitmap, offset, REG_SIZE_32);

        case REG_XMM7: 
            pushTaintReg(REG_XMM7, bitmap, offset, REG_SIZE_16);

            break;

        #if defined(TARGET_IA32E)
        case REG_YMM8: 
            pushTaintReg(REG_YMM8, bitmap, offset, REG_SIZE_32);

        case REG_XMM8: 
            pushTaintReg(REG_XMM8, bitmap, offset, REG_SIZE_16);

            break;

        case REG_YMM9: 
            pushTaintReg(REG_YMM9, bitmap, offset, REG_SIZE_32);

        case REG_XMM9: 
            pushTaintReg(REG_XMM9, bitmap, offset, REG_SIZE_16);

            break;

        case REG_YMM10: 
            pushTaintReg(REG_YMM10, bitmap, offset, REG_SIZE_32);

        case REG_XMM10: 
            pushTaintReg(REG_XMM10, bitmap, offset, REG_SIZE_16);

            break;

        case REG_YMM11: 
            pushTaintReg(REG_YMM11, bitmap, offset, REG_SIZE_32);

        case REG_XMM11: 
            pushTaintReg(REG_XMM11, bitmap, offset, REG_SIZE_16);

            break;

        case REG_YMM12: 
            pushTaintReg(REG_YMM12, bitmap, offset, REG_SIZE_32);

        case REG_XMM12: 
            pushTaintReg(REG_XMM12, bitmap, offset, REG_SIZE_16);

            break;

        case REG_YMM13: 
            pushTaintReg(REG_YMM13, bitmap, offset, REG_SIZE_32);

        case REG_XMM13: 
            pushTaintReg(REG_XMM13, bitmap, offset, REG_SIZE_16);

            break;

        case REG_YMM14: 
            pushTaintReg(REG_YMM14, bitmap, offset, REG_SIZE_32);

        case REG_XMM14: 
            pushTaintReg(REG_XMM14, bitmap, offset, REG_SIZE_16);

            break;

        case REG_YMM15: 
            pushTaintReg(REG_YMM15, bitmap, offset, REG_SIZE_32);

        case REG_XMM15: 
            pushTaintReg(REG_XMM15, bitmap, offset, REG_SIZE_16);

            break;
        #endif

        #if defined(TARGET_IA32E)
        case REG_RBP:
            pushTaintReg(REG_RBP, bitmap, offset, REG_SIZE_8);
        #endif

        case REG_EBP:
            pushTaintReg(REG_EBP, bitmap, offset, REG_SIZE_4);

            break;

        default:
          return false;
    }

    return true;
}

bool removeRegTainted(REG reg){
    REG_TAINT* tempReg;

    switch(reg){

        #if defined(TARGET_IA32E)
        case REG_RAX:
            tempReg = getTaintRegPointer(REG_RAX);
            regsTainted.remove(tempReg);
            delete tempReg;
        #endif

        case REG_EAX:  
            tempReg = getTaintRegPointer(REG_EAX);
            regsTainted.remove(tempReg);
            delete tempReg;

        case REG_AX:   
            tempReg = getTaintRegPointer(REG_AX);
            regsTainted.remove(tempReg);
            delete tempReg;

        case REG_AH:  
            tempReg = getTaintRegPointer(REG_AH);
            regsTainted.remove(tempReg);
            delete tempReg;

        case REG_AL:
            if(reg == REG_AH) break;

            tempReg = getTaintRegPointer(REG_AL);
            regsTainted.remove(tempReg);
            delete tempReg;
            
            break;

        #if defined(TARGET_IA32E)
        case REG_RBX:
            tempReg = getTaintRegPointer(REG_RBX);
            regsTainted.remove(tempReg);
            delete tempReg;
        #endif

        case REG_EBX: 
            tempReg = getTaintRegPointer(REG_EBX);
            regsTainted.remove(tempReg);
            delete tempReg;

        case REG_BX:  
            tempReg = getTaintRegPointer(REG_BX);
            regsTainted.remove(tempReg);
            delete tempReg;

        case REG_BH:   
            tempReg = getTaintRegPointer(REG_BH);
            regsTainted.remove(tempReg);
            delete tempReg;

        case REG_BL: 
            if(reg == REG_BH) break;

            tempReg = getTaintRegPointer(REG_BL);
            regsTainted.remove(tempReg);
            delete tempReg;

            break;

        #if defined(TARGET_IA32E)
        case REG_RCX: 
            tempReg = getTaintRegPointer(REG_RCX);
            regsTainted.remove(tempReg);
            delete tempReg;
        #endif

        case REG_ECX:  
            tempReg = getTaintRegPointer(REG_ECX);
            regsTainted.remove(tempReg);
            delete tempReg;

        case REG_CX: 
            tempReg = getTaintRegPointer(REG_CX);
            regsTainted.remove(tempReg);
            delete tempReg;

        case REG_CH:  
            tempReg = getTaintRegPointer(REG_CH);
            regsTainted.remove(tempReg);
            delete tempReg;

        case REG_CL:  
            if(reg == REG_CH) break;
            tempReg = getTaintRegPointer(REG_CL);
            regsTainted.remove(tempReg);
            delete tempReg;
            
            break;

        #if defined(TARGET_IA32E)
        case REG_RDX: 
            tempReg = getTaintRegPointer(REG_RDX);
            regsTainted.remove(tempReg);
            delete tempReg;
        #endif

        case REG_EDX: 
            tempReg = getTaintRegPointer(REG_EDX);
            regsTainted.remove(tempReg);
            delete tempReg;

        case REG_DX:  
            tempReg = getTaintRegPointer(REG_DX);
            regsTainted.remove(tempReg);
            delete tempReg;

        case REG_DH:   
            tempReg = getTaintRegPointer(REG_DH);
            regsTainted.remove(tempReg);
            delete tempReg;

        case REG_DL:   
            if(reg == REG_DH) break;

            tempReg = getTaintRegPointer(REG_DL);
            regsTainted.remove(tempReg);
            delete tempReg;

            break;

        #if defined(TARGET_IA32E)
        case REG_RDI: 
            tempReg = getTaintRegPointer(REG_RDI);
            regsTainted.remove(tempReg);
            delete tempReg;
        #endif

        case REG_EDI:  
            tempReg = getTaintRegPointer(REG_EDI);
            regsTainted.remove(tempReg);
            delete tempReg;

        case REG_DI:  
            tempReg = getTaintRegPointer(REG_DI);
            regsTainted.remove(tempReg);
            delete tempReg;

        #if defined(TARGET_IA32E)
        case REG_DIL: 
            tempReg = getTaintRegPointer(REG_DIL);
            regsTainted.remove(tempReg);
            delete tempReg;
        #endif

            break;

        #if defined(TARGET_IA32E)
        case REG_RSI: 
            tempReg = getTaintRegPointer(REG_RSI);
            regsTainted.remove(tempReg);
            delete tempReg;
        #endif

        case REG_ESI: 
            tempReg = getTaintRegPointer(REG_ESI);
            regsTainted.remove(tempReg);
            delete tempReg;

        case REG_SI:  
            tempReg = getTaintRegPointer(REG_SI);
            regsTainted.remove(tempReg);
            delete tempReg;

        #if defined(TARGET_IA32E)
        case REG_SIL: 
            tempReg = getTaintRegPointer(REG_SIL);
            regsTainted.remove(tempReg);
            delete tempReg;
        #endif

            break;

        #if defined(TARGET_IA32E)
        case REG_R8: 
            tempReg = getTaintRegPointer(REG_R8);
            regsTainted.remove(tempReg);
            delete tempReg;

        case REG_R8D: 
            tempReg = getTaintRegPointer(REG_R8D);
            regsTainted.remove(tempReg);
            delete tempReg;

        case REG_R8W:  
            tempReg = getTaintRegPointer(REG_R8W);
            regsTainted.remove(tempReg);
            delete tempReg;

        case REG_R8B: 
            tempReg = getTaintRegPointer(REG_R8B);
            regsTainted.remove(tempReg);
            delete tempReg;

            break;

        case REG_R9: 
            tempReg = getTaintRegPointer(REG_R9);
            regsTainted.remove(tempReg);
            delete tempReg;

        case REG_R9D: 
            tempReg = getTaintRegPointer(REG_R9D);
            regsTainted.remove(tempReg);
            delete tempReg;

        case REG_R9W:  
            tempReg = getTaintRegPointer(REG_R9W);
            regsTainted.remove(tempReg);
            delete tempReg;

        case REG_R9B: 
            tempReg = getTaintRegPointer(REG_R9B);
            regsTainted.remove(tempReg);
            delete tempReg;

            break;

        case REG_R10: 
            tempReg = getTaintRegPointer(REG_R10);
            regsTainted.remove(tempReg);
            delete tempReg;

        case REG_R10D: 
            tempReg = getTaintRegPointer(REG_R10D);
            regsTainted.remove(tempReg);
            delete tempReg;

        case REG_R10W:  
            tempReg = getTaintRegPointer(REG_R10W);
            regsTainted.remove(tempReg);
            delete tempReg;

        case REG_R10B: 
            tempReg = getTaintRegPointer(REG_R10B);
            regsTainted.remove(tempReg);
            delete tempReg;

            break;

        case REG_R11: 
            tempReg = getTaintRegPointer(REG_R11);
            regsTainted.remove(tempReg);
            delete tempReg;

        case REG_R11D: 
            tempReg = getTaintRegPointer(REG_R11D);
            regsTainted.remove(tempReg);
            delete tempReg;

        case REG_R11W:  
            tempReg = getTaintRegPointer(REG_R11W);
            regsTainted.remove(tempReg);
            delete tempReg;

        case REG_R11B: 
            tempReg = getTaintRegPointer(REG_R11B);
            regsTainted.remove(tempReg);
            delete tempReg;

            break;

        case REG_R12: 
            tempReg = getTaintRegPointer(REG_R12);
            regsTainted.remove(tempReg);
            delete tempReg;

        case REG_R12D: 
            tempReg = getTaintRegPointer(REG_R12D);
            regsTainted.remove(tempReg);
            delete tempReg;

        case REG_R12W:  
            tempReg = getTaintRegPointer(REG_R12W);
            regsTainted.remove(tempReg);
            delete tempReg;

        case REG_R12B: 
            tempReg = getTaintRegPointer(REG_R12B);
            regsTainted.remove(tempReg);
            delete tempReg;

            break;

        case REG_R13: 
            tempReg = getTaintRegPointer(REG_R13);
            regsTainted.remove(tempReg);
            delete tempReg;

        case REG_R13D: 
            tempReg = getTaintRegPointer(REG_R13D);
            regsTainted.remove(tempReg);
            delete tempReg;

        case REG_R13W:  
            tempReg = getTaintRegPointer(REG_R13W);
            regsTainted.remove(tempReg);
            delete tempReg;

        case REG_R13B: 
            tempReg = getTaintRegPointer(REG_R13B);
            regsTainted.remove(tempReg);
            delete tempReg;

            break;

        case REG_R14: 
            tempReg = getTaintRegPointer(REG_R14);
            regsTainted.remove(tempReg);
            delete tempReg;

        case REG_R14D: 
            tempReg = getTaintRegPointer(REG_R14D);
            regsTainted.remove(tempReg);
            delete tempReg;

        case REG_R14W:  
            tempReg = getTaintRegPointer(REG_R14W);
            regsTainted.remove(tempReg);
            delete tempReg;

        case REG_R14B: 
            tempReg = getTaintRegPointer(REG_R14B);
            regsTainted.remove(tempReg);
            delete tempReg;

            break;

        case REG_R15: 
            tempReg = getTaintRegPointer(REG_R15);
            regsTainted.remove(tempReg);
            delete tempReg;

        case REG_R15D: 
            tempReg = getTaintRegPointer(REG_R15D);
            regsTainted.remove(tempReg);
            delete tempReg;

        case REG_R15W:  
            tempReg = getTaintRegPointer(REG_R15W);
            regsTainted.remove(tempReg);
            delete tempReg;

        case REG_R15B: 
            tempReg = getTaintRegPointer(REG_R15B);
            regsTainted.remove(tempReg);
            delete tempReg;

            break;
        #endif

        case REG_YMM0: 
            tempReg = getTaintRegPointer(REG_YMM0);
            regsTainted.remove(tempReg);
            delete tempReg;

        case REG_XMM0: 
            tempReg = getTaintRegPointer(REG_XMM0);
            regsTainted.remove(tempReg);
            delete tempReg;

            break;

        case REG_YMM1: 
            tempReg = getTaintRegPointer(REG_YMM1);
            regsTainted.remove(tempReg);
            delete tempReg;

        case REG_XMM1: 
            tempReg = getTaintRegPointer(REG_XMM1);
            regsTainted.remove(tempReg);
            delete tempReg;

            break;

        case REG_YMM2: 
            tempReg = getTaintRegPointer(REG_YMM2);
            regsTainted.remove(tempReg);
            delete tempReg;

        case REG_XMM2: 
            tempReg = getTaintRegPointer(REG_XMM2);
            regsTainted.remove(tempReg);
            delete tempReg;

            break;

        case REG_YMM3: 
            tempReg = getTaintRegPointer(REG_YMM3);
            regsTainted.remove(tempReg);
            delete tempReg;

        case REG_XMM3: 
            tempReg = getTaintRegPointer(REG_XMM3);
            regsTainted.remove(tempReg);
            delete tempReg;

            break;

        case REG_YMM4: 
            tempReg = getTaintRegPointer(REG_YMM4);
            regsTainted.remove(tempReg);
            delete tempReg;

        case REG_XMM4: 
            tempReg = getTaintRegPointer(REG_XMM4);
            regsTainted.remove(tempReg);
            delete tempReg;

            break;

        case REG_YMM5: 
            tempReg = getTaintRegPointer(REG_YMM5);
            regsTainted.remove(tempReg);
            delete tempReg;

        case REG_XMM5: 
            tempReg = getTaintRegPointer(REG_XMM5);
            regsTainted.remove(tempReg);
            delete tempReg;

            break;

        case REG_YMM6: 
            tempReg = getTaintRegPointer(REG_YMM6);
            regsTainted.remove(tempReg);
            delete tempReg;

        case REG_XMM6: 
            tempReg = getTaintRegPointer(REG_XMM6);
            regsTainted.remove(tempReg);
            delete tempReg;

            break;

        case REG_YMM7: 
            tempReg = getTaintRegPointer(REG_YMM7);
            regsTainted.remove(tempReg);
            delete tempReg;

        case REG_XMM7: 
            tempReg = getTaintRegPointer(REG_XMM7);
            regsTainted.remove(tempReg);
            delete tempReg;

            break;

        #if defined(TARGET_IA32E)
        case REG_YMM8: 
            tempReg = getTaintRegPointer(REG_YMM8);
            regsTainted.remove(tempReg);
            delete tempReg;

        case REG_XMM8: 
            tempReg = getTaintRegPointer(REG_XMM8);
            regsTainted.remove(tempReg);
            delete tempReg;

            break;

        case REG_YMM9: 
            tempReg = getTaintRegPointer(REG_YMM9);
            regsTainted.remove(tempReg);
            delete tempReg;

        case REG_XMM9: 
            tempReg = getTaintRegPointer(REG_XMM9);
            regsTainted.remove(tempReg);
            delete tempReg;

            break;

        case REG_YMM10: 
            tempReg = getTaintRegPointer(REG_YMM10);
            regsTainted.remove(tempReg);
            delete tempReg;

        case REG_XMM10: 
            tempReg = getTaintRegPointer(REG_XMM10);
            regsTainted.remove(tempReg);
            delete tempReg;

            break;

        case REG_YMM11: 
            tempReg = getTaintRegPointer(REG_YMM11);
            regsTainted.remove(tempReg);
            delete tempReg;

        case REG_XMM11: 
            tempReg = getTaintRegPointer(REG_XMM11);
            regsTainted.remove(tempReg);
            delete tempReg;

            break;

        case REG_YMM12: 
            tempReg = getTaintRegPointer(REG_YMM12);
            regsTainted.remove(tempReg);
            delete tempReg;

        case REG_XMM12: 
            tempReg = getTaintRegPointer(REG_XMM12);
            regsTainted.remove(tempReg);
            delete tempReg;

            break;

        case REG_YMM13: 
            tempReg = getTaintRegPointer(REG_YMM13);
            regsTainted.remove(tempReg);
            delete tempReg;

        case REG_XMM13: 
            tempReg = getTaintRegPointer(REG_XMM13);
            regsTainted.remove(tempReg);
            delete tempReg;

            break;

        case REG_YMM14: 
            tempReg = getTaintRegPointer(REG_YMM14);
            regsTainted.remove(tempReg);
            delete tempReg;

        case REG_XMM14: 
            tempReg = getTaintRegPointer(REG_XMM14);
            regsTainted.remove(tempReg);
            delete tempReg;

            break;

        case REG_YMM15: 
            tempReg = getTaintRegPointer(REG_YMM15);
            regsTainted.remove(tempReg);
            delete tempReg;

        case REG_XMM15: 
            tempReg = getTaintRegPointer(REG_XMM15);
            regsTainted.remove(tempReg);
            delete tempReg;

            break;
        #endif

        #if defined(TARGET_IA32E)
        case REG_RBP:
            tempReg = getTaintRegPointer(REG_RBP);
            regsTainted.remove(tempReg);
            delete tempReg;
        #endif

        case REG_EBP:
            tempReg = getTaintRegPointer(REG_EBP);
            regsTainted.remove(tempReg);
            delete tempReg;

            break;

        default:
          return false;
    }

    return true;
}