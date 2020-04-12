#include <iostream>

#include "analysis.hpp"
#include "instruction.hpp"
#include "syscall.hpp"

VOID Instruction(INS ins, VOID *v)
{
    if(!isTaintStart) return;

    xed_iclass_enum_t ins_indx = (xed_iclass_enum_t)INS_Opcode(ins);

    switch (ins_indx){

    case XED_ICLASS_MOVSQ:
    case XED_ICLASS_MOVSD:
    case XED_ICLASS_MOVSW:
    case XED_ICLASS_MOVSB:
        INS_InsertCall(
            ins, IPOINT_BEFORE, (AFUNPTR)taintMOVS,
            IARG_ADDRINT, INS_Address(ins),
            IARG_PTR, new string(INS_Disassemble(ins)),
            IARG_UINT32, INS_OperandCount(ins),
            IARG_MEMORYREAD_EA,
            IARG_UINT32, INS_MemoryReadSize(ins),
            IARG_MEMORYWRITE_EA,
            IARG_UINT32, INS_MemoryWriteSize(ins),
            IARG_END);
        break;

    case XED_ICLASS_STOSQ:
    case XED_ICLASS_STOSD:
    case XED_ICLASS_STOSW:
    case XED_ICLASS_STOSB:

        INS_InsertCall(
            ins, IPOINT_BEFORE, (AFUNPTR)taintSTOS,
            IARG_ADDRINT, INS_Address(ins),
            IARG_PTR, new string(INS_Disassemble(ins)),
            IARG_UINT32, INS_OperandCount(ins),
            IARG_MEMORYWRITE_EA,
            IARG_UINT32, INS_MemoryWriteSize(ins),
            IARG_END);

        break;

    case XED_ICLASS_LODSQ:
    case XED_ICLASS_LODSD:
    case XED_ICLASS_LODSW:
    case XED_ICLASS_LODSB:

        INS_InsertCall(
            ins, IPOINT_BEFORE, (AFUNPTR)taintLODS,
            IARG_ADDRINT, INS_Address(ins),
            IARG_PTR, new string(INS_Disassemble(ins)),
            IARG_UINT32, INS_OperandCount(ins),
            IARG_MEMORYREAD_EA,
            IARG_UINT32, INS_MemoryReadSize(ins),
            IARG_END);

        break;

    case XED_ICLASS_CMPSQ:
    case XED_ICLASS_CMPSD:
    case XED_ICLASS_CMPSW:
    case XED_ICLASS_CMPSB:

        if(INS_RepPrefix(ins)){
            INS_InsertCall(
                ins, IPOINT_BEFORE, (AFUNPTR)traceCMPS,
                IARG_ADDRINT, INS_Address(ins),
                IARG_PTR, new string(INS_Disassemble(ins)),
                IARG_UINT32, INS_OperandCount(ins),
                IARG_FIRST_REP_ITERATION,
                IARG_MEMORYREAD_EA,
                IARG_MEMORYREAD2_EA ,
                IARG_UINT32, INS_MemoryReadSize(ins),
                IARG_REG_VALUE, INS_RepCountRegister(ins),
                IARG_END);
        }
        else{
            INS_InsertCall(
                ins, IPOINT_BEFORE, (AFUNPTR)traceCMPS,
                IARG_ADDRINT, INS_Address(ins),
                IARG_PTR, new string(INS_Disassemble(ins)),
                IARG_UINT32, INS_OperandCount(ins),
                IARG_BOOL, true,
                IARG_MEMORYREAD_EA,
                IARG_MEMORYREAD2_EA,
                IARG_UINT32, INS_MemoryReadSize(ins),
                IARG_UINT32, 1,
                IARG_END);        
        }

        break;

    /* TODO */
    case XED_ICLASS_CALL_NEAR:
        break;

    case XED_ICLASS_JMP:
        break;

    case XED_ICLASS_LEAVE:
        break;

    case XED_ICLASS_RET_NEAR:
    case XED_ICLASS_RET_FAR:

        break;

    case XED_ICLASS_NOP:
        break;

    case XED_ICLASS_CMP:
    case XED_ICLASS_TEST:
        if(INS_MemoryOperandCount(ins) == 0){
            // cmp reg, reg
            if(!INS_OperandIsImmediate(ins, OP_1)){
                if(REG_is_xmm_ymm_zmm(INS_RegR(ins, OP_0)) || REG_is_mm(INS_RegR(ins, OP_0))){
                    INS_InsertCall(
                        ins, IPOINT_BEFORE, (AFUNPTR)traceCMPRegReg,
                        IARG_ADDRINT, INS_Address(ins),
                        IARG_PTR, new string(INS_Disassemble(ins)),
                        IARG_UINT32, INS_OperandCount(ins),
                        IARG_UINT32, INS_RegR(ins, OP_0),
                        IARG_ADDRINT, 0,
                        IARG_UINT32, INS_RegR(ins, OP_1),
                        IARG_ADDRINT, 0,
                        IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                        IARG_END);
                }
                else{
                    INS_InsertCall(
                        ins, IPOINT_BEFORE, (AFUNPTR)traceCMPRegReg,
                        IARG_ADDRINT, INS_Address(ins),
                        IARG_PTR, new string(INS_Disassemble(ins)),
                        IARG_UINT32, INS_OperandCount(ins),
                        IARG_UINT32, INS_RegR(ins, OP_0),
                        IARG_REG_VALUE, INS_RegR(ins, OP_0),
                        IARG_UINT32, INS_RegR(ins, OP_1),
                        IARG_REG_VALUE, INS_RegR(ins, OP_1),
                        IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                        IARG_END);
                }
            } 
            // cmp reg, imm
            else{
                if(REG_is_xmm_ymm_zmm(INS_RegR(ins, OP_0)) || REG_is_mm(INS_RegR(ins, OP_0))){
                    INS_InsertCall(
                        ins, IPOINT_BEFORE, (AFUNPTR)traceCMPRegImm,
                        IARG_ADDRINT, INS_Address(ins),
                        IARG_PTR, new string(INS_Disassemble(ins)),
                        IARG_UINT32, INS_OperandCount(ins),
                        IARG_UINT32, INS_RegR(ins, OP_0),
                        IARG_ADDRINT, 0,
                        IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                        IARG_UINT64, INS_OperandImmediate(ins, OP_1),
                        IARG_END);
                } else{
                    INS_InsertCall(
                        ins, IPOINT_BEFORE, (AFUNPTR)traceCMPRegImm,
                        IARG_ADDRINT, INS_Address(ins),
                        IARG_PTR, new string(INS_Disassemble(ins)),
                        IARG_UINT32, INS_OperandCount(ins),
                        IARG_UINT32, INS_RegR(ins, OP_0),
                        IARG_REG_VALUE, INS_RegR(ins, OP_0),
                        IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                        IARG_UINT64, INS_OperandImmediate(ins, OP_1),
                        IARG_END);
                }
            }
        } else {
            //cmp reg, mem
            if(INS_OperandIsReg(ins, OP_0)){
                if(REG_is_xmm_ymm_zmm(INS_RegR(ins, OP_0)) || REG_is_mm(INS_RegR(ins, OP_0))){
                    INS_InsertCall(
                        ins, IPOINT_BEFORE, (AFUNPTR)traceCMPRegMem,
                        IARG_ADDRINT, INS_Address(ins),
                        IARG_PTR, new string(INS_Disassemble(ins)),
                        IARG_UINT32, INS_OperandCount(ins),
                        IARG_UINT32, INS_RegR(ins, OP_0),
                        IARG_ADDRINT, 0,
                        IARG_MEMORYREAD_EA,
                        IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                        IARG_END);
                }
                else{
                    INS_InsertCall(
                        ins, IPOINT_BEFORE, (AFUNPTR)traceCMPRegMem,
                        IARG_ADDRINT, INS_Address(ins),
                        IARG_PTR, new string(INS_Disassemble(ins)),
                        IARG_UINT32, INS_OperandCount(ins),
                        IARG_UINT32, INS_RegR(ins, OP_0),
                        IARG_REG_VALUE, INS_RegR(ins, OP_0),
                        IARG_MEMORYREAD_EA,
                        IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                        IARG_END);
                }
            }
            //cmp mem, reg
            else if(INS_OperandIsReg(ins, 1)){
                if(REG_is_xmm_ymm_zmm(INS_RegR(ins, OP_0)) || REG_is_mm(INS_RegR(ins, OP_0))){
                    INS_InsertCall(
                        ins, IPOINT_BEFORE, (AFUNPTR)traceCMPMemReg,
                        IARG_ADDRINT, INS_Address(ins),
                        IARG_PTR, new string(INS_Disassemble(ins)),
                        IARG_UINT32, INS_OperandCount(ins),
                        IARG_MEMORYREAD_EA,
                        IARG_UINT32, INS_RegR(ins, OP_1),
                        IARG_ADDRINT, 0,
                        IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                        IARG_END);
                }
                else{
                    INS_InsertCall(
                        ins, IPOINT_BEFORE, (AFUNPTR)traceCMPMemReg,
                        IARG_ADDRINT, INS_Address(ins),
                        IARG_PTR, new string(INS_Disassemble(ins)),
                        IARG_UINT32, INS_OperandCount(ins),
                        IARG_MEMORYREAD_EA,
                        IARG_UINT32, INS_OperandReg(ins, OP_1),
                        IARG_REG_VALUE, INS_OperandReg(ins, OP_1),
                        IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                        IARG_END);
                }
            }
            //cmp mem, imm
            else{
                INS_InsertCall(
                    ins, IPOINT_BEFORE, (AFUNPTR)traceCMPMemImm,
                    IARG_ADDRINT, INS_Address(ins),
                    IARG_PTR, new string(INS_Disassemble(ins)),
                    IARG_UINT32, INS_OperandCount(ins),
                    IARG_MEMORYREAD_EA,
                    IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                    IARG_UINT64, INS_OperandImmediate(ins, OP_1),
                    IARG_END);
            }
        }

        break;

    case XED_ICLASS_PCMPEQB:
    case XED_ICLASS_PCMPEQD:
    case XED_ICLASS_PCMPEQW:
    case XED_ICLASS_PCMPEQQ:

    case XED_ICLASS_PCMPGTB:
    case XED_ICLASS_PCMPGTW:
    case XED_ICLASS_PCMPGTD:
    case XED_ICLASS_PCMPGTQ:
        if(INS_MemoryOperandCount(ins) == 0){
            // pcmpeq reg, reg
            if(!INS_OperandIsImmediate(ins, OP_1)){
                INS_InsertCall(
                    ins, IPOINT_BEFORE, (AFUNPTR)tracePCMPRegReg,
                    IARG_ADDRINT, INS_Address(ins),
                    IARG_PTR, new string(INS_Disassemble(ins)),
                    IARG_CONTEXT,
                    IARG_UINT32, INS_OperandCount(ins),
                    IARG_UINT32, INS_RegR(ins, OP_0),
                    IARG_UINT32, INS_RegR(ins, OP_1),
                    IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                    IARG_END);
            } 
            else{
                INS_InsertCall(
                    ins, IPOINT_BEFORE, (AFUNPTR)traceUnsupport,
                    IARG_ADDRINT, INS_Address(ins),
                    IARG_PTR, new string(INS_Disassemble(ins)),
                    IARG_END);
            }
        } 
        else {            
            // pcmpeq reg, mem
            if(INS_OperandIsReg(ins, OP_0)){
                INS_InsertCall(
                    ins, IPOINT_BEFORE, (AFUNPTR)tracePCMPRegMem,
                    IARG_ADDRINT, INS_Address(ins),
                    IARG_PTR, new string(INS_Disassemble(ins)),
                    IARG_CONTEXT,
                    IARG_UINT32, INS_OperandCount(ins),
                    IARG_UINT32, INS_RegR(ins, OP_0),
                    IARG_MEMORYREAD_EA,
                    IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                    IARG_END);
            } 
            else{
                INS_InsertCall(
                    ins, IPOINT_BEFORE, (AFUNPTR)traceUnsupport,
                    IARG_ADDRINT, INS_Address(ins),
                    IARG_PTR, new string(INS_Disassemble(ins)),
                    IARG_END);
            }

        }
    
        break;
    
    case XED_ICLASS_PUSH:
        //reg -> memory
        if(INS_OperandIsReg(ins, OP_0)){
            INS_InsertCall(
                ins, IPOINT_BEFORE, (AFUNPTR)taintMemReg,
                IARG_ADDRINT, INS_Address(ins),
                IARG_PTR, new string(INS_Disassemble(ins)),
                IARG_UINT32, INS_OperandCount(ins),
                IARG_MEMORYWRITE_EA,
                IARG_UINT32, INS_OperandReg(ins, OP_0),
                IARG_REG_VALUE, INS_OperandReg(ins, OP_0),
                IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                IARG_END);
        } 
        // memory -> memory
        else if(INS_OperandIsMemory(ins, OP_0)){
            INS_InsertCall(
                ins, IPOINT_BEFORE, (AFUNPTR)taintMemMem,
                IARG_ADDRINT, INS_Address(ins),
                IARG_PTR, new string(INS_Disassemble(ins)),
                IARG_UINT32, INS_OperandCount(ins),
                IARG_MEMORYREAD_EA,
                IARG_UINT32, INS_MemoryReadSize(ins),
                IARG_MEMORYWRITE_EA,
                IARG_UINT32, INS_MemoryWriteSize(ins),
                IARG_END);
        }
        // free taint
        else if(INS_OperandIsImmediate(ins, OP_0)){
            INS_InsertCall(
                ins, IPOINT_BEFORE, (AFUNPTR)taintMemImm,
                IARG_ADDRINT, INS_Address(ins),
                IARG_PTR, new string(INS_Disassemble(ins)),
                IARG_UINT32, INS_OperandCount(ins),
                IARG_MEMORYWRITE_EA,
                IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                IARG_END);   
        }
        else{
            INS_InsertCall(
                ins, IPOINT_BEFORE, (AFUNPTR)traceUnsupport,
                IARG_ADDRINT, INS_Address(ins),
                IARG_PTR, new string(INS_Disassemble(ins)),
                IARG_END);
        }

        break;

    case XED_ICLASS_POP:
        //memory -> reg
        if(INS_OperandIsReg(ins, OP_0)){
            INS_InsertCall(
                ins, IPOINT_BEFORE, (AFUNPTR)taintRegMem,
                IARG_ADDRINT, INS_Address(ins),
                IARG_PTR, new string(INS_Disassemble(ins)),
                IARG_UINT32, INS_OperandCount(ins),
                IARG_MEMORYREAD_EA,
                IARG_UINT32, INS_RegW(ins, OP_0),
                IARG_UINT32, INS_MemoryReadSize(ins),
                IARG_END);
        }
        //memory -> mem
        else if(INS_OperandIsMemory(ins, OP_0)){
            INS_InsertCall(
                ins, IPOINT_BEFORE, (AFUNPTR)taintMemMem,
                IARG_ADDRINT, INS_Address(ins),
                IARG_PTR, new string(INS_Disassemble(ins)),
                IARG_UINT32, INS_OperandCount(ins),
                IARG_MEMORYREAD_EA,
                IARG_UINT32, INS_MemoryReadSize(ins),
                IARG_MEMORYWRITE_EA,
                IARG_UINT32, INS_MemoryWriteSize(ins),
                IARG_END);
        }
        else{
            INS_InsertCall(
                ins, IPOINT_BEFORE, (AFUNPTR)traceUnsupport,
                IARG_ADDRINT, INS_Address(ins),
                IARG_PTR, new string(INS_Disassemble(ins)),
                IARG_END);
        }

        break;

    // arithmetic operation
    case XED_ICLASS_ADC:
    case XED_ICLASS_ADD:
    case XED_ICLASS_SBB:
    case XED_ICLASS_SUB:

    case XED_ICLASS_ADDSD:
    case XED_ICLASS_SUBSD:

    case XED_ICLASS_AND:
    case XED_ICLASS_OR:
    case XED_ICLASS_XOR:

    case XED_ICLASS_PAND:
    case XED_ICLASS_POR:
    case XED_ICLASS_PXOR: 

        if(INS_MemoryOperandCount(ins) == 0){
            if(!INS_OperandIsImmediate(ins, OP_1)){
                //reg, reg
                if(ins_indx == XED_ICLASS_XOR){
                    INS_InsertCall(
                        ins, IPOINT_BEFORE, (AFUNPTR)traceXORRegReg,
                        IARG_ADDRINT, INS_Address(ins),
                        IARG_PTR, new string(INS_Disassemble(ins)),
                        IARG_UINT32, INS_OperandCount(ins),
                        IARG_UINT32, INS_OperandReg(ins, OP_0),
                        IARG_REG_VALUE, INS_OperandReg(ins, OP_0),
                        IARG_UINT32, INS_OperandReg(ins, OP_1),
                        IARG_REG_VALUE, INS_OperandReg(ins, OP_1),
                        IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                        IARG_END);
                }
                else if(ins_indx == XED_ICLASS_OR){
                    INS_InsertCall(
                        ins, IPOINT_BEFORE, (AFUNPTR)traceORRegReg,
                        IARG_ADDRINT, INS_Address(ins),
                        IARG_PTR, new string(INS_Disassemble(ins)),
                        IARG_UINT32, INS_OperandCount(ins),
                        IARG_UINT32, INS_OperandReg(ins, OP_0),
                        IARG_REG_VALUE, INS_OperandReg(ins, OP_0),
                        IARG_UINT32, INS_OperandReg(ins, OP_1),
                        IARG_REG_VALUE, INS_OperandReg(ins, OP_1),
                        IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                        IARG_END);
                }
                else{
                    if(REG_is_xmm_ymm_zmm(INS_OperandReg(ins, OP_0)) || REG_is_mm(INS_OperandReg(ins, OP_0))){
                        INS_InsertCall(
                            ins, IPOINT_BEFORE, (AFUNPTR)traceArithRegReg,
                            IARG_ADDRINT, INS_Address(ins),
                            IARG_PTR, new string(INS_Disassemble(ins)),
                            IARG_UINT32, INS_OperandCount(ins),
                            IARG_UINT32, INS_OperandReg(ins, OP_0),
                            IARG_ADDRINT, 0,
                            IARG_UINT32, INS_OperandReg(ins, OP_1),
                            IARG_ADDRINT, 0,
                            IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                            IARG_END);
                    }
                    else
                    {
                        INS_InsertCall(
                            ins, IPOINT_BEFORE, (AFUNPTR)traceArithRegReg,
                            IARG_ADDRINT, INS_Address(ins),
                            IARG_PTR, new string(INS_Disassemble(ins)),
                            IARG_UINT32, INS_OperandCount(ins),
                            IARG_UINT32, INS_OperandReg(ins, OP_0),
                            IARG_REG_VALUE, INS_OperandReg(ins, OP_0),
                            IARG_UINT32, INS_OperandReg(ins, OP_1),
                            IARG_REG_VALUE, INS_OperandReg(ins, OP_1),
                            IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                            IARG_END);
                    }
                }
            } 
            // reg, imm
            else{
                if(ins_indx == XED_ICLASS_AND){
                    INS_InsertCall(
                        ins, IPOINT_BEFORE, (AFUNPTR)traceANDRegImm,
                        IARG_ADDRINT, INS_Address(ins),
                        IARG_PTR, new string(INS_Disassemble(ins)),
                        IARG_UINT32, INS_OperandCount(ins),
                        IARG_UINT32, INS_OperandReg(ins, OP_0),
                        IARG_REG_VALUE, INS_OperandReg(ins, OP_0),
                        IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                        IARG_UINT64, INS_OperandImmediate(ins, OP_1),
                        IARG_END);
                }
                else{
                    INS_InsertCall(
                        ins, IPOINT_BEFORE, (AFUNPTR)traceArithRegImm,
                        IARG_ADDRINT, INS_Address(ins),
                        IARG_PTR, new string(INS_Disassemble(ins)),
                        IARG_UINT32, INS_OperandCount(ins),
                        IARG_UINT32, INS_OperandReg(ins, OP_0),
                        IARG_REG_VALUE, INS_OperandReg(ins, OP_0),
                        IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                        IARG_UINT64, INS_OperandImmediate(ins, OP_1),
                        IARG_END);
                }
            }
        }
        else{
            // reg, mem
            if(INS_OperandIsReg(ins, 0)){
                if(REG_is_xmm_ymm_zmm(INS_RegW(ins, OP_0)) || REG_is_mm(INS_RegW(ins, OP_0))){
                    INS_InsertCall(
                        ins, IPOINT_BEFORE, (AFUNPTR)traceArithRegMem,
                        IARG_ADDRINT, INS_Address(ins),
                        IARG_PTR, new string(INS_Disassemble(ins)),
                        IARG_UINT32, INS_OperandCount(ins),
                        IARG_UINT32, INS_RegW(ins, OP_0),
                        IARG_ADDRINT, 0,
                        IARG_MEMORYREAD_EA,
                        IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                        IARG_END);    
                }
                else{
                    if(ins_indx == XED_ICLASS_OR){
                        INS_InsertCall(
                            ins, IPOINT_BEFORE, (AFUNPTR)traceArithRegMem,
                            IARG_ADDRINT, INS_Address(ins),
                            IARG_PTR, new string(INS_Disassemble(ins)),
                            IARG_UINT32, INS_OperandCount(ins),
                            IARG_UINT32, INS_RegW(ins, OP_0),
                            IARG_REG_VALUE, INS_RegW(ins, OP_0),
                            IARG_MEMORYREAD_EA,
                            IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                            IARG_END);

                    } else{
                        INS_InsertCall(
                            ins, IPOINT_BEFORE, (AFUNPTR)traceArithRegMem,
                            IARG_ADDRINT, INS_Address(ins),
                            IARG_PTR, new string(INS_Disassemble(ins)),
                            IARG_UINT32, INS_OperandCount(ins),
                            IARG_UINT32, INS_RegW(ins, OP_0),
                            IARG_REG_VALUE, INS_RegW(ins, OP_0),
                            IARG_MEMORYREAD_EA,
                            IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                            IARG_END);
                    }
                }
            } 
            // mem, reg
            else if(INS_OperandIsReg(ins, OP_1)){
                if(REG_is_xmm_ymm_zmm(INS_OperandReg(ins, OP_1)) || REG_is_mm(INS_OperandReg(ins, OP_1))){
                    INS_InsertCall(
                        ins, IPOINT_BEFORE, (AFUNPTR)traceArithMemReg,
                        IARG_ADDRINT, INS_Address(ins),
                        IARG_PTR, new string(INS_Disassemble(ins)),
                        IARG_UINT32, INS_OperandCount(ins),
                        IARG_MEMORYREAD_EA,
                        IARG_UINT32, INS_OperandReg(ins, OP_1),
                        IARG_ADDRINT, 0,
                        IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                        IARG_END);
                }
                else{
                    if(ins_indx == XED_ICLASS_OR){
                        INS_InsertCall(
                            ins, IPOINT_BEFORE, (AFUNPTR)traceORMemReg,
                            IARG_ADDRINT, INS_Address(ins),
                            IARG_PTR, new string(INS_Disassemble(ins)),
                            IARG_UINT32, INS_OperandCount(ins),
                            IARG_MEMORYREAD_EA,
                            IARG_UINT32, INS_OperandReg(ins, OP_1),
                            IARG_REG_VALUE, INS_OperandReg(ins, OP_1),
                            IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                            IARG_END);
                    } else{
                        INS_InsertCall(
                            ins, IPOINT_BEFORE, (AFUNPTR)traceArithMemReg,
                            IARG_ADDRINT, INS_Address(ins),
                            IARG_PTR, new string(INS_Disassemble(ins)),
                            IARG_UINT32, INS_OperandCount(ins),
                            IARG_MEMORYREAD_EA,
                            IARG_UINT32, INS_OperandReg(ins, OP_1),
                            IARG_REG_VALUE, INS_OperandReg(ins, OP_1),
                            IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                            IARG_END);
                    }
                }
            } 
            // mem, imm
            else {
                if(ins_indx == XED_ICLASS_AND){
                    INS_InsertCall(
                        ins, IPOINT_BEFORE, (AFUNPTR)traceANDMemImm,
                        IARG_ADDRINT, INS_Address(ins),
                        IARG_PTR, new string(INS_Disassemble(ins)),
                        IARG_UINT32, INS_OperandCount(ins),
                        IARG_MEMORYREAD_EA,
                        IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                        IARG_UINT64, INS_OperandImmediate(ins, OP_1),
                        IARG_END);   
                }
                else{
                    INS_InsertCall(
                        ins, IPOINT_BEFORE, (AFUNPTR)traceArithMemImm,
                        IARG_ADDRINT, INS_Address(ins),
                        IARG_PTR, new string(INS_Disassemble(ins)),
                        IARG_UINT32, INS_OperandCount(ins),
                        IARG_MEMORYREAD_EA,
                        IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                        IARG_UINT64, INS_OperandImmediate(ins, OP_1),
                        IARG_END);   
                }
            }
        }


        break;

    case XED_ICLASS_INC:
    case XED_ICLASS_DEC:
    case XED_ICLASS_NOT:
        if(INS_OperandIsMemory(ins, OP_0)){

            INS_InsertCall(
                ins, IPOINT_BEFORE, (AFUNPTR)traceArithMem,
                IARG_ADDRINT, INS_Address(ins),
                IARG_PTR, new string(INS_Disassemble(ins)),
                IARG_UINT32, INS_OperandCount(ins),
                IARG_MEMORYOP_EA, 0,
                IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                IARG_END);  
        }
        else if(INS_OperandIsReg(ins, OP_0)){
            INS_InsertCall(
                ins, IPOINT_BEFORE, (AFUNPTR)traceArithReg,
                IARG_ADDRINT, INS_Address(ins),
                IARG_PTR, new string(INS_Disassemble(ins)),
                IARG_UINT32, INS_OperandCount(ins),
                IARG_UINT32, INS_OperandReg(ins, OP_0),
                IARG_REG_VALUE, INS_OperandReg(ins, OP_0),
                IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                IARG_END);

        }
        else {
            INS_InsertCall(
                ins, IPOINT_BEFORE, (AFUNPTR)traceUnsupport,
                IARG_ADDRINT, INS_Address(ins),
                IARG_PTR, new string(INS_Disassemble(ins)),
                IARG_END);
        }

        break;
    
    case XED_ICLASS_DIV:
    case XED_ICLASS_IDIV:
        if(INS_OperandIsReg(ins, OP_0)){
            INS_InsertCall(
                ins, IPOINT_BEFORE, (AFUNPTR)traceArithRegReg,
                IARG_ADDRINT, INS_Address(ins),
                IARG_PTR, new string(INS_Disassemble(ins)),
                IARG_UINT32, INS_OperandCount(ins),
                IARG_UINT32, INS_OperandReg(ins, OP_1),
                IARG_REG_VALUE, INS_OperandReg(ins, OP_1),
                IARG_UINT32, INS_OperandReg(ins, OP_0),
                IARG_REG_VALUE, INS_OperandReg(ins, OP_0),
                IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                IARG_END);
        }
        else if(INS_OperandIsMemory(ins, OP_0)){
            INS_InsertCall(
                ins, IPOINT_BEFORE, (AFUNPTR)traceArithRegMem,
                IARG_ADDRINT, INS_Address(ins),
                IARG_PTR, new string(INS_Disassemble(ins)),
                IARG_UINT32, INS_OperandCount(ins),
                IARG_UINT32, INS_RegW(ins, OP_0),
                IARG_REG_VALUE, INS_RegW(ins, OP_0),
                IARG_MEMORYREAD_EA,
                IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                IARG_END);
        }
        else {
            INS_InsertCall(
                ins, IPOINT_BEFORE, (AFUNPTR)traceUnsupport,
                IARG_ADDRINT, INS_Address(ins),
                IARG_PTR, new string(INS_Disassemble(ins)),
                IARG_END);
        }

        break;

    case XED_ICLASS_MUL:
    case XED_ICLASS_IMUL:
        if(INS_OperandIsImplicit(ins, OP_1)){
            // OP_0 : Explicit Operand
            // OP_1 : Implicit Operand
            // OP_2 : Destination (Low)
            // OP_3 : Destination (High)
            if(INS_OperandIsReg(ins, OP_0)){
                INS_InsertCall(
                    ins, IPOINT_BEFORE, (AFUNPTR)traceArithRegReg,
                    IARG_ADDRINT, INS_Address(ins),
                    IARG_PTR, new string(INS_Disassemble(ins)),
                    IARG_UINT32, INS_OperandCount(ins),
                    IARG_UINT32, INS_OperandReg(ins, OP_0),
                    IARG_REG_VALUE, INS_OperandReg(ins, OP_0),
                    IARG_UINT32, INS_OperandReg(ins, OP_1),
                    IARG_REG_VALUE, INS_OperandReg(ins, OP_1),
                    IARG_UINT32, INS_OperandWidth(ins, OP_1)/8,
                    IARG_END);
            }
            else{
                INS_InsertCall(
                    ins, IPOINT_BEFORE, (AFUNPTR)traceArithMemReg,
                    IARG_ADDRINT, INS_Address(ins),
                    IARG_PTR, new string(INS_Disassemble(ins)),
                    IARG_UINT32, INS_OperandCount(ins),
                    IARG_MEMORYREAD_EA,
                    IARG_UINT32, INS_OperandReg(ins, OP_1),
                    IARG_REG_VALUE, INS_OperandReg(ins, OP_1),
                    IARG_UINT32, INS_OperandWidth(ins, OP_1)/8,
                    IARG_END);                
            }
        }
        else{
            if(INS_OperandCount(ins) == 4 && INS_OperandIsImmediate(ins, OP_2)){
                //reg, reg, imm
                if(INS_OperandIsReg(ins, OP_1)){
                    INS_InsertCall(
                        ins, IPOINT_BEFORE, (AFUNPTR)traceMULRegRegImm,
                        IARG_ADDRINT, INS_Address(ins),
                        IARG_PTR, new string(INS_Disassemble(ins)),
                        IARG_UINT32, INS_OperandCount(ins),
                        IARG_UINT32, INS_OperandReg(ins, OP_0),
                        IARG_REG_VALUE, INS_OperandReg(ins, OP_0),
                        IARG_UINT32, INS_OperandReg(ins, OP_1),
                        IARG_REG_VALUE, INS_OperandReg(ins, OP_1),
                        IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                        IARG_UINT64, INS_OperandImmediate(ins, OP_2),
                        IARG_END);
                }
                //reg, mem, imm
                else{
                    INS_InsertCall(
                        ins, IPOINT_BEFORE, (AFUNPTR)traceMULRegMemImm,
                        IARG_ADDRINT, INS_Address(ins),
                        IARG_PTR, new string(INS_Disassemble(ins)),
                        IARG_UINT32, INS_OperandCount(ins),
                        IARG_UINT32, INS_OperandReg(ins, OP_0),
                        IARG_REG_VALUE, INS_OperandReg(ins, OP_0),
                        IARG_MEMORYREAD_EA,
                        IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                        IARG_UINT64, INS_OperandImmediate(ins, OP_2),
                        IARG_END);
                }
            }
            else if(INS_OperandCount(ins) == 3 && INS_OperandIsReg(ins, OP_0)){
                //reg, reg
                //reg + rax
                if(INS_OperandIsReg(ins, OP_1)){
                    INS_InsertCall(
                        ins, IPOINT_BEFORE, (AFUNPTR)traceArithRegReg,
                        IARG_ADDRINT, INS_Address(ins),
                        IARG_PTR, new string(INS_Disassemble(ins)),
                        IARG_UINT32, INS_OperandCount(ins),
                        IARG_UINT32, INS_OperandReg(ins, OP_1),
                        IARG_REG_VALUE, INS_OperandReg(ins, OP_1),
                        IARG_UINT32, INS_OperandReg(ins, OP_0),
                        IARG_REG_VALUE, INS_OperandReg(ins, OP_0),
                        IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                        IARG_END);
                }
                //reg, mem
                else if(INS_OperandIsMemory(ins, OP_1)){
                    INS_InsertCall(
                        ins, IPOINT_BEFORE, (AFUNPTR)traceArithMemReg,
                        IARG_ADDRINT, INS_Address(ins),
                        IARG_PTR, new string(INS_Disassemble(ins)),
                        IARG_UINT32, INS_OperandCount(ins),
                        IARG_MEMORYREAD_EA,
                        IARG_UINT32, INS_RegW(ins, OP_0),
                        IARG_REG_VALUE, INS_RegW(ins, OP_0),
                        IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                        IARG_END);
                }
                //reg, imm
                else if(INS_OperandIsImmediate(ins, OP_1)){
                    INS_InsertCall(
                        ins, IPOINT_BEFORE, (AFUNPTR)traceArithRegImm,
                        IARG_ADDRINT, INS_Address(ins),
                        IARG_PTR, new string(INS_Disassemble(ins)),
                        IARG_UINT32, INS_OperandCount(ins),
                        IARG_UINT32, INS_RegW(ins, OP_0),
                        IARG_REG_VALUE, INS_RegW(ins, OP_0),
                        IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                        IARG_END);
                } else{
                    INS_InsertCall(
                        ins, IPOINT_BEFORE, (AFUNPTR)traceUnsupport,
                        IARG_ADDRINT, INS_Address(ins),
                        IARG_PTR, new string(INS_Disassemble(ins)),
                        IARG_END);
                }
            }
            else{
                INS_InsertCall(
                    ins, IPOINT_BEFORE, (AFUNPTR)traceUnsupport,
                    IARG_ADDRINT, INS_Address(ins),
                    IARG_PTR, new string(INS_Disassemble(ins)),
                    IARG_END);
            }
        }

        break;

    case XED_ICLASS_RCL:
    case XED_ICLASS_RCR:
    case XED_ICLASS_ROL:
    case XED_ICLASS_ROR:
        if(INS_MemoryOperandCount(ins) == 0){
            if(!INS_OperandIsImmediate(ins, OP_1)){
                //reg, reg
                INS_InsertCall(
                    ins, IPOINT_BEFORE, (AFUNPTR)traceArithRegReg,
                    IARG_ADDRINT, INS_Address(ins),
                    IARG_PTR, new string(INS_Disassemble(ins)),
                    IARG_UINT32, INS_OperandCount(ins),
                    IARG_UINT32, INS_OperandReg(ins, OP_0),
                    IARG_REG_VALUE, INS_OperandReg(ins, OP_0),
                    IARG_UINT32, INS_OperandReg(ins, OP_1),
                    IARG_REG_VALUE, INS_OperandReg(ins, OP_1),
                    IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                    IARG_END);
            } 
            // reg, imm
            else{
                INS_InsertCall(
                    ins, IPOINT_BEFORE, (AFUNPTR)traceArithRegImm,
                    IARG_ADDRINT, INS_Address(ins),
                    IARG_PTR, new string(INS_Disassemble(ins)),
                    IARG_UINT32, INS_OperandCount(ins),
                    IARG_UINT32, INS_RegW(ins, OP_0),
                    IARG_REG_VALUE, INS_RegW(ins, OP_0),
                    IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                    IARG_UINT64, INS_OperandImmediate(ins, OP_1),
                    IARG_END);
            }
        } else{
            // reg, mem
            if(INS_OperandIsReg(ins, OP_0)){
                INS_InsertCall(
                    ins, IPOINT_BEFORE, (AFUNPTR)traceArithMemReg,
                    IARG_ADDRINT, INS_Address(ins),
                    IARG_PTR, new string(INS_Disassemble(ins)),
                    IARG_UINT32, INS_OperandCount(ins),
                    IARG_MEMORYREAD_EA,
                    IARG_UINT32, INS_OperandReg(ins, OP_0),
                    IARG_REG_VALUE, INS_OperandReg(ins, OP_0),
                    IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                IARG_END);
            } 
            // mem, imm
            else if(INS_OperandIsImmediate(ins, OP_1)){
                INS_InsertCall(
                    ins, IPOINT_BEFORE, (AFUNPTR)traceArithMemImm,
                    IARG_ADDRINT, INS_Address(ins),
                    IARG_PTR, new string(INS_Disassemble(ins)),
                    IARG_UINT32, INS_OperandCount(ins),
                    IARG_MEMORYREAD_EA,
                    IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                    IARG_UINT64, INS_OperandImmediate(ins, OP_1),
                IARG_END);   
            }
        }

        break;
    
    case XED_ICLASS_SHL:
    case XED_ICLASS_SAR:
    case XED_ICLASS_SHR:
        if(INS_MemoryOperandCount(ins) == 0){
            if(!INS_OperandIsImmediate(ins, OP_1)){
                //reg, reg
                if(ins_indx == XED_ICLASS_SHL){
                    INS_InsertCall(
                        ins, IPOINT_BEFORE, (AFUNPTR)traceSHLRegReg,
                        IARG_ADDRINT, INS_Address(ins),
                        IARG_PTR, new string(INS_Disassemble(ins)),
                        IARG_UINT32, INS_OperandCount(ins),
                        IARG_UINT32, INS_OperandReg(ins, OP_0),
                        IARG_REG_VALUE, INS_OperandReg(ins, OP_0),
                        IARG_UINT32, INS_OperandReg(ins, OP_1),
                        IARG_REG_VALUE, INS_OperandReg(ins, OP_1),
                        IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                        IARG_END);
                }
                else if(ins_indx == XED_ICLASS_SAR || ins_indx == XED_ICLASS_SHR){
                    INS_InsertCall(
                        ins, IPOINT_BEFORE, (AFUNPTR)traceSHRRegReg,
                        IARG_ADDRINT, INS_Address(ins),
                        IARG_PTR, new string(INS_Disassemble(ins)),
                        IARG_UINT32, INS_OperandCount(ins),
                        IARG_UINT32, INS_OperandReg(ins, OP_0),
                        IARG_REG_VALUE, INS_OperandReg(ins, OP_0),
                        IARG_UINT32, INS_OperandReg(ins, OP_1),
                        IARG_REG_VALUE, INS_OperandReg(ins, OP_1),
                        IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                        IARG_END);               
                }
            } 
            // reg, imm
            else{
                if(ins_indx == XED_ICLASS_SHL){
                    INS_InsertCall(
                        ins, IPOINT_BEFORE, (AFUNPTR)traceSHLRegImm,
                        IARG_ADDRINT, INS_Address(ins),
                        IARG_PTR, new string(INS_Disassemble(ins)),
                        IARG_UINT32, INS_OperandCount(ins),
                        IARG_UINT32, INS_RegW(ins, OP_0),
                        IARG_REG_VALUE, INS_RegW(ins, OP_0),
                        IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                        IARG_UINT64, INS_OperandImmediate(ins, OP_1),
                        IARG_END);
                }
                else if(ins_indx == XED_ICLASS_SAR || ins_indx == XED_ICLASS_SHR){
                    INS_InsertCall(
                        ins, IPOINT_BEFORE, (AFUNPTR)traceSHRRegImm,
                        IARG_ADDRINT, INS_Address(ins),
                        IARG_PTR, new string(INS_Disassemble(ins)),
                        IARG_UINT32, INS_OperandCount(ins),
                        IARG_UINT32, INS_RegW(ins, OP_0),
                        IARG_REG_VALUE, INS_RegW(ins, OP_0),
                        IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                        IARG_UINT64, INS_OperandImmediate(ins, OP_1),
                        IARG_END);
                }
            }
        }
        else{
            // reg, mem
            if(INS_OperandIsReg(ins, OP_0)){
                INS_InsertCall(
                    ins, IPOINT_BEFORE, (AFUNPTR)traceArithMemReg,
                    IARG_ADDRINT, INS_Address(ins),
                    IARG_PTR, new string(INS_Disassemble(ins)),
                    IARG_UINT32, INS_OperandCount(ins),
                    IARG_MEMORYREAD_EA,
                    IARG_UINT32, INS_OperandReg(ins, OP_0),
                    IARG_REG_VALUE, INS_OperandReg(ins, OP_0),
                    IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                IARG_END);
            }
            // mem, imm
            else{
                if(INS_OperandIsImmediate(ins, OP_1)){
                    if(ins_indx == XED_ICLASS_SHL){
                        INS_InsertCall(
                            ins, IPOINT_BEFORE, (AFUNPTR)traceSHLMemImm,
                            IARG_ADDRINT, INS_Address(ins),
                            IARG_PTR, new string(INS_Disassemble(ins)),
                            IARG_UINT32, INS_OperandCount(ins),
                            IARG_MEMORYREAD_EA,
                            IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                            IARG_UINT64, INS_OperandImmediate(ins, OP_1),
                        IARG_END);  
                    } 
                    else if(ins_indx == XED_ICLASS_SAR || ins_indx == XED_ICLASS_SHR){
                        INS_InsertCall(
                            ins, IPOINT_BEFORE, (AFUNPTR)traceSHRMemImm,
                            IARG_ADDRINT, INS_Address(ins),
                            IARG_PTR, new string(INS_Disassemble(ins)),
                            IARG_UINT32, INS_OperandCount(ins),
                            IARG_MEMORYREAD_EA,
                            IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                            IARG_UINT64, INS_OperandImmediate(ins, OP_1),
                        IARG_END); 
                    }
                }
                // mem, reg
                else if(INS_OperandIsReg(ins, OP_1)){
                    if(ins_indx == XED_ICLASS_SHL){
                        INS_InsertCall(
                            ins, IPOINT_BEFORE, (AFUNPTR)traceSHLMemReg,
                            IARG_ADDRINT, INS_Address(ins),
                            IARG_PTR, new string(INS_Disassemble(ins)),
                            IARG_UINT32, INS_OperandCount(ins),
                            IARG_MEMORYREAD_EA,
                            IARG_UINT32, INS_OperandReg(ins, OP_1),
                            IARG_REG_VALUE, INS_OperandReg(ins, OP_1),
                            IARG_UINT32, INS_MemoryReadSize(ins),
                        IARG_END); 
                    } 
                    else if(ins_indx == XED_ICLASS_SAR || ins_indx == XED_ICLASS_SHR){
                        INS_InsertCall(
                            ins, IPOINT_BEFORE, (AFUNPTR)traceSHRMemReg,
                            IARG_ADDRINT, INS_Address(ins),
                            IARG_PTR, new string(INS_Disassemble(ins)),
                            IARG_UINT32, INS_OperandCount(ins),
                            IARG_MEMORYREAD_EA,
                            IARG_UINT32, INS_OperandReg(ins, OP_1),
                            IARG_REG_VALUE, INS_OperandReg(ins, OP_1),
                            IARG_UINT32, INS_MemoryReadSize(ins),
                        IARG_END); 
                    }
                }
            }
        }
    
    break;  

    case XED_ICLASS_SHLD:
    case XED_ICLASS_SHRD:
        INS_InsertCall(
            ins, IPOINT_BEFORE, (AFUNPTR)traceUnsupport,
            IARG_ADDRINT, INS_Address(ins),
            IARG_PTR, new string(INS_Disassemble(ins)),
            IARG_END);

        break;

    case XED_ICLASS_MOV:
    case XED_ICLASS_MOVSX:
    case XED_ICLASS_MOVSXD:
    case XED_ICLASS_MOVZX:
    
    case XED_ICLASS_MOVQ:
    case XED_ICLASS_MOVD:
    case XED_ICLASS_VMOVDQA:
    case XED_ICLASS_MOVDQA:
    case XED_ICLASS_VMOVAPS:
    case XED_ICLASS_MOVAPS:
    case XED_ICLASS_VMOVDQU:
    case XED_ICLASS_MOVDQU:
    case XED_ICLASS_VMOVQ:
    case XED_ICLASS_VMOVD:
    case XED_ICLASS_MOVAPD:
    case XED_ICLASS_VMOVAPD:

        if(INS_MemoryOperandCount(ins) == 0){
            //reg, reg
            if(!INS_OperandIsImmediate(ins, OP_1)){
                INS_InsertCall(
                    ins, IPOINT_BEFORE, (AFUNPTR)taintRegReg,
                    IARG_ADDRINT, INS_Address(ins),
                    IARG_PTR, new string(INS_Disassemble(ins)),
                    IARG_UINT32, INS_OperandCount(ins),
                    IARG_UINT32, INS_RegR(ins, OP_0),
                    IARG_UINT32, INS_RegW(ins, OP_0),
                    IARG_ADDRINT, 0,
                    IARG_UINT32, INS_OperandWidth(ins, OP_1)/8,
                    IARG_END);
            } 
            // reg, imm
            else{
                INS_InsertCall(
                    ins, IPOINT_BEFORE, (AFUNPTR)taintRegImm,
                    IARG_ADDRINT, INS_Address(ins),
                    IARG_PTR, new string(INS_Disassemble(ins)),
                    IARG_UINT32, INS_OperandCount(ins),
                    IARG_UINT32, INS_RegW(ins, OP_0),
                    IARG_ADDRINT, 0,
                    IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                    IARG_END);
            }
        }
        else{
            // reg, mem
            if(INS_OperandIsReg(ins, OP_0)){
                INS_InsertCall(
                    ins, IPOINT_BEFORE, (AFUNPTR)taintRegMem,
                    IARG_ADDRINT, INS_Address(ins),
                    IARG_PTR, new string(INS_Disassemble(ins)),
                    IARG_UINT32, INS_OperandCount(ins),
                    IARG_MEMORYREAD_EA,
                    IARG_UINT32, INS_RegW(ins, OP_0),
                    IARG_UINT32, INS_MemoryReadSize(ins),
                    IARG_END);
            } 
            // mem, reg
            else if(INS_OperandIsReg(ins, OP_1)){
                INS_InsertCall(
                    ins, IPOINT_BEFORE, (AFUNPTR)taintMemReg,
                    IARG_ADDRINT, INS_Address(ins),
                    IARG_PTR, new string(INS_Disassemble(ins)),
                    IARG_UINT32, INS_OperandCount(ins),
                    IARG_MEMORYWRITE_EA,
                    IARG_UINT32, INS_OperandReg(ins, OP_1),
                    IARG_ADDRINT, 0,
                    IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                    IARG_END); 
            } 
            // mem, imm
            else if(INS_OperandIsImmediate(ins, OP_1)){
                INS_InsertCall(
                    ins, IPOINT_BEFORE, (AFUNPTR)taintMemImm,
                    IARG_ADDRINT, INS_Address(ins),
                    IARG_PTR, new string(INS_Disassemble(ins)),
                    IARG_UINT32, INS_OperandCount(ins),
                    IARG_MEMORYWRITE_EA,
                    IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                    IARG_END);   
            } 
            else{
                INS_InsertCall(
                    ins, IPOINT_BEFORE, (AFUNPTR)traceUnsupport,
                    IARG_ADDRINT, INS_Address(ins),
                    IARG_PTR, new string(INS_Disassemble(ins)),
                    IARG_END);
            }
        }

        break;

    /* conditional movs */
    /* TODO */ 
    case XED_ICLASS_CMOVB:
    case XED_ICLASS_CMOVBE:
    case XED_ICLASS_CMOVL:
    case XED_ICLASS_CMOVLE:
    case XED_ICLASS_CMOVNB:
    case XED_ICLASS_CMOVNBE:
    case XED_ICLASS_CMOVNL:
    case XED_ICLASS_CMOVNLE:
    case XED_ICLASS_CMOVNO:
    case XED_ICLASS_CMOVNP:
    case XED_ICLASS_CMOVNS:
    case XED_ICLASS_CMOVNZ:
    case XED_ICLASS_CMOVO:
    case XED_ICLASS_CMOVP:
    case XED_ICLASS_CMOVS:
    case XED_ICLASS_CMOVZ:
    
        if(INS_MemoryOperandCount(ins) == 0){
            if(!INS_OperandIsImmediate(ins, OP_1)){
                //reg, reg
                INS_InsertPredicatedCall(
                    ins, IPOINT_BEFORE, (AFUNPTR)taintRegReg,
                    IARG_ADDRINT, INS_Address(ins),
                    IARG_PTR, new string(INS_Disassemble(ins)),
                    IARG_UINT32, INS_OperandCount(ins),
                    IARG_UINT32, INS_RegR(ins, OP_0),
                    IARG_UINT32, INS_RegW(ins, OP_0),
                    IARG_REG_VALUE, INS_RegR(ins, OP_0),
                    IARG_UINT32, INS_OperandWidth(ins, OP_1)/8,
                    IARG_END);
            } 
            // reg, imm
            else{
                INS_InsertPredicatedCall(
                    ins, IPOINT_BEFORE, (AFUNPTR)taintRegImm,
                    IARG_ADDRINT, INS_Address(ins),
                    IARG_PTR, new string(INS_Disassemble(ins)),
                    IARG_UINT32, INS_OperandCount(ins),
                    IARG_UINT32, INS_RegW(ins, OP_0),
                    IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                    IARG_END);
            }

        }

        else{
            // reg, mem
            if(INS_OperandIsReg(ins, OP_0)){
                INS_InsertPredicatedCall(
                    ins, IPOINT_BEFORE, (AFUNPTR)taintRegMem,
                    IARG_ADDRINT, INS_Address(ins),
                    IARG_PTR, new string(INS_Disassemble(ins)),
                    IARG_UINT32, INS_OperandCount(ins),
                    IARG_MEMORYREAD_EA,
                    IARG_UINT32, INS_RegW(ins, OP_0),
                    IARG_UINT32, INS_MemoryReadSize(ins),
                    IARG_END);
            } 
            // mem, reg
            else if(INS_OperandIsReg(ins, OP_1)){
                INS_InsertPredicatedCall(
                    ins, IPOINT_BEFORE, (AFUNPTR)taintMemReg,
                    IARG_ADDRINT, INS_Address(ins),
                    IARG_PTR, new string(INS_Disassemble(ins)),
                    IARG_UINT32, INS_OperandCount(ins),
                    IARG_MEMORYWRITE_EA,
                    IARG_UINT32, INS_OperandReg(ins, OP_1),
                    IARG_REG_VALUE, INS_OperandReg(ins, OP_1),
                    IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                    IARG_END);
            } 
            // mem, imm
            else if(INS_OperandIsImmediate(ins, OP_1)){
                INS_InsertPredicatedCall(
                    ins, IPOINT_BEFORE, (AFUNPTR)taintMemImm,
                    IARG_ADDRINT, INS_Address(ins),
                    IARG_PTR, new string(INS_Disassemble(ins)),
                    IARG_UINT32, INS_OperandCount(ins),
                    IARG_MEMORYWRITE_EA,
                    IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                    IARG_END);   
            } 
            else{
                INS_InsertPredicatedCall(
                    ins, IPOINT_BEFORE, (AFUNPTR)traceUnsupport,
                    IARG_ADDRINT, INS_Address(ins),
                    IARG_PTR, new string(INS_Disassemble(ins)),
                    IARG_END);
            }
        }

        break;

    case XED_ICLASS_XCHG:
        if(INS_MemoryOperandCount(ins) == 0){
        //reg reg
            INS_InsertCall(
                ins, IPOINT_BEFORE, (AFUNPTR)traceXCHGRegReg,
                IARG_ADDRINT, INS_Address(ins),
                IARG_PTR, new string(INS_Disassemble(ins)),
                IARG_UINT32, INS_OperandCount(ins),
                IARG_UINT32, INS_OperandReg(ins, OP_0),
                IARG_REG_VALUE, INS_OperandReg(ins, OP_0),
                IARG_UINT32, INS_OperandReg(ins, OP_1),
                IARG_REG_VALUE, INS_OperandReg(ins, OP_1),
                IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                IARG_END);
        }
        else{
            //reg mem
            if(INS_OperandIsReg(ins, OP_0)){                       
                INS_InsertCall(
                    ins, IPOINT_BEFORE, (AFUNPTR)traceXCHGRegMem,
                    IARG_ADDRINT, INS_Address(ins),
                    IARG_PTR, new string(INS_Disassemble(ins)),
                    IARG_UINT32, INS_OperandCount(ins),
                    IARG_UINT32, INS_OperandReg(ins, OP_0),        
                    IARG_REG_VALUE, INS_OperandReg(ins, OP_0),
                    IARG_MEMORYREAD_EA,
                    IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                    IARG_END);
            }
            //mem reg
            else{
                INS_InsertCall(
                    ins, IPOINT_BEFORE, (AFUNPTR)traceXCHGMemReg,
                    IARG_ADDRINT, INS_Address(ins),
                    IARG_PTR, new string(INS_Disassemble(ins)),
                    IARG_UINT32, INS_OperandCount(ins),
                    IARG_MEMORYREAD_EA,
                    IARG_UINT32, INS_OperandReg(ins, OP_1),
                    IARG_REG_VALUE, INS_OperandReg(ins, OP_1),
                    IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                    IARG_END);
            }
        }

        break;

    case XED_ICLASS_CMPXCHG:
        if(INS_MemoryOperandCount(ins) == 0){
        //reg reg
            INS_InsertCall(
                ins, IPOINT_BEFORE, (AFUNPTR)traceCMPXCHGRegReg,
                IARG_ADDRINT, INS_Address(ins),
                IARG_PTR, new string(INS_Disassemble(ins)),
                IARG_CONTEXT,
                IARG_UINT32, INS_OperandCount(ins),
                IARG_UINT32, INS_OperandReg(ins, OP_0),
                IARG_REG_VALUE, INS_OperandReg(ins, OP_0),
                IARG_UINT32, INS_OperandReg(ins, OP_1),
                IARG_REG_VALUE, INS_OperandReg(ins, OP_1),
                IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                IARG_END);
        }
        else{
        //mem reg
            INS_InsertCall(
                ins, IPOINT_BEFORE, (AFUNPTR)traceCMPXCHGMemReg,
                IARG_ADDRINT, INS_Address(ins),
                IARG_PTR, new string(INS_Disassemble(ins)),
                IARG_CONTEXT,
                IARG_UINT32, INS_OperandCount(ins),
                IARG_MEMORYREAD_EA,
                IARG_UINT32, INS_OperandReg(ins, OP_1),
                IARG_REG_VALUE, INS_OperandReg(ins, OP_1),
                IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                IARG_END);
        }

        break;

    /* just untaint register */
    /* TODO */
    case XED_ICLASS_LEA:
        INS_InsertPredicatedCall(
            ins, IPOINT_BEFORE, (AFUNPTR)taintLEA,
            IARG_ADDRINT, INS_Address(ins),
            IARG_PTR, new string(INS_Disassemble(ins)),
            IARG_UINT32, INS_OperandCount(ins),
            IARG_UINT32, INS_RegW(ins, OP_0),
            IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
            IARG_END);

        break;

    /* TODO */
    case XED_ICLASS_SETB:
    case XED_ICLASS_SETBE:
    case XED_ICLASS_SETL:
    case XED_ICLASS_SETLE:
    case XED_ICLASS_SETNB:
    case XED_ICLASS_SETNBE:
    case XED_ICLASS_SETNL:
    case XED_ICLASS_SETNLE:
    case XED_ICLASS_SETNO:
    case XED_ICLASS_SETNP:
    case XED_ICLASS_SETNS:
    case XED_ICLASS_SETNZ:
    case XED_ICLASS_SETO:
    case XED_ICLASS_SETP:
    case XED_ICLASS_SETS:
    case XED_ICLASS_SETZ:
        INS_InsertCall(
        ins, IPOINT_BEFORE, (AFUNPTR)traceUnsupport,
        IARG_ADDRINT, INS_Address(ins),
        IARG_PTR, new string(INS_Disassemble(ins)),
        IARG_END);

        break;

    case XED_ICLASS_BSWAP:
            INS_InsertCall(
                ins, IPOINT_BEFORE, (AFUNPTR)traceBSWAP,
                IARG_ADDRINT, INS_Address(ins),
                IARG_PTR, new string(INS_Disassemble(ins)),
                IARG_UINT32, INS_OperandCount(ins),
                IARG_UINT32, INS_OperandReg(ins, OP_0),
                IARG_REG_VALUE, INS_OperandReg(ins, OP_0),
                IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                IARG_END);

        break;

    default:
        break;
    }
}