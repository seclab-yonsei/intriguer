#include <list>

#if !defined(TARGET_WINDOWS)
#include <sys/syscall.h>
#endif

#include "syscall.hpp"
#include "instrument.hpp"
#include "trace.hpp"

UINT64 globalOffset;

bool isTargetFileOpen=false;
bool isTargetFileRead=false;
bool isLseekCalled = false;
bool isLlseekCalled = false;
bool isTargetFileMmap2 = false;
bool isTaintStart = false;
bool isLibcSO = false;

UINT64* llseekResult;
UINT64 taintMemoryStart;
UINT64 mmapSize;
UINT64 targetFileFd=0xFFFFFFFF;

string targetFileName;

VOID SysBefore(ADDRINT ip, ADDRINT num, ADDRINT arg0, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5)
{
#if defined(TARGET_LINUX) && defined(TARGET_IA32) 
    // On ia32 Linux, there are only 5 registers for passing system call arguments, 
    // but mmap needs 6. For mmap on ia32, the first argument to the system call 
    // is a pointer to an array of the 6 arguments
    if (num == SYS_mmap)
    {
        ADDRINT * mmapArgs = reinterpret_cast<ADDRINT *>(arg0);
        arg0 = mmapArgs[0];
        arg1 = mmapArgs[1];
        arg2 = mmapArgs[2];
        arg3 = mmapArgs[3];
        arg4 = mmapArgs[4];
        arg5 = mmapArgs[5];
    }
#endif

    if(num == __NR_read){
        output << "[READ FILE]\t";
        output << hex << "0x" << ip << ":\tfd: " << arg0 << endl;

        taintMemoryStart = static_cast<INT64>(arg1);

        if(arg0 == targetFileFd || arg0 == 0){
            isTargetFileRead = true;
            isTaintStart = true;
        }

    } else if(num == __NR_open){
        output << "[OPEN FILE]\t";

        output << hex << "0x" << ip << ":\t" << (char*)arg0 << endl;

        if(strstr((char*)arg0, targetFileName.c_str()) != NULL){
            isTargetFileOpen = true;
            output << "\tOpen target file" << endl;

            isTaintStart = true;
        }

        if(strstr((char*)arg0, "libc.so") != NULL){
            isLibcSO = true;
        }

    } else if(num == __NR_close){
        output << hex << "[CLOSE FILE]\t\tfd: " << arg0 << endl;

        if(arg0 == targetFileFd){
            targetFileFd = 0xFFFFFFFF;
        }

        if(isLibcSO == true){
            isTaintStart = true;
        }
    } else if(num == __NR_lseek){
        output << hex << "[LSEEK FILE]\t\tfd: " << arg0 << " offset: " << arg1 << " whence: " << arg2 << endl;

        if(arg0 == targetFileFd){
            isLseekCalled = true;
        }

    } else if(num == 140){
        output << hex << "[LLSEEK FILE]\t\tfd: " << arg0 << " offseth: " << arg1 << " offsetl: " << arg2 << " result: " << arg3 <<" whence: " << arg4 << endl;
        
        if(arg0 == targetFileFd){
            llseekResult = (UINT64*)arg3;
            isLlseekCalled = true;
        }

    } else if (num == __NR_mmap){
        output << hex << "[MMAP]\t\taddr: " << arg0 << " length: " << arg1 << " prot: " << arg2 << " flags: " << arg3 <<" fd: " << arg4 << " offset: " << arg5 << endl;
    }

    #if defined(TARGET_LINUX) && defined(TARGET_IA32) 
    else if (num == __NR_mmap2){
        output << hex << "[MMAP2]\t\taddr: " << arg0 << " length: " << arg1 << " prot: " << arg2 << " flags: " << arg3 <<" fd: " << arg4 << " pgoffset: " << arg5 << endl;
        if(arg4 == targetFileFd && arg4 != 0xFFFFFFFF){
            isTargetFileMmap2 = true;
            mmapSize = arg1;
            isTaintStart = true;
        }
    }
    #endif
}

VOID SysAfter(ADDRINT ret)
{
    if(isTargetFileOpen && ret >= 0){
        targetFileFd = ret;
        isTargetFileOpen = false;
        globalOffset = 0;
        output << "\topen file descriptor " << targetFileFd << endl;
    } 

    if(isTargetFileRead && ret >= 0){
        isTargetFileRead = false;
        
        UINT64 size = ret;

        for (UINT64 i = 0; i < size; i++){
            addMemTainted(taintMemoryStart + i, globalOffset);

            globalOffset++;
        }
          
        output << "[TAINT]\t\t\t0x" << size << " bytes tainted from ";
        output << hex << "0x" << taintMemoryStart << " to 0x" << taintMemoryStart+size;
        output << " by file offset 0x" << globalOffset-size << " (via read)" << endl;
    }

    if(isLseekCalled == true){
        isLseekCalled = false;
        globalOffset = ret;

        output << "[LSEEK] result: " << llseekResult << endl;
    }

    if(isLlseekCalled == true){
        isLlseekCalled = false;
        globalOffset = *llseekResult;

        output << "[LLSEEK] result: " << *llseekResult << endl;
    }

    if(isTargetFileMmap2){
        isTargetFileMmap2 = false;
        
        if(ret != 0xFFFFFFFF){
            UINT64 mmapResult = ret;

            for (UINT64 i = 0; i < mmapSize; i++){
                addMemTainted(mmapResult + i, i);
            }

            output << "[TAINT]\t\t\t0x" << mmapSize << " bytes tainted from ";
            output << hex << "0x" << mmapResult << " to 0x" << mmapResult+mmapSize << " (via mmap2)" << endl;
        }
    }
}

VOID SyscallEntry(THREADID threadIndex, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v)
{
    SysBefore(PIN_GetContextReg(ctxt, REG_INST_PTR),
        PIN_GetSyscallNumber(ctxt, std),
        PIN_GetSyscallArgument(ctxt, std, 0),
        PIN_GetSyscallArgument(ctxt, std, 1),
        PIN_GetSyscallArgument(ctxt, std, 2),
        PIN_GetSyscallArgument(ctxt, std, 3),
        PIN_GetSyscallArgument(ctxt, std, 4),
        PIN_GetSyscallArgument(ctxt, std, 5));
}

VOID SyscallExit(THREADID threadIndex, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v)
{
    SysAfter(PIN_GetSyscallReturn(ctxt, std));
}

void doStdin(){
    targetFileFd = 0;
    globalOffset = 0;
}
