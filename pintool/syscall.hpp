#ifndef INTRIGUER_SYSCALL_HPP_
#define INTRIGUER_SYSCALL_HPP_

#include "pin.H"

extern ofstream output;

// Print syscall number and arguments
VOID SysBefore(ADDRINT ip, ADDRINT num, ADDRINT arg0, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5);

// Print the return value of the system call
VOID SysAfter(ADDRINT ret);

VOID SyscallEntry(THREADID threadIndex, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v);

VOID SyscallExit(THREADID threadIndex, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v);

void doStdin();

#endif