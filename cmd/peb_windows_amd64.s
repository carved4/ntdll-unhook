#include "textflag.h"

// GetPEB retrieves the Process Environment Block (PEB) address directly from GS register
// func GetPEB() uintptr
TEXT ·GetPEB(SB), $0-8
    MOVQ 0x60(GS), AX  // Access PEB from GS register (x64)
    MOVQ AX, ret+0(FP)  // Store result in return value
    RET 
    