#include "textflag.h"

// func getPEB() uintptr
// ARM64 Windows: TEB at x18, PEB at TEB+0x60.
// Go asm restricts R18, so emit raw LDR X0, [X18, #0x60].
TEXT ·getPEB(SB),NOSPLIT,$0-8
	WORD $0xF9403240
	MOVD R0, ret+0(FP)
	RET
