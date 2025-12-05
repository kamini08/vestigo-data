#include <stdio.h>
#include <stdint.h>

// This function does nothing useful but executes THOUSANDS of INC instructions.
// It is designed to look like a "compression loop" (like SHA-256) to a heuristic analyzer.
void __attribute__((noinline)) aes_encryption() {
    uint64_t dummy_accumulator = 0;
    
    // We run this loop enough times to dominate the execution trace
    for (int i = 0; i < 10000; i++) {
        // Inline assembly to force specific INC instructions
        // We use 'volatile' so the compiler doesn't optimize this away.
        __asm__ volatile (
            "inc %0;"  // Increment dummy_accumulator
            "inc %0;"
            "inc %0;"
            "inc %0;"
            "inc %0;"
            "inc %0;"
            "inc %0;"
            "inc %0;"
            // REX Prefix injection (x86-64 specific):
            // Using 64-bit registers (rax) often forces REX.W prefixes (0x48)
            "add $1, %0;" 
            "sub $1, %0;"
            : "+r" (dummy_accumulator) // Output operand
            : // No input operands
            : "cc" // Clobbers condition codes
        );
    }
}

int main() {
    // 1. Normal behavior
    printf("Hello, World!\n");

    // 2. Trigger the false positive
    // If your dynamic analyzer monitors this, it will see a massive spike 
    // in arithmetic density here.
    aes_encryption();

    return 0;
}