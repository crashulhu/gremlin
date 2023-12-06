

.text
_start:
   
   # mmap(0, 0x21000, 15, 0x22, 0, 0 )
   mov %rax, 9 # syscall number
   # addr, we don't care what address we get so leave at 0
   mov %rdi, 0 
   # length
   mov %rsi, 0x21000
   # perms, this gives us a RWX region 
   mov %rdx, 15
   # flags
   mov %r10, 0x22
   mov %r8,  0 
   mov %r9,  0
   syscall

# we grab the return value in the injector

# remove before final version
#   ret 

