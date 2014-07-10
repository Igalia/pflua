# Generated ASM code

Currently the following filter: 

```
tcp port 80
```

yields the following assembly (x86) code:

```asm
0bcaf0b0  mov dword [0x416d24a0], 0x3
0bcaf0bb  movsd xmm7, [0x409bfe88]
0bcaf0c4  movsd xmm5, [0x409bfec0]
0bcaf0cd  movsd xmm4, [0x409bfea8]
0bcaf0d6  cmp dword [rdx+0x4], -0x09
0bcaf0da  jnz 0x0bca0010	->0
0bcaf0e0  cmp dword [rdx+0xc], -0x0c
0bcaf0e4  jnz 0x0bca0010	->0
0bcaf0ea  mov r14d, [rdx+0x8]
0bcaf0ee  cmp dword [rdx], 0x416f1590
0bcaf0f4  jnz 0x0bca0010	->0
0bcaf0fa  cmp dword [r14+0x1c], +0x03
0bcaf0ff  jnz 0x0bca0010	->0
0bcaf105  mov ebp, [r14+0x14]
0bcaf109  mov rdi, 0xfffffffb416daf58
0bcaf113  cmp rdi, [rbp+0x20]
0bcaf117  jnz 0x0bca0010	->0
0bcaf11d  cmp dword [rbp+0x1c], 0xfffeffff
0bcaf124  jnb 0x0bca0010	->0
0bcaf12a  movsd xmm6, [rbp+0x18]
0bcaf12f  ucomisd xmm7, xmm6
0bcaf133  ja 0x0bca0014	->1
0bcaf139  mov ebx, [r14+0x1c]
0bcaf13d  and ebx, 0xd1c8f3e8
0bcaf143  lea ebx, [rbx+rbx*2]
0bcaf146  shl ebx, 0x03
0bcaf149  add ebx, [r14+0x14]
0bcaf14d  cmp dword [rbx+0xc], -0x05
0bcaf151  jnz 0x0bcaf160
0bcaf153  cmp dword [rbx+0x8], 0x416db198
0bcaf15a  jz 0x0bca0018	->2
0bcaf160  mov ebx, [rbx+0x10]
0bcaf163  test ebx, ebx
0bcaf165  jnz 0x0bcaf14d
0bcaf167  mov ebx, 0x416d2420
0bcaf16c  mov ebx, [r14+0x10]
0bcaf170  test ebx, ebx
0bcaf172  jz 0x0bca0018	->2
0bcaf178  cmp dword [rbx+0x1c], +0x01
0bcaf17c  jnz 0x0bca0018	->2
0bcaf182  mov ebx, [rbx+0x14]
0bcaf185  mov rdi, 0xfffffffb416d4430
0bcaf18f  cmp rdi, [rbx+0x20]
0bcaf193  jnz 0x0bca0018	->2
0bcaf199  cmp dword [rbx+0x1c], -0x0c
0bcaf19d  jnz 0x0bca0018	->2
0bcaf1a3  mov ebx, [rbx+0x18]
0bcaf1a6  cmp dword [rbx+0x1c], +0x03
0bcaf1aa  jnz 0x0bca0018	->2
0bcaf1b0  mov r15d, [rbx+0x14]
0bcaf1b4  mov rdi, 0xfffffffb416db198
0bcaf1be  cmp rdi, [r15+0x50]
0bcaf1c2  jnz 0x0bca0018	->2
0bcaf1c8  cmp dword [r15+0x4c], -0x09
0bcaf1cd  jnz 0x0bca0018	->2
0bcaf1d3  cmp dword [r15+0x48], 0x416ee010
0bcaf1db  jnz 0x0bca0018	->2
0bcaf1e1  cmp dword [0x416ee03c], -0x0c
0bcaf1e9  jnz 0x0bca0018	->2
0bcaf1ef  mov ebx, [0x416ee038]
0bcaf1f6  cmp dword [rbx+0x1c], +0x0f
0bcaf1fa  jnz 0x0bca0018	->2
0bcaf200  mov r12d, [rbx+0x14]
0bcaf204  mov rdi, 0xfffffffb416d9180
0bcaf20e  cmp rdi, [r12+0xe0]
0bcaf216  jnz 0x0bca0018	->2
0bcaf21c  cmp dword [r12+0xdc], -0x09
0bcaf225  jnz 0x0bca0018	->2
0bcaf22b  mov rdi, 0xfffffffb416d8fd0
0bcaf235  cmp rdi, [r12+0x140]
0bcaf23d  jnz 0x0bca0018	->2
0bcaf243  cmp dword [r12+0x13c], -0x09
0bcaf24c  jnz 0x0bca0018	->2
0bcaf252  mov rdi, 0xfffffffb416dd300
0bcaf25c  cmp rdi, [rbp+0x8]
0bcaf260  jnz 0x0bca0018	->2
0bcaf266  cmp dword [rbp+0x4], -0x0b
0bcaf26a  jnz 0x0bca0018	->2
0bcaf270  mov ebp, [rbp+0x0]
0bcaf273  movzx ebx, word [rbp+0x6]
0bcaf277  cmp ebx, 0xa8
0bcaf27d  jnz 0x0bca0018	->2
0bcaf283  mov rbx, [rbp+0x8]
0bcaf287  movzx ebp, byte [rbx+0xc]
0bcaf28b  cmp dword [r12+0x138], 0x416d8fa8
0bcaf297  jnz 0x0bca0018	->2
0bcaf29d  shl ebp, 0x08
0bcaf2a0  movzx r13d, byte [rbx+0xd]
0bcaf2a5  cmp dword [r12+0xd8], 0x416d9158
0bcaf2b1  jnz 0x0bca0018	->2
0bcaf2b7  or ebp, r13d
0bcaf2ba  cmp ebp, 0x86dd
0bcaf2c0  jz 0x0bca001c	->3
0bcaf2c6  cmp ebp, 0x800
0bcaf2cc  jnz 0x0bca0020	->4
0bcaf2d2  ucomisd xmm4, xmm6
0bcaf2d6  ja 0x0bca0024	->5
0bcaf2dc  mov r13d, [r14+0x1c]
0bcaf2e0  and r13d, 0x7c6f8560
0bcaf2e7  lea r13d, [r13+r13*2+0x0]
0bcaf2ec  shl r13d, 0x03
0bcaf2f0  add r13d, [r14+0x14]
0bcaf2f4  cmp dword [r13+0xc], -0x05
0bcaf2f9  jnz 0x0bcaf309
0bcaf2fb  cmp dword [r13+0x8], 0x416e9d58
0bcaf303  jz 0x0bca0028	->6
0bcaf309  mov r13d, [r13+0x10]
0bcaf30d  test r13d, r13d
0bcaf310  jnz 0x0bcaf2f4
0bcaf312  mov r13d, 0x416d2420
0bcaf318  mov rdi, 0xfffffffb416e9d58
0bcaf322  cmp rdi, [r15+0x8]
0bcaf326  jnz 0x0bca0028	->6
0bcaf32c  cmp dword [r15+0x4], -0x09
0bcaf331  jnz 0x0bca0028	->6
0bcaf337  cmp dword [r15], 0x416edff0
0bcaf33e  jnz 0x0bca0028	->6
0bcaf344  movzx r15d, byte [rbx+0x17]
0bcaf349  cmp r15d, +0x06
0bcaf34d  jnz 0x0bca002c	->7
0bcaf353  ucomisd xmm5, xmm6
0bcaf357  ja 0x0bca0030	->8
0bcaf35d  movzx r13d, byte [rbx+0x14]
0bcaf362  shl r13d, 0x08
0bcaf366  movzx ebp, byte [rbx+0x15]
0bcaf36a  or r13d, ebp
0bcaf36d  mov ebp, [0x416f1598]
0bcaf374  cmp dword [rbp+0x1c], +0x3f
0bcaf378  jnz 0x0bca0034	->9
0bcaf37e  mov ebp, [rbp+0x14]
0bcaf381  mov rdi, 0xfffffffb416d8d00
0bcaf38b  cmp rdi, [rbp+0x398]
0bcaf392  jnz 0x0bca0034	->9
0bcaf398  cmp dword [rbp+0x394], -0x0c
0bcaf39f  jnz 0x0bca0034	->9
0bcaf3a5  mov ebp, [rbp+0x390]
0bcaf3ab  cmp dword [rbp+0x1c], +0x0f
0bcaf3af  jnz 0x0bca0034	->9
0bcaf3b5  mov ebp, [rbp+0x14]
0bcaf3b8  mov rdi, 0xfffffffb416d9138
0bcaf3c2  cmp rdi, [rbp+0x170]
0bcaf3c9  jnz 0x0bca0034	->9
0bcaf3cf  cmp dword [rbp+0x16c], -0x09
0bcaf3d6  jnz 0x0bca0034	->9
0bcaf3dc  cmp dword [rbp+0x168], 0x416d9110
0bcaf3e6  jnz 0x0bca0034	->9
0bcaf3ec  test r13d, 0x1fff
0bcaf3f3  jnz 0x0bca0038	->10
0bcaf3f9  ucomisd xmm7, xmm6
0bcaf3fd  jnb 0x0bca003c	->11
0bcaf403  mov rdi, 0xfffffffb416d8fd0
0bcaf40d  cmp rdi, [rbp+0x140]
0bcaf414  jnz 0x0bca0040	->12
0bcaf41a  cmp dword [rbp+0x13c], -0x09
0bcaf421  jnz 0x0bca0040	->12
0bcaf427  movzx r12d, byte [rbx+0xe]
0bcaf42c  cmp dword [rbp+0x138], 0x416d8fa8
0bcaf436  jnz 0x0bca0040	->12
0bcaf43c  shl r12d, 0x02
0bcaf440  and r12d, +0x3c
0bcaf444  mov rdi, 0xfffffffb416d8ef8
0bcaf44e  cmp rdi, [rbp+0x128]
0bcaf455  jnz 0x0bca0040	->12
0bcaf45b  cmp dword [rbp+0x124], -0x09
0bcaf462  jnz 0x0bca0040	->12
0bcaf468  cmp dword [rbp+0x120], 0x416d8ed0
0bcaf472  jnz 0x0bca0040	->12
0bcaf478  mov ebp, r12d
0bcaf47b  add ebp, +0x0e
0bcaf47e  jl 0x0bca0044	->13
0bcaf484  mov r15d, ebp
0bcaf487  add r15d, +0x02
0bcaf48b  jo 0x0bca0048	->14
0bcaf491  xorps xmm7, xmm7
0bcaf494  cvtsi2sd xmm7, r15d
0bcaf499  ucomisd xmm7, xmm6
0bcaf49d  ja 0x0bca004c	->15
0bcaf4a3  movsxd r15, ebp
0bcaf4a6  movzx r13d, byte [r15+rbx]
0bcaf4ab  shl r13d, 0x08
0bcaf4af  movzx r15d, byte [r15+rbx+0x1]
0bcaf4b5  or r13d, r15d
0bcaf4b8  cmp r13d, +0x50
0bcaf4bc  jz 0x0bca0054	->17
0bcaf4c2  mov ebp, r12d
0bcaf4c5  add ebp, +0x10
0bcaf4c8  jl 0x0bca005c	->19
0bcaf4ce  mov r15d, ebp
0bcaf4d1  add r15d, +0x02
0bcaf4d5  jo 0x0bca0060	->20
0bcaf4db  xorps xmm7, xmm7
0bcaf4de  cvtsi2sd xmm7, r15d
0bcaf4e3  ucomisd xmm7, xmm6
0bcaf4e7  ja 0x0bca0064	->21
0bcaf4ed  movsxd r15, ebp
0bcaf4f0  movzx ebp, byte [r15+rbx]
0bcaf4f5  shl ebp, 0x08
0bcaf4f8  movzx ebx, byte [r15+rbx+0x1]
0bcaf4fe  or ebp, ebx
0bcaf500  cmp ebp, +0x50
0bcaf503  jz 0x0bca006c	->23
0bcaf509  xor eax, eax
0bcaf50b  mov ebx, 0x416f17b0
0bcaf510  mov r14d, 0x416d2f78
0bcaf516  jmp 0x0041e288
```
