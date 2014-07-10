# Generated ASM code

Currently the following filter: 

```
tcp port 80
```

yields the following assembly (x86) code:

```asm
0bcaf187  mov dword [0x4157d4a0], 0x3
0bcaf192  movsd xmm7, [0x409329b8]
0bcaf19b  movsd xmm5, [0x409329f0]
0bcaf1a4  movsd xmm4, [0x409329d8]
0bcaf1ad  cmp dword [rdx+0x4], -0x09
0bcaf1b1  jnz 0x0bca0010	->0
0bcaf1b7  cmp dword [rdx+0xc], -0x0b
0bcaf1bb  jnz 0x0bca0010	->0
0bcaf1c1  mov r14d, [rdx+0x8]
0bcaf1c5  cmp dword [rdx+0x14], 0xfffeffff
0bcaf1cc  jnb 0x0bca0010	->0
0bcaf1d2  movsd xmm6, [rdx+0x10]
0bcaf1d7  cmp dword [rdx], 0x4158bbd0
0bcaf1dd  jnz 0x0bca0010	->0
0bcaf1e3  ucomisd xmm7, xmm6
0bcaf1e7  ja 0x0bca0014	->1
0bcaf1ed  mov ebp, [0x4158bbd8]
0bcaf1f4  cmp dword [rbp+0x1c], +0x3f
0bcaf1f8  jnz 0x0bca0018	->2
0bcaf1fe  mov ebp, [rbp+0x14]
0bcaf201  mov rdi, 0xfffffffb41583d00
0bcaf20b  cmp rdi, [rbp+0x398]
0bcaf212  jnz 0x0bca0018	->2
0bcaf218  cmp dword [rbp+0x394], -0x0c
0bcaf21f  jnz 0x0bca0018	->2
0bcaf225  mov ebp, [rbp+0x390]
0bcaf22b  cmp dword [rbp+0x1c], +0x0f
0bcaf22f  jnz 0x0bca0018	->2
0bcaf235  mov ebp, [rbp+0x14]
0bcaf238  mov rdi, 0xfffffffb41584180
0bcaf242  cmp rdi, [rbp+0xe0]
0bcaf249  jnz 0x0bca0018	->2
0bcaf24f  cmp dword [rbp+0xdc], -0x09
0bcaf256  jnz 0x0bca0018	->2
0bcaf25c  mov rdi, 0xfffffffb41583fd0
0bcaf266  cmp rdi, [rbp+0x140]
0bcaf26d  jnz 0x0bca0018	->2
0bcaf273  cmp dword [rbp+0x13c], -0x09
0bcaf27a  jnz 0x0bca0018	->2
0bcaf280  movzx ebx, word [r14+0x6]
0bcaf285  cmp ebx, 0xa8
0bcaf28b  jnz 0x0bca0018	->2
0bcaf291  mov rbx, [r14+0x8]
0bcaf295  movzx r15d, byte [rbx+0xc]
0bcaf29a  cmp dword [rbp+0x138], 0x41583fa8
0bcaf2a4  jnz 0x0bca0018	->2
0bcaf2aa  shl r15d, 0x08
0bcaf2ae  movzx r13d, byte [rbx+0xd]
0bcaf2b3  cmp dword [rbp+0xd8], 0x41584158
0bcaf2bd  jnz 0x0bca0018	->2
0bcaf2c3  or r15d, r13d
0bcaf2c6  cmp r15d, 0x86dd
0bcaf2cd  jz 0x0bca001c	->3
0bcaf2d3  cmp r15d, 0x800
0bcaf2da  jnz 0x0bca0020	->4
0bcaf2e0  ucomisd xmm4, xmm6
0bcaf2e4  ja 0x0bca0024	->5
0bcaf2ea  movzx r15d, byte [rbx+0x17]
0bcaf2ef  cmp r15d, +0x06
0bcaf2f3  jnz 0x0bca0028	->6
0bcaf2f9  ucomisd xmm5, xmm6
0bcaf2fd  ja 0x0bca002c	->7
0bcaf303  movzx r13d, byte [rbx+0x14]
0bcaf308  shl r13d, 0x08
0bcaf30c  movzx r12d, byte [rbx+0x15]
0bcaf311  or r13d, r12d
0bcaf314  mov rdi, 0xfffffffb41584138
0bcaf31e  cmp rdi, [rbp+0x170]
0bcaf325  jnz 0x0bca0030	->8
0bcaf32b  cmp dword [rbp+0x16c], -0x09
0bcaf332  jnz 0x0bca0030	->8
0bcaf338  cmp dword [rbp+0x168], 0x41584110
0bcaf342  jnz 0x0bca0030	->8
0bcaf348  test r13d, 0x1fff
0bcaf34f  jnz 0x0bca0034	->9
0bcaf355  ucomisd xmm7, xmm6
0bcaf359  jnb 0x0bca0038	->10
0bcaf35f  movzx r12d, byte [rbx+0xe]
0bcaf364  shl r12d, 0x02
0bcaf368  and r12d, +0x3c
0bcaf36c  mov rdi, 0xfffffffb41583ef8
0bcaf376  cmp rdi, [rbp+0x128]
0bcaf37d  jnz 0x0bca003c	->11
0bcaf383  cmp dword [rbp+0x124], -0x09
0bcaf38a  jnz 0x0bca003c	->11
0bcaf390  cmp dword [rbp+0x120], 0x41583ed0
0bcaf39a  jnz 0x0bca003c	->11
0bcaf3a0  mov ebp, r12d
0bcaf3a3  add ebp, +0x0e
0bcaf3a6  jl 0x0bca0040	->12
0bcaf3ac  mov r15d, ebp
0bcaf3af  add r15d, +0x02
0bcaf3b3  jo 0x0bca0044	->13
0bcaf3b9  xorps xmm7, xmm7
0bcaf3bc  cvtsi2sd xmm7, r15d
0bcaf3c1  ucomisd xmm7, xmm6
0bcaf3c5  ja 0x0bca0048	->14
0bcaf3cb  movsxd r15, ebp
0bcaf3ce  movzx r13d, byte [r15+rbx]
0bcaf3d3  shl r13d, 0x08
0bcaf3d7  movzx r15d, byte [r15+rbx+0x1]
0bcaf3dd  or r13d, r15d
0bcaf3e0  cmp r13d, +0x50
0bcaf3e4  jz 0x0bca0050	->16
0bcaf3ea  mov ebp, r12d
0bcaf3ed  add ebp, +0x10
0bcaf3f0  jl 0x0bca0058	->18
0bcaf3f6  mov r15d, ebp
0bcaf3f9  add r15d, +0x02
0bcaf3fd  jo 0x0bca005c	->19
0bcaf403  xorps xmm7, xmm7
0bcaf406  cvtsi2sd xmm7, r15d
0bcaf40b  ucomisd xmm7, xmm6
0bcaf40f  ja 0x0bca0060	->20
0bcaf415  movsxd r15, ebp
0bcaf418  movzx ebp, byte [r15+rbx]
0bcaf41d  shl ebp, 0x08
0bcaf420  movzx ebx, byte [r15+rbx+0x1]
0bcaf426  or ebp, ebx
0bcaf428  cmp ebp, +0x50
0bcaf42b  jz 0x0bca0068	->22
0bcaf431  xor eax, eax
0bcaf433  mov ebx, 0x4159c78c
0bcaf438  mov r14d, 0x4157df78
0bcaf43e  jmp 0x0041e288
```
