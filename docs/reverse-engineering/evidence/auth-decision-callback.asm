
work/vowifi-analysis/vohive_v1.5.5-10u_linux_amd64:     file format elf64-x86-64


Disassembly of section .text:

0000000000fd4e20 <.text+0xbd3e20>:
  fd4e20:	49 3b 66 10          	cmp    0x10(%r14),%rsp
  fd4e24:	0f 86 82 01 00 00    	jbe    0xfd4fac
  fd4e2a:	55                   	push   %rbp
  fd4e2b:	48 89 e5             	mov    %rsp,%rbp
  fd4e2e:	48 83 ec 48          	sub    $0x48,%rsp
  fd4e32:	48 8b 4a 08          	mov    0x8(%rdx),%rcx
  fd4e36:	80 79 20 00          	cmpb   $0x0,0x20(%rcx)
  fd4e3a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
  fd4e40:	0f 84 5c 01 00 00    	je     0xfd4fa2
  fd4e46:	48 8b 42 10          	mov    0x10(%rdx),%rax
  fd4e4a:	48 8b 72 40          	mov    0x40(%rdx),%rsi
  fd4e4e:	48 89 74 24 30       	mov    %rsi,0x30(%rsp)
  fd4e53:	48 85 c0             	test   %rax,%rax
  fd4e56:	0f 85 97 00 00 00    	jne    0xfd4ef3
  fd4e5c:	0f b6 11             	movzbl (%rcx),%edx
  fd4e5f:	90                   	nop
  fd4e60:	80 fa 02             	cmp    $0x2,%dl
  fd4e63:	75 0a                	jne    0xfd4e6f
  fd4e65:	48 83 79 28 01       	cmpq   $0x1,0x28(%rcx)
  fd4e6a:	0f 94 c1             	sete   %cl
  fd4e6d:	eb 11                	jmp    0xfd4e80
  fd4e6f:	80 fa 03             	cmp    $0x3,%dl
  fd4e72:	75 51                	jne    0xfd4ec5
  fd4e74:	48 83 79 28 02       	cmpq   $0x2,0x28(%rcx)
  fd4e79:	0f 94 c1             	sete   %cl
  fd4e7c:	0f 1f 40 00          	nopl   0x0(%rax)
  fd4e80:	84 c9                	test   %cl,%cl
  fd4e82:	74 41                	je     0xfd4ec5
  fd4e84:	48 89 f0             	mov    %rsi,%rax
  fd4e87:	e8 34 f7 ff ff       	call   0xfd45c0
  fd4e8c:	48 85 c0             	test   %rax,%rax
  fd4e8f:	74 06                	je     0xfd4e97
  fd4e91:	48 83 c4 48          	add    $0x48,%rsp
  fd4e95:	5d                   	pop    %rbp
  fd4e96:	c3                   	ret
  fd4e97:	48 8b 54 24 30       	mov    0x30(%rsp),%rdx
  fd4e9c:	48 8b 82 98 04 00 00 	mov    0x498(%rdx),%rax
  fd4ea3:	48 8d 1d 4f 83 25 01 	lea    0x125834f(%rip),%rbx        # 0x222d1f9
  fd4eaa:	b9 42 00 00 00       	mov    $0x42,%ecx
  fd4eaf:	31 ff                	xor    %edi,%edi
  fd4eb1:	31 f6                	xor    %esi,%esi
  fd4eb3:	49 89 f0             	mov    %rsi,%r8
  fd4eb6:	e8 a5 2b b6 ff       	call   0xb37a60
  fd4ebb:	31 c0                	xor    %eax,%eax
  fd4ebd:	31 db                	xor    %ebx,%ebx
  fd4ebf:	48 83 c4 48          	add    $0x48,%rsp
  fd4ec3:	5d                   	pop    %rbp
  fd4ec4:	c3                   	ret
  fd4ec5:	48 8d 05 14 0c dd 00 	lea    0xdd0c14(%rip),%rax        # 0x1da5ae0
  fd4ecc:	e8 af 07 45 ff       	call   0x425680
  fd4ed1:	48 c7 40 08 39 00 00 	movq   $0x39,0x8(%rax)
  fd4ed8:	00
  fd4ed9:	48 8d 0d 34 ce 24 01 	lea    0x124ce34(%rip),%rcx        # 0x2221d14
  fd4ee0:	48 89 08             	mov    %rcx,(%rax)
  fd4ee3:	48 89 c3             	mov    %rax,%rbx
  fd4ee6:	48 8d 05 33 14 7b 01 	lea    0x17b1433(%rip),%rax        # 0x2786320
  fd4eed:	48 83 c4 48          	add    $0x48,%rsp
  fd4ef1:	5d                   	pop    %rbp
  fd4ef2:	c3                   	ret
  fd4ef3:	48 8b 4a 18          	mov    0x18(%rdx),%rcx
  fd4ef7:	48 8b 5a 38          	mov    0x38(%rdx),%rbx
  fd4efb:	48 8b 31             	mov    (%rcx),%rsi
  fd4efe:	48 89 ca             	mov    %rcx,%rdx
  fd4f01:	ff d6                	call   *%rsi
  fd4f03:	48 85 c0             	test   %rax,%rax
  fd4f06:	74 6c                	je     0xfd4f74
  fd4f08:	44 0f 11 7c 24 38    	movups %xmm15,0x38(%rsp)
  fd4f0e:	74 04                	je     0xfd4f14
  fd4f10:	48 8b 40 08          	mov    0x8(%rax),%rax
  fd4f14:	48 89 44 24 38       	mov    %rax,0x38(%rsp)
  fd4f19:	48 89 5c 24 40       	mov    %rbx,0x40(%rsp)
  fd4f1e:	48 8d 05 43 f9 24 01 	lea    0x124f943(%rip),%rax        # 0x2224868
  fd4f25:	bb 3b 00 00 00       	mov    $0x3b,%ebx
  fd4f2a:	48 8d 4c 24 38       	lea    0x38(%rsp),%rcx
  fd4f2f:	bf 01 00 00 00       	mov    $0x1,%edi
  fd4f34:	48 89 fe             	mov    %rdi,%rsi
  fd4f37:	e8 84 90 54 ff       	call   0x51dfc0
  fd4f3c:	0f 1f 40 00          	nopl   0x0(%rax)
  fd4f40:	48 85 c0             	test   %rax,%rax
  fd4f43:	75 29                	jne    0xfd4f6e
  fd4f45:	90                   	nop
  fd4f46:	48 8d 05 93 0b dd 00 	lea    0xdd0b93(%rip),%rax        # 0x1da5ae0
  fd4f4d:	e8 2e 07 45 ff       	call   0x425680
  fd4f52:	48 c7 40 08 3b 00 00 	movq   $0x3b,0x8(%rax)
  fd4f59:	00
  fd4f5a:	48 8d 0d 07 f9 24 01 	lea    0x124f907(%rip),%rcx        # 0x2224868
  fd4f61:	48 89 08             	mov    %rcx,(%rax)
  fd4f64:	48 89 c3             	mov    %rax,%rbx
  fd4f67:	48 8d 05 b2 13 7b 01 	lea    0x17b13b2(%rip),%rax        # 0x2786320
  fd4f6e:	48 83 c4 48          	add    $0x48,%rsp
  fd4f72:	5d                   	pop    %rbp
  fd4f73:	c3                   	ret
  fd4f74:	48 8b 54 24 30       	mov    0x30(%rsp),%rdx
  fd4f79:	48 8b 82 98 04 00 00 	mov    0x498(%rdx),%rax
  fd4f80:	48 8d 1d 07 34 21 01 	lea    0x1213407(%rip),%rbx        # 0x21e838e
  fd4f87:	b9 20 00 00 00       	mov    $0x20,%ecx
  fd4f8c:	31 ff                	xor    %edi,%edi
  fd4f8e:	31 f6                	xor    %esi,%esi
  fd4f90:	49 89 f0             	mov    %rsi,%r8
  fd4f93:	e8 28 2a b6 ff       	call   0xb379c0
  fd4f98:	31 c0                	xor    %eax,%eax
  fd4f9a:	31 db                	xor    %ebx,%ebx
  fd4f9c:	48 83 c4 48          	add    $0x48,%rsp
  fd4fa0:	5d                   	pop    %rbp
  fd4fa1:	c3                   	ret
  fd4fa2:	31 c0                	xor    %eax,%eax
  fd4fa4:	31 db                	xor    %ebx,%ebx
  fd4fa6:	48 83 c4 48          	add    $0x48,%rsp
  fd4faa:	5d                   	pop    %rbp
  fd4fab:	c3                   	ret
  fd4fac:	e8 af 91 4b ff       	call   0x48e160
  fd4fb1:	e9 6a fe ff ff       	jmp    0xfd4e20
  fd4fb6:	cc                   	int3
  fd4fb7:	cc                   	int3
  fd4fb8:	cc                   	int3
  fd4fb9:	cc                   	int3
  fd4fba:	cc                   	int3
  fd4fbb:	cc                   	int3
  fd4fbc:	cc                   	int3
  fd4fbd:	cc                   	int3
  fd4fbe:	cc                   	int3
  fd4fbf:	cc                   	int3
