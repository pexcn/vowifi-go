
work/vowifi-analysis/vohive_v1.5.5-10u_linux_amd64:     file format elf64-x86-64


Disassembly of section .text:

0000000000dbf340 <.text+0x9be340>:
  dbf340:	49 3b 66 10          	cmp    0x10(%r14),%rsp
  dbf344:	76 43                	jbe    0xdbf389
  dbf346:	55                   	push   %rbp
  dbf347:	48 89 e5             	mov    %rsp,%rbp
  dbf34a:	48 83 ec 20          	sub    $0x20,%rsp
  dbf34e:	48 89 44 24 30       	mov    %rax,0x30(%rsp)
  dbf353:	e8 28 01 00 00       	call   0xdbf480
  dbf358:	84 c9                	test   %cl,%cl
  dbf35a:	74 25                	je     0xdbf381
  dbf35c:	48 8b 15 ed 64 d8 02 	mov    0x2d864ed(%rip),%rdx        # 0x3b45850
  dbf363:	48 89 c1             	mov    %rax,%rcx
  dbf366:	48 89 df             	mov    %rbx,%rdi
  dbf369:	48 8d 05 90 f8 fc 00 	lea    0xfcf890(%rip),%rax        # 0x1d8ec00
  dbf370:	48 89 d3             	mov    %rdx,%rbx
  dbf373:	e8 48 73 65 ff       	call   0x4166c0
  dbf378:	89 d8                	mov    %ebx,%eax
  dbf37a:	48 83 c4 20          	add    $0x20,%rsp
  dbf37e:	5d                   	pop    %rbp
  dbf37f:	90                   	nop
  dbf380:	c3                   	ret
  dbf381:	31 c0                	xor    %eax,%eax
  dbf383:	48 83 c4 20          	add    $0x20,%rsp
  dbf387:	5d                   	pop    %rbp
  dbf388:	c3                   	ret
  dbf389:	48 89 44 24 08       	mov    %rax,0x8(%rsp)
  dbf38e:	48 89 5c 24 10       	mov    %rbx,0x10(%rsp)
  dbf393:	e8 68 ee 6c ff       	call   0x48e200
  dbf398:	48 8b 44 24 08       	mov    0x8(%rsp),%rax
  dbf39d:	48 8b 5c 24 10       	mov    0x10(%rsp),%rbx
  dbf3a2:	eb 9c                	jmp    0xdbf340
  dbf3a4:	cc                   	int3
  dbf3a5:	cc                   	int3
  dbf3a6:	cc                   	int3
  dbf3a7:	cc                   	int3
  dbf3a8:	cc                   	int3
  dbf3a9:	cc                   	int3
  dbf3aa:	cc                   	int3
  dbf3ab:	cc                   	int3
  dbf3ac:	cc                   	int3
  dbf3ad:	cc                   	int3
  dbf3ae:	cc                   	int3
  dbf3af:	cc                   	int3
  dbf3b0:	cc                   	int3
  dbf3b1:	cc                   	int3
  dbf3b2:	cc                   	int3
  dbf3b3:	cc                   	int3
  dbf3b4:	cc                   	int3
  dbf3b5:	cc                   	int3
  dbf3b6:	cc                   	int3
  dbf3b7:	cc                   	int3
  dbf3b8:	cc                   	int3
  dbf3b9:	cc                   	int3
  dbf3ba:	cc                   	int3
  dbf3bb:	cc                   	int3
  dbf3bc:	cc                   	int3
  dbf3bd:	cc                   	int3
  dbf3be:	cc                   	int3
  dbf3bf:	cc                   	int3
