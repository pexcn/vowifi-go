
/workspace/work/vowifi-analysis/vohive_v1.5.5-10u_linux_amd64:     file format elf64-x86-64


Disassembly of section .text:

0000000000fd45c0 <.text+0xbd35c0>:
  fd45c0:	49 3b 66 10          	cmp    0x10(%r14),%rsp
  fd45c4:	0f 86 10 01 00 00    	jbe    0xfd46da
  fd45ca:	55                   	push   %rbp
  fd45cb:	48 89 e5             	mov    %rsp,%rbp
  fd45ce:	48 83 ec 38          	sub    $0x38,%rsp
  fd45d2:	80 b8 f8 03 00 00 00 	cmpb   $0x0,0x3f8(%rax)
  fd45d9:	0f 84 cd 00 00 00    	je     0xfd46ac
  fd45df:	48 83 b8 60 03 00 00 	cmpq   $0x0,0x360(%rax)
  fd45e6:	00
  fd45e7:	0f 84 91 00 00 00    	je     0xfd467e
  fd45ed:	80 b8 f9 03 00 00 17 	cmpb   $0x17,0x3f9(%rax)
  fd45f4:	74 7e                	je     0xfd4674
  fd45f6:	44 0f 11 7c 24 28    	movups %xmm15,0x28(%rsp)
  fd45fc:	0f b6 90 f9 03 00 00 	movzbl 0x3f9(%rax),%edx
  fd4603:	4c 8d 05 56 a3 c8 00 	lea    0xc8a356(%rip),%r8        # 0x1c5e960
  fd460a:	4c 89 44 24 28       	mov    %r8,0x28(%rsp)
  fd460f:	4c 8d 05 2a b5 80 01 	lea    0x180b52a(%rip),%r8        # 0x27dfb40
  fd4616:	49 8d 14 d0          	lea    (%r8,%rdx,8),%rdx
  fd461a:	48 89 54 24 30       	mov    %rdx,0x30(%rsp)
  fd461f:	48 8d 05 27 32 26 01 	lea    0x1263227(%rip),%rax        # 0x223784d
  fd4626:	bb 4d 00 00 00       	mov    $0x4d,%ebx
  fd462b:	48 8d 4c 24 28       	lea    0x28(%rsp),%rcx
  fd4630:	bf 01 00 00 00       	mov    $0x1,%edi
  fd4635:	48 89 fe             	mov    %rdi,%rsi
  fd4638:	e8 83 99 54 ff       	call   0x51dfc0
  fd463d:	0f 1f 00             	nopl   (%rax)
  fd4640:	48 85 c0             	test   %rax,%rax
  fd4643:	75 29                	jne    0xfd466e
  fd4645:	90                   	nop
  fd4646:	48 8d 05 93 14 dd 00 	lea    0xdd1493(%rip),%rax        # 0x1da5ae0
  fd464d:	e8 2e 10 45 ff       	call   0x425680
  fd4652:	48 c7 40 08 4d 00 00 	movq   $0x4d,0x8(%rax)
  fd4659:	00
  fd465a:	48 8d 0d ec 31 26 01 	lea    0x12631ec(%rip),%rcx        # 0x223784d
  fd4661:	48 89 08             	mov    %rcx,(%rax)
  fd4664:	48 89 c3             	mov    %rax,%rbx
  fd4667:	48 8d 05 b2 1c 7b 01 	lea    0x17b1cb2(%rip),%rax        # 0x2786320
  fd466e:	48 83 c4 38          	add    $0x38,%rsp
  fd4672:	5d                   	pop    %rbp
  fd4673:	c3                   	ret
  fd4674:	31 c0                	xor    %eax,%eax
  fd4676:	31 db                	xor    %ebx,%ebx
  fd4678:	48 83 c4 38          	add    $0x38,%rsp
  fd467c:	5d                   	pop    %rbp
  fd467d:	c3                   	ret
  fd467e:	48 8d 05 5b 14 dd 00 	lea    0xdd145b(%rip),%rax        # 0x1da5ae0
  fd4685:	e8 f6 0f 45 ff       	call   0x425680
  fd468a:	48 c7 40 08 2b 00 00 	movq   $0x2b,0x8(%rax)
  fd4691:	00
  fd4692:	48 8d 0d 15 3c 23 01 	lea    0x1233c15(%rip),%rcx        # 0x22082ae
  fd4699:	48 89 08             	mov    %rcx,(%rax)
  fd469c:	48 89 c3             	mov    %rax,%rbx
  fd469f:	48 8d 05 7a 1c 7b 01 	lea    0x17b1c7a(%rip),%rax        # 0x2786320
  fd46a6:	48 83 c4 38          	add    $0x38,%rsp
  fd46aa:	5d                   	pop    %rbp
  fd46ab:	c3                   	ret
  fd46ac:	48 8d 05 2d 14 dd 00 	lea    0xdd142d(%rip),%rax        # 0x1da5ae0
  fd46b3:	e8 c8 0f 45 ff       	call   0x425680
  fd46b8:	48 c7 40 08 33 00 00 	movq   $0x33,0x8(%rax)
  fd46bf:	00
  fd46c0:	48 8d 0d f2 39 24 01 	lea    0x12439f2(%rip),%rcx        # 0x22180b9
  fd46c7:	48 89 08             	mov    %rcx,(%rax)
  fd46ca:	48 89 c3             	mov    %rax,%rbx
  fd46cd:	48 8d 05 4c 1c 7b 01 	lea    0x17b1c4c(%rip),%rax        # 0x2786320
  fd46d4:	48 83 c4 38          	add    $0x38,%rsp
  fd46d8:	5d                   	pop    %rbp
  fd46d9:	c3                   	ret
  fd46da:	48 89 44 24 08       	mov    %rax,0x8(%rsp)
  fd46df:	90                   	nop
  fd46e0:	e8 1b 9b 4b ff       	call   0x48e200
  fd46e5:	48 8b 44 24 08       	mov    0x8(%rsp),%rax
  fd46ea:	e9 d1 fe ff ff       	jmp    0xfd45c0
  fd46ef:	cc                   	int3
  fd46f0:	cc                   	int3
  fd46f1:	cc                   	int3
  fd46f2:	cc                   	int3
  fd46f3:	cc                   	int3
  fd46f4:	cc                   	int3
  fd46f5:	cc                   	int3
  fd46f6:	cc                   	int3
  fd46f7:	cc                   	int3
  fd46f8:	cc                   	int3
  fd46f9:	cc                   	int3
  fd46fa:	cc                   	int3
  fd46fb:	cc                   	int3
  fd46fc:	cc                   	int3
  fd46fd:	cc                   	int3
  fd46fe:	cc                   	int3
  fd46ff:	cc                   	int3
  fd4700:	49 3b 66 10          	cmp    0x10(%r14),%rsp
  fd4704:	0f 86 93 01 00 00    	jbe    0xfd489d
  fd470a:	55                   	push   %rbp
  fd470b:	48 89 e5             	mov    %rsp,%rbp
  fd470e:	48 83 ec 10          	sub    $0x10,%rsp
  fd4712:	48 85 c0             	test   %rax,%rax
  fd4715:	0f 84 54 01 00 00    	je     0xfd486f
  fd471b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
  fd4720:	48 85 db             	test   %rbx,%rbx
  fd4723:	0f 84 18 01 00 00    	je     0xfd4841
  fd4729:	80 7b 18 00          	cmpb   $0x0,0x18(%rbx)
  fd472d:	74 78                	je     0xfd47a7
  fd472f:	80 7b 1a 00          	cmpb   $0x0,0x1a(%rbx)
  fd4733:	74 41                	je     0xfd4776
  fd4735:	c6 00 01             	movb   $0x1,(%rax)
  fd4738:	48 8b 4b 08          	mov    0x8(%rbx),%rcx
  fd473c:	48 8b 53 10          	mov    0x10(%rbx),%rdx
  fd4740:	48 8b 33             	mov    (%rbx),%rsi
  fd4743:	48 89 48 10          	mov    %rcx,0x10(%rax)
  fd4747:	48 89 50 18          	mov    %rdx,0x18(%rax)
  fd474b:	83 3d fe bb b9 02 00 	cmpl   $0x0,0x2b9bbfe(%rip)        # 0x3b70350
  fd4752:	74 10                	je     0xfd4764
  fd4754:	48 8b 48 08          	mov    0x8(%rax),%rcx
  fd4758:	e8 23 b4 4b ff       	call   0x48fb80
  fd475d:	49 89 33             	mov    %rsi,(%r11)
  fd4760:	49 89 4b 08          	mov    %rcx,0x8(%r11)
  fd4764:	48 89 70 08          	mov    %rsi,0x8(%rax)
  fd4768:	c6 40 01 00          	movb   $0x0,0x1(%rax)
  fd476c:	31 c0                	xor    %eax,%eax
  fd476e:	31 db                	xor    %ebx,%ebx
  fd4770:	48 83 c4 10          	add    $0x10,%rsp
  fd4774:	5d                   	pop    %rbp
  fd4775:	c3                   	ret
  fd4776:	48 8d 05 63 13 dd 00 	lea    0xdd1363(%rip),%rax        # 0x1da5ae0
  fd477d:	0f 1f 00             	nopl   (%rax)
