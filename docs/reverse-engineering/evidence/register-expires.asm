
/workspace/work/vowifi-analysis/vohive_v1.5.5-10u_linux_amd64:     file format elf64-x86-64


Disassembly of section .text:

00000000010d7560 <.text+0xcd6560>:
 10d7560:	4c 8d a4 24 e0 fb ff 	lea    -0x420(%rsp),%r12
 10d7567:	ff
 10d7568:	4d 3b 66 10          	cmp    0x10(%r14),%r12
 10d756c:	0f 86 45 01 00 00    	jbe    0x10d76b7
 10d7572:	55                   	push   %rbp
 10d7573:	48 89 e5             	mov    %rsp,%rbp
 10d7576:	48 81 ec 98 04 00 00 	sub    $0x498,%rsp
 10d757d:	48 89 84 24 30 06 00 	mov    %rax,0x630(%rsp)
 10d7584:	00
 10d7585:	48 89 e0             	mov    %rsp,%rax
 10d7588:	48 8d 8c 24 a8 04 00 	lea    0x4a8(%rsp),%rcx
 10d758f:	00
 10d7590:	ba 06 00 00 00       	mov    $0x6,%edx
 10d7595:	44 0f 10 31          	movups (%rcx),%xmm14
 10d7599:	44 0f 11 30          	movups %xmm14,(%rax)
 10d759d:	44 0f 10 71 10       	movups 0x10(%rcx),%xmm14
 10d75a2:	44 0f 11 70 10       	movups %xmm14,0x10(%rax)
 10d75a7:	44 0f 10 71 20       	movups 0x20(%rcx),%xmm14
 10d75ac:	44 0f 11 70 20       	movups %xmm14,0x20(%rax)
 10d75b1:	44 0f 10 71 30       	movups 0x30(%rcx),%xmm14
 10d75b6:	44 0f 11 70 30       	movups %xmm14,0x30(%rax)
 10d75bb:	48 83 c1 40          	add    $0x40,%rcx
 10d75bf:	48 83 c0 40          	add    $0x40,%rax
 10d75c3:	ff ca                	dec    %edx
 10d75c5:	75 ce                	jne    0x10d7595
 10d75c7:	44 0f 10 71 f8       	movups -0x8(%rcx),%xmm14
 10d75cc:	44 0f 11 70 f8       	movups %xmm14,-0x8(%rax)
 10d75d1:	e8 2a f7 cd ff       	call   0xdb6d00
 10d75d6:	48 8d 84 24 10 03 00 	lea    0x310(%rsp),%rax
 10d75dd:	00
 10d75de:	48 8d 8c 24 88 01 00 	lea    0x188(%rsp),%rcx
 10d75e5:	00
 10d75e6:	ba 06 00 00 00       	mov    $0x6,%edx
 10d75eb:	44 0f 10 31          	movups (%rcx),%xmm14
 10d75ef:	44 0f 11 30          	movups %xmm14,(%rax)
 10d75f3:	44 0f 10 71 10       	movups 0x10(%rcx),%xmm14
 10d75f8:	44 0f 11 70 10       	movups %xmm14,0x10(%rax)
 10d75fd:	44 0f 10 71 20       	movups 0x20(%rcx),%xmm14
 10d7602:	44 0f 11 70 20       	movups %xmm14,0x20(%rax)
 10d7607:	44 0f 10 71 30       	movups 0x30(%rcx),%xmm14
 10d760c:	44 0f 11 70 30       	movups %xmm14,0x30(%rax)
 10d7611:	48 83 c1 40          	add    $0x40,%rcx
 10d7615:	48 83 c0 40          	add    $0x40,%rax
 10d7619:	ff ca                	dec    %edx
 10d761b:	75 ce                	jne    0x10d75eb
 10d761d:	44 0f 10 71 f8       	movups -0x8(%rcx),%xmm14
 10d7622:	44 0f 11 70 f8       	movups %xmm14,-0x8(%rax)
 10d7627:	48 8b 84 24 28 03 00 	mov    0x328(%rsp),%rax
 10d762e:	00
 10d762f:	48 85 c0             	test   %rax,%rax
 10d7632:	7f 7a                	jg     0x10d76ae
 10d7634:	48 8b 8c 24 30 06 00 	mov    0x630(%rsp),%rcx
 10d763b:	00
 10d763c:	0f 1f 40 00          	nopl   0x0(%rax)
 10d7640:	48 85 c9             	test   %rcx,%rcx
 10d7643:	7f 5d                	jg     0x10d76a2
 10d7645:	90                   	nop
 10d7646:	e8 f5 c1 cd ff       	call   0xdb3840
 10d764b:	48 8d 84 24 10 03 00 	lea    0x310(%rsp),%rax
 10d7652:	00
 10d7653:	48 89 e1             	mov    %rsp,%rcx
 10d7656:	ba 06 00 00 00       	mov    $0x6,%edx
 10d765b:	44 0f 10 31          	movups (%rcx),%xmm14
 10d765f:	44 0f 11 30          	movups %xmm14,(%rax)
 10d7663:	44 0f 10 71 10       	movups 0x10(%rcx),%xmm14
 10d7668:	44 0f 11 70 10       	movups %xmm14,0x10(%rax)
 10d766d:	44 0f 10 71 20       	movups 0x20(%rcx),%xmm14
 10d7672:	44 0f 11 70 20       	movups %xmm14,0x20(%rax)
 10d7677:	44 0f 10 71 30       	movups 0x30(%rcx),%xmm14
 10d767c:	44 0f 11 70 30       	movups %xmm14,0x30(%rax)
 10d7681:	48 83 c1 40          	add    $0x40,%rcx
 10d7685:	48 83 c0 40          	add    $0x40,%rax
 10d7689:	ff ca                	dec    %edx
 10d768b:	75 ce                	jne    0x10d765b
 10d768d:	44 0f 10 71 f8       	movups -0x8(%rcx),%xmm14
 10d7692:	44 0f 11 70 f8       	movups %xmm14,-0x8(%rax)
 10d7697:	48 8b 84 24 28 03 00 	mov    0x328(%rsp),%rax
 10d769e:	00
 10d769f:	48 89 c1             	mov    %rax,%rcx
 10d76a2:	48 89 c8             	mov    %rcx,%rax
 10d76a5:	48 81 c4 98 04 00 00 	add    $0x498,%rsp
 10d76ac:	5d                   	pop    %rbp
 10d76ad:	c3                   	ret
 10d76ae:	48 81 c4 98 04 00 00 	add    $0x498,%rsp
 10d76b5:	5d                   	pop    %rbp
 10d76b6:	c3                   	ret
 10d76b7:	48 89 84 24 90 01 00 	mov    %rax,0x190(%rsp)
 10d76be:	00
 10d76bf:	90                   	nop
 10d76c0:	e8 3b 6b 3b ff       	call   0x48e200
 10d76c5:	48 8b 84 24 90 01 00 	mov    0x190(%rsp),%rax
 10d76cc:	00
 10d76cd:	e9 8e fe ff ff       	jmp    0x10d7560
 10d76d2:	cc                   	int3
 10d76d3:	cc                   	int3
 10d76d4:	cc                   	int3
 10d76d5:	cc                   	int3
 10d76d6:	cc                   	int3
 10d76d7:	cc                   	int3
 10d76d8:	cc                   	int3
 10d76d9:	cc                   	int3
 10d76da:	cc                   	int3
 10d76db:	cc                   	int3
 10d76dc:	cc                   	int3
 10d76dd:	cc                   	int3
 10d76de:	cc                   	int3
 10d76df:	cc                   	int3
