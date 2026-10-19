
/workspace/work/vowifi-analysis/vohive_v1.5.5-10u_linux_amd64:     file format elf64-x86-64


Disassembly of section .text:

0000000000fa05a0 <.text+0xb9f5a0>:
  fa05a0:	49 3b 66 10          	cmp    0x10(%r14),%rsp
  fa05a4:	0f 86 a5 01 00 00    	jbe    0xfa074f
  fa05aa:	55                   	push   %rbp
  fa05ab:	48 89 e5             	mov    %rsp,%rbp
  fa05ae:	48 83 ec 60          	sub    $0x60,%rsp
  fa05b2:	48 89 44 24 70       	mov    %rax,0x70(%rsp)
  fa05b7:	48 83 fb 04          	cmp    $0x4,%rbx
  fa05bb:	7c 45                	jl     0xfa0602
  fa05bd:	48 89 8c 24 80 00 00 	mov    %rcx,0x80(%rsp)
  fa05c4:	00
  fa05c5:	48 89 44 24 70       	mov    %rax,0x70(%rsp)
  fa05ca:	48 89 5c 24 78       	mov    %rbx,0x78(%rsp)
  fa05cf:	48 8d 05 4a 9a ee 00 	lea    0xee9a4a(%rip),%rax        # 0x1e8a020
  fa05d6:	e8 a5 50 48 ff       	call   0x425680
  fa05db:	48 89 44 24 50       	mov    %rax,0x50(%rsp)
  fa05e0:	48 8b 4c 24 70       	mov    0x70(%rsp),%rcx
  fa05e5:	0f b6 11             	movzbl (%rcx),%edx
  fa05e8:	88 10                	mov    %dl,(%rax)
  fa05ea:	44 0f 11 78 10       	movups %xmm15,0x10(%rax)
  fa05ef:	48 8d 15 ea f1 bc 02 	lea    0x2bcf1ea(%rip),%rdx        # 0x3b6f7e0
  fa05f6:	48 89 50 08          	mov    %rdx,0x8(%rax)
  fa05fa:	ba 04 00 00 00       	mov    $0x4,%edx
  fa05ff:	90                   	nop
  fa0600:	eb 2f                	jmp    0xfa0631
  fa0602:	48 8d 05 47 ec 1f 01 	lea    0x11fec47(%rip),%rax        # 0x219f250
  fa0609:	bb 02 00 00 00       	mov    $0x2,%ebx
  fa060e:	e8 8d 03 00 00       	call   0xfa09a0
  fa0613:	48 89 d9             	mov    %rbx,%rcx
  fa0616:	48 89 c3             	mov    %rax,%rbx
  fa0619:	31 c0                	xor    %eax,%eax
  fa061b:	48 83 c4 60          	add    $0x60,%rsp
  fa061f:	5d                   	pop    %rbp
  fa0620:	c3                   	ret
  fa0621:	4b 89 44 c1 f8       	mov    %rax,-0x8(%r9,%r8,8)
  fa0626:	48 89 d0             	mov    %rdx,%rax
  fa0629:	48 8b 4c 24 70       	mov    0x70(%rsp),%rcx
  fa062e:	48 89 f2             	mov    %rsi,%rdx
  fa0631:	48 8b 5c 24 78       	mov    0x78(%rsp),%rbx
  fa0636:	48 39 d3             	cmp    %rdx,%rbx
  fa0639:	0f 8e 00 01 00 00    	jle    0xfa073f
  fa063f:	90                   	nop
  fa0640:	0f 82 03 01 00 00    	jb     0xfa0749
  fa0646:	48 89 54 24 40       	mov    %rdx,0x40(%rsp)
  fa064b:	48 8b b4 24 80 00 00 	mov    0x80(%rsp),%rsi
  fa0652:	00
  fa0653:	48 29 d6             	sub    %rdx,%rsi
  fa0656:	48 89 df             	mov    %rbx,%rdi
  fa0659:	48 29 d7             	sub    %rdx,%rdi
  fa065c:	49 89 f0             	mov    %rsi,%r8
  fa065f:	48 f7 de             	neg    %rsi
  fa0662:	48 c1 fe 3f          	sar    $0x3f,%rsi
  fa0666:	48 21 d6             	and    %rdx,%rsi
  fa0669:	48 8d 04 31          	lea    (%rcx,%rsi,1),%rax
  fa066d:	48 89 fb             	mov    %rdi,%rbx
  fa0670:	4c 89 c1             	mov    %r8,%rcx
  fa0673:	e8 08 01 00 00       	call   0xfa0780
  fa0678:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
  fa067f:	00
  fa0680:	48 85 c9             	test   %rcx,%rcx
  fa0683:	0f 85 a8 00 00 00    	jne    0xfa0731
  fa0689:	48 8b 54 24 50       	mov    0x50(%rsp),%rdx
  fa068e:	48 8b 4a 18          	mov    0x18(%rdx),%rcx
  fa0692:	4c 8b 42 10          	mov    0x10(%rdx),%r8
  fa0696:	49 ff c0             	inc    %r8
  fa0699:	4c 8b 4a 08          	mov    0x8(%rdx),%r9
  fa069d:	0f 1f 00             	nopl   (%rax)
  fa06a0:	4c 39 c1             	cmp    %r8,%rcx
  fa06a3:	73 5b                	jae    0xfa0700
  fa06a5:	48 89 44 24 58       	mov    %rax,0x58(%rsp)
  fa06aa:	48 89 5c 24 48       	mov    %rbx,0x48(%rsp)
  fa06af:	4c 89 c8             	mov    %r9,%rax
  fa06b2:	4c 89 c3             	mov    %r8,%rbx
  fa06b5:	bf 01 00 00 00       	mov    $0x1,%edi
  fa06ba:	48 8d 35 9f 94 d5 00 	lea    0xd5949f(%rip),%rsi        # 0x1cf9b60
  fa06c1:	e8 9a a4 4e ff       	call   0x48ab60
  fa06c6:	48 8b 54 24 50       	mov    0x50(%rsp),%rdx
  fa06cb:	48 89 4a 18          	mov    %rcx,0x18(%rdx)
  fa06cf:	83 3d 7a fc bc 02 00 	cmpl   $0x0,0x2bcfc7a(%rip)        # 0x3b70350
  fa06d6:	74 14                	je     0xfa06ec
  fa06d8:	48 8b 72 08          	mov    0x8(%rdx),%rsi
  fa06dc:	0f 1f 40 00          	nopl   0x0(%rax)
  fa06e0:	e8 9b f4 4e ff       	call   0x48fb80
  fa06e5:	49 89 03             	mov    %rax,(%r11)
  fa06e8:	49 89 73 08          	mov    %rsi,0x8(%r11)
  fa06ec:	48 89 42 08          	mov    %rax,0x8(%rdx)
  fa06f0:	49 89 d8             	mov    %rbx,%r8
  fa06f3:	49 89 c1             	mov    %rax,%r9
  fa06f6:	48 8b 44 24 58       	mov    0x58(%rsp),%rax
  fa06fb:	48 8b 5c 24 48       	mov    0x48(%rsp),%rbx
  fa0700:	4c 89 42 10          	mov    %r8,0x10(%rdx)
  fa0704:	48 8b 74 24 40       	mov    0x40(%rsp),%rsi
  fa0709:	48 01 de             	add    %rbx,%rsi
  fa070c:	83 3d 3d fc bc 02 00 	cmpl   $0x0,0x2bcfc3d(%rip)        # 0x3b70350
  fa0713:	0f 84 08 ff ff ff    	je     0xfa0621
  fa0719:	4b 8b 7c c1 f8       	mov    -0x8(%r9,%r8,8),%rdi
  fa071e:	66 90                	xchg   %ax,%ax
  fa0720:	e8 5b f4 4e ff       	call   0x48fb80
  fa0725:	49 89 03             	mov    %rax,(%r11)
  fa0728:	49 89 7b 08          	mov    %rdi,0x8(%r11)
  fa072c:	e9 f0 fe ff ff       	jmp    0xfa0621
  fa0731:	31 c0                	xor    %eax,%eax
  fa0733:	48 89 cb             	mov    %rcx,%rbx
  fa0736:	48 89 f9             	mov    %rdi,%rcx
  fa0739:	48 83 c4 60          	add    $0x60,%rsp
  fa073d:	5d                   	pop    %rbp
  fa073e:	c3                   	ret
  fa073f:	31 db                	xor    %ebx,%ebx
  fa0741:	31 c9                	xor    %ecx,%ecx
  fa0743:	48 83 c4 60          	add    $0x60,%rsp
  fa0747:	5d                   	pop    %rbp
  fa0748:	c3                   	ret
  fa0749:	e8 d2 f7 4e ff       	call   0x48ff20
  fa074e:	90                   	nop
  fa074f:	48 89 44 24 08       	mov    %rax,0x8(%rsp)
  fa0754:	48 89 5c 24 10       	mov    %rbx,0x10(%rsp)
  fa0759:	48 89 4c 24 18       	mov    %rcx,0x18(%rsp)
  fa075e:	66 90                	xchg   %ax,%ax
  fa0760:	e8 9b da 4e ff       	call   0x48e200
  fa0765:	48 8b 44 24 08       	mov    0x8(%rsp),%rax
  fa076a:	48 8b 5c 24 10       	mov    0x10(%rsp),%rbx
  fa076f:	48 8b 4c 24 18       	mov    0x18(%rsp),%rcx
  fa0774:	e9 27 fe ff ff       	jmp    0xfa05a0
  fa0779:	cc                   	int3
  fa077a:	cc                   	int3
  fa077b:	cc                   	int3
  fa077c:	cc                   	int3
  fa077d:	cc                   	int3
  fa077e:	cc                   	int3
  fa077f:	cc                   	int3
  fa0780:	49 3b 66 10          	cmp    0x10(%r14),%rsp
  fa0784:	0f 86 d9 01 00 00    	jbe    0xfa0963
  fa078a:	55                   	push   %rbp
  fa078b:	48 89 e5             	mov    %rsp,%rbp
  fa078e:	48 83 ec 40          	sub    $0x40,%rsp
  fa0792:	48 89 44 24 50       	mov    %rax,0x50(%rsp)
  fa0797:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
  fa079e:	00 00
  fa07a0:	48 83 fb 04          	cmp    $0x4,%rbx
  fa07a4:	0f 8c 98 01 00 00    	jl     0xfa0942
  fa07aa:	48 89 44 24 50       	mov    %rax,0x50(%rsp)
  fa07af:	0f b7 10             	movzwl (%rax),%edx
  fa07b2:	66 c1 c2 08          	rol    $0x8,%dx
  fa07b6:	90                   	nop
  fa07b7:	89 d6                	mov    %edx,%esi
  fa07b9:	81 e2 ff 7f 00 00    	and    $0x7fff,%edx
  fa07bf:	66 89 54 24 1e       	mov    %dx,0x1e(%rsp)
  fa07c4:	66 f7 c6 00 80       	test   $0x8000,%si
  fa07c9:	0f 85 eb 00 00 00    	jne    0xfa08ba
  fa07cf:	0f b7 70 02          	movzwl 0x2(%rax),%esi
  fa07d3:	66 c1 c6 08          	rol    $0x8,%si
  fa07d7:	0f b7 f6             	movzwl %si,%esi
  fa07da:	48 8d 7e 04          	lea    0x4(%rsi),%rdi
  fa07de:	66 90                	xchg   %ax,%ax
  fa07e0:	48 39 fb             	cmp    %rdi,%rbx
  fa07e3:	0f 8c b0 00 00 00    	jl     0xfa0899
  fa07e9:	48 89 4c 24 60       	mov    %rcx,0x60(%rsp)
  fa07ee:	48 89 74 24 20       	mov    %rsi,0x20(%rsp)
  fa07f3:	48 89 7c 24 28       	mov    %rdi,0x28(%rsp)
  fa07f8:	48 8d 05 61 e1 cb 00 	lea    0xcbe161(%rip),%rax        # 0x1c5e960
  fa07ff:	48 89 f3             	mov    %rsi,%rbx
  fa0802:	48 89 d9             	mov    %rbx,%rcx
  fa0805:	e8 76 a2 4e ff       	call   0x48aa80
  fa080a:	48 89 44 24 38       	mov    %rax,0x38(%rsp)
  fa080f:	48 8d 05 6a 97 ee 00 	lea    0xee976a(%rip),%rax        # 0x1e89f80
  fa0816:	e8 65 4e 48 ff       	call   0x425680
  fa081b:	0f b7 54 24 1e       	movzwl 0x1e(%rsp),%edx
  fa0820:	66 89 10             	mov    %dx,(%rax)
  fa0823:	48 8b 4c 24 20       	mov    0x20(%rsp),%rcx
  fa0828:	48 89 48 10          	mov    %rcx,0x10(%rax)
  fa082c:	48 89 48 18          	mov    %rcx,0x18(%rax)
  fa0830:	48 8b 54 24 60       	mov    0x60(%rsp),%rdx
  fa0835:	48 83 c2 fc          	add    $0xfffffffffffffffc,%rdx
  fa0839:	48 f7 da             	neg    %rdx
  fa083c:	48 c1 fa 3f          	sar    $0x3f,%rdx
  fa0840:	83 e2 04             	and    $0x4,%edx
  fa0843:	48 8b 74 24 50       	mov    0x50(%rsp),%rsi
  fa0848:	48 8d 1c 16          	lea    (%rsi,%rdx,1),%rbx
  fa084c:	83 3d fd fa bc 02 00 	cmpl   $0x0,0x2bcfafd(%rip)        # 0x3b70350
  fa0853:	75 0b                	jne    0xfa0860
  fa0855:	48 8b 54 24 38       	mov    0x38(%rsp),%rdx
  fa085a:	eb 11                	jmp    0xfa086d
  fa085c:	0f 1f 40 00          	nopl   0x0(%rax)
  fa0860:	e8 fb f2 4e ff       	call   0x48fb60
  fa0865:	48 8b 54 24 38       	mov    0x38(%rsp),%rdx
  fa086a:	49 89 13             	mov    %rdx,(%r11)
  fa086d:	48 89 50 08          	mov    %rdx,0x8(%rax)
  fa0871:	48 39 da             	cmp    %rbx,%rdx
  fa0874:	74 14                	je     0xfa088a
  fa0876:	48 89 44 24 30       	mov    %rax,0x30(%rsp)
  fa087b:	48 89 d0             	mov    %rdx,%rax
  fa087e:	66 90                	xchg   %ax,%ax
  fa0880:	e8 3b fa 4e ff       	call   0x4902c0
  fa0885:	48 8b 44 24 30       	mov    0x30(%rsp),%rax
  fa088a:	48 8b 5c 24 28       	mov    0x28(%rsp),%rbx
  fa088f:	31 c9                	xor    %ecx,%ecx
  fa0891:	31 ff                	xor    %edi,%edi
  fa0893:	48 83 c4 40          	add    $0x40,%rsp
  fa0897:	5d                   	pop    %rbp
  fa0898:	c3                   	ret
  fa0899:	48 8d 05 42 18 22 01 	lea    0x1221842(%rip),%rax        # 0x21c20e2
  fa08a0:	bb 12 00 00 00       	mov    $0x12,%ebx
  fa08a5:	e8 f6 00 00 00       	call   0xfa09a0
  fa08aa:	48 89 c1             	mov    %rax,%rcx
  fa08ad:	48 89 df             	mov    %rbx,%rdi
  fa08b0:	31 c0                	xor    %eax,%eax
  fa08b2:	31 db                	xor    %ebx,%ebx
  fa08b4:	48 83 c4 40          	add    $0x40,%rsp
  fa08b8:	5d                   	pop    %rbp
  fa08b9:	c3                   	ret
  fa08ba:	48 8d 05 9f e0 cb 00 	lea    0xcbe09f(%rip),%rax        # 0x1c5e960
  fa08c1:	bb 02 00 00 00       	mov    $0x2,%ebx
  fa08c6:	48 89 d9             	mov    %rbx,%rcx
  fa08c9:	e8 b2 a1 4e ff       	call   0x48aa80
  fa08ce:	48 89 44 24 38       	mov    %rax,0x38(%rsp)
  fa08d3:	48 8b 54 24 50       	mov    0x50(%rsp),%rdx
  fa08d8:	48 8d 72 02          	lea    0x2(%rdx),%rsi
  fa08dc:	0f 1f 40 00          	nopl   0x0(%rax)
  fa08e0:	48 39 f0             	cmp    %rsi,%rax
  fa08e3:	74 07                	je     0xfa08ec
  fa08e5:	0f b7 4a 02          	movzwl 0x2(%rdx),%ecx
  fa08e9:	66 89 08             	mov    %cx,(%rax)
  fa08ec:	48 8d 05 8d 96 ee 00 	lea    0xee968d(%rip),%rax        # 0x1e89f80
  fa08f3:	e8 88 4d 48 ff       	call   0x425680
  fa08f8:	0f b7 4c 24 1e       	movzwl 0x1e(%rsp),%ecx
  fa08fd:	66 89 08             	mov    %cx,(%rax)
  fa0900:	48 c7 40 10 02 00 00 	movq   $0x2,0x10(%rax)
  fa0907:	00
  fa0908:	48 c7 40 18 02 00 00 	movq   $0x2,0x18(%rax)
  fa090f:	00
  fa0910:	83 3d 39 fa bc 02 00 	cmpl   $0x0,0x2bcfa39(%rip)        # 0x3b70350
  fa0917:	75 09                	jne    0xfa0922
  fa0919:	48 8b 54 24 38       	mov    0x38(%rsp),%rdx
  fa091e:	66 90                	xchg   %ax,%ax
  fa0920:	eb 0d                	jmp    0xfa092f
  fa0922:	e8 39 f2 4e ff       	call   0x48fb60
  fa0927:	48 8b 54 24 38       	mov    0x38(%rsp),%rdx
  fa092c:	49 89 13             	mov    %rdx,(%r11)
  fa092f:	48 89 50 08          	mov    %rdx,0x8(%rax)
  fa0933:	bb 04 00 00 00       	mov    $0x4,%ebx
  fa0938:	31 c9                	xor    %ecx,%ecx
  fa093a:	31 ff                	xor    %edi,%edi
  fa093c:	48 83 c4 40          	add    $0x40,%rsp
  fa0940:	5d                   	pop    %rbp
  fa0941:	c3                   	ret
  fa0942:	48 8d 05 14 50 21 01 	lea    0x1215014(%rip),%rax        # 0x21b595d
  fa0949:	bb 0c 00 00 00       	mov    $0xc,%ebx
  fa094e:	e8 4d 00 00 00       	call   0xfa09a0
  fa0953:	48 89 c1             	mov    %rax,%rcx
  fa0956:	48 89 df             	mov    %rbx,%rdi
  fa0959:	31 c0                	xor    %eax,%eax
  fa095b:	31 db                	xor    %ebx,%ebx
  fa095d:	48 83 c4 40          	add    $0x40,%rsp
  fa0961:	5d                   	pop    %rbp
  fa0962:	c3                   	ret
  fa0963:	48 89 44 24 08       	mov    %rax,0x8(%rsp)
  fa0968:	48 89 5c 24 10       	mov    %rbx,0x10(%rsp)
  fa096d:	48 89 4c 24 18       	mov    %rcx,0x18(%rsp)
  fa0972:	e8 89 d8 4e ff       	call   0x48e200
  fa0977:	48 8b 44 24 08       	mov    0x8(%rsp),%rax
  fa097c:	48 8b 5c 24 10       	mov    0x10(%rsp),%rbx
  fa0981:	48 8b 4c 24 18       	mov    0x18(%rsp),%rcx
  fa0986:	e9 f5 fd ff ff       	jmp    0xfa0780
  fa098b:	cc                   	int3
  fa098c:	cc                   	int3
  fa098d:	cc                   	int3
  fa098e:	cc                   	int3
  fa098f:	cc                   	int3
  fa0990:	cc                   	int3
  fa0991:	cc                   	int3
  fa0992:	cc                   	int3
  fa0993:	cc                   	int3
  fa0994:	cc                   	int3
  fa0995:	cc                   	int3
  fa0996:	cc                   	int3
  fa0997:	cc                   	int3
  fa0998:	cc                   	int3
  fa0999:	cc                   	int3
  fa099a:	cc                   	int3
  fa099b:	cc                   	int3
  fa099c:	cc                   	int3
  fa099d:	cc                   	int3
  fa099e:	cc                   	int3
  fa099f:	cc                   	int3
