#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

long decrypt(long cipher)
{
	puts("この復号は、平文 (fwd ポインタ) の最初の 12 ビットが既知であるという事実を利用します。");
	puts("12 ビットのシフトがあるためです。");
	puts("また、鍵である ASLR の値は、平文 (fwd ポインタ) の上位ビットと同じです。");
	long key = 0;
	long plain;

	for(int i=1; i<6; i++) {
		int bits = 64-12*i;
		if(bits < 0) bits = 0;
		plain = ((cipher ^ key) >> bits) << bits;
		key = plain >> 12;
		printf("round %d:\n", i);
		printf("key:    %#016lx\n", key);
		printf("plain:  %#016lx\n", plain);
		printf("cipher: %#016lx\n\n", cipher);
	}
	return plain;
}

int main()
{
	/*
	 * この技法は、safe-linking の仕組みによって加工 (poison) された値から、
	 * 元の内容を復元する方法を示します。
	 * この攻撃は、平文 (ポインタ) の最初の 12 ビットが既知であり、
	 * 鍵 (ASLR のスライド) がポインタの上位ビットと同じであるという事実を利用します。
	 * その結果、ポインタが格納されているチャンクがポインタ自身と同じページにある限り、
	 * ポインタの値を完全に復元できます。
	 * そうでない場合でも、格納側とポインタとのページオフセットを使ってポインタを復元できます。
	 * ここで示すのは、ページオフセットが 0 である特別な場合です。
	 * その他のより一般的な場合のデモについては、次を参照してください: 
	 * https://github.com/n132/Dec-Safe-Linking
	 */

	setbuf(stdin, NULL);
	setbuf(stdout, NULL);

	// ステップ 1: チャンクを確保します
	long *a = malloc(0x20);
	long *b = malloc(0x20);
	printf("まず、チャンク a (%p) とチャンク b (%p) を作成します\n", a, b);
	malloc(0x10);
	puts("次に、併合 (consolidation) を防ぐためのパディング用チャンクを作成します。");


	// ステップ 2: チャンクを解放します
	puts("ここで、チャンク a を解放し、続けてチャンク b を解放します。");
	free(a);
	free(b);
	printf("これでfree list (freelist) は [%p -> %p] になりました\n", b, a);
	printf("safe-linking のため、b[0] に実際に格納されている値は次のとおりです: %#lx\n", b[0]);

	// ステップ 3: 値を復元します
	puts("加工された値を復号します");
	long plaintext = decrypt(b[0]);

	printf("値: %p\n", a);
	printf("復元した値: %#lx\n", plaintext);
	assert(plaintext == (long)a);
}
