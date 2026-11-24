ヒープ保護に関する主な変更の ChangeLog
--------------------------------------------

## Version 2.25

このリポジトリのすべての攻撃は、少なくともこのバージョンで動作します。

## Version 2.26

- tcache(スレッドごとのキャッシュ、per-thread cache)が導入されました(ubuntu のビルドでは 2.27 から有効です)
    * 概要は [tukan.farm](http://tukan.farm/2017/07/08/tcache/) を参照してください
    

- `unlink(AV, P, BK, FD)`:
    * サイズの整合性チェックを追加しました:
        ```
            if (__builtin_expect (chunksize(P) != prev_size (next_chunk(P)), 0))
              malloc_printerr ("corrupted size vs. prev_size");
        ```

## Version 2.27

- `malloc_consolidate(mstate av)`:
    * チャンクを fastbin に置く際のサイズチェックを追加しました:
        ```
        unsigned int idx = fastbin_index (chunksize (p));
        if ((&fastbin (av, idx)) != fb)
          malloc_printerr ("malloc_consolidate(): invalid chunk size");
        ```
