> これは [shellphish/how2heap](https://github.com/shellphish/how2heap) の日本語訳です。原著のライセンス (MIT) に従います。
> 訳したのは説明文とコメントのみで、コードは原著のままです。対象は各技法の最新の glibc バージョンのファイルです(古いバージョンのディレクトリは原文のままです)。

# 学習用ヒープエクスプロイト(Heap Exploitation)

このリポジトリは、さまざまなヒープエクスプロイトの技法を学ぶためのものです。
基準には Ubuntu の Libc リリースを使っています。各技法は、対応する Ubuntu のリリースで動作することを確認済みです。
Debian 系のオペレーティングシステムでは、`apt source libc6` を実行すると、使っている Libc のソースコードをダウンロードできます。表の「ブラウザ」列のリンク(外部サイト)を開くと、ブラウザ上で gdb を使って技法をデバッグすることもできます。

このアイデアはハックミーティングの最中に思いつき、以下の技法を実装しました。

| ファイル | ブラウザ | 技法 | Glibc バージョン | パッチ | 該当する CTF 問題 |
|------|-----|-----------|---------------|-------|---------------------------|
| [first_fit.c](first_fit.c) | |  glibc の malloc の first-fit(空き領域のうち最初に見つかった適合領域を使う)動作を示します。 | | | |
| [calc_tcache_idx.c](calc_tcache_idx.c)| |  glibc の tcache(スレッドごとのキャッシュ、thread cache)のインデックス計算を示します。| | | |
| [fastbin_dup.c](glibc_2.35/fastbin_dup.c) | [ブラウザで試す](https://wargames.ret2.systems/level/how2heap_fastbin_dup_2.34) | fastbinのfree listを悪用して、malloc に確保済みのヒープポインタを返させます。 | < 2.43 | [patch](https://sourceware.org/git/?p=glibc.git;a=blobdiff;f=malloc/malloc.c;h=fa854fc4b8f75b09902ea7ed1180487beb6e4683;hp=7811152d9d9eba3e0f0a3416d9944cc142caaafe;hb=bf1015fb2d7e4057925481960626533f8571a2fb;hpb=e3062b06c5767f672baf9574c4d7cbebf7d0ee6e) | |
| [fastbin_dup_into_stack.c](glibc_2.35/fastbin_dup_into_stack.c) | [ブラウザで試す](https://wargames.ret2.systems/level/how2heap_fastbin_dup_into_stack_2.23) | fastbin のfree listを悪用して、malloc にほぼ任意のポインタを返させます。 | < 2.43 | [patch](https://sourceware.org/git/?p=glibc.git;a=blobdiff;f=malloc/malloc.c;h=fa854fc4b8f75b09902ea7ed1180487beb6e4683;hp=7811152d9d9eba3e0f0a3416d9944cc142caaafe;hb=bf1015fb2d7e4057925481960626533f8571a2fb;hpb=e3062b06c5767f672baf9574c4d7cbebf7d0ee6e) | [9447-search-engine](https://github.com/ctfs/write-ups-2015/tree/master/9447-ctf-2015/exploitation/search-engine), [0ctf 2017-babyheap](https://web.archive.org/web/20181104155842/http://uaf.io/exploitation/2017/03/19/0ctf-Quals-2017-BabyHeap2017.html) |
| [fastbin_dup_consolidate.c](glibc_2.35/fastbin_dup_consolidate.c) | [ブラウザで試す](https://wargames.ret2.systems/level/how2heap_fastbin_dup_consolidate_2.23) | fastbin のfree listとtop chunkの両方にポインタを置くことで、malloc に確保済みのヒープポインタを返させます。 | < 2.43 | [patch](https://sourceware.org/git/?p=glibc.git;a=blobdiff;f=malloc/malloc.c;h=fa854fc4b8f75b09902ea7ed1180487beb6e4683;hp=7811152d9d9eba3e0f0a3416d9944cc142caaafe;hb=bf1015fb2d7e4057925481960626533f8571a2fb;hpb=e3062b06c5767f672baf9574c4d7cbebf7d0ee6e) | [Hitcon 2016 SleepyHolder](https://github.com/mehQQ/public_writeup/tree/master/hitcon2016/SleepyHolder) |
| [unsafe_unlink.c](glibc_2.35/unsafe_unlink.c) | [ブラウザで試す](https://wargames.ret2.systems/level/how2heap_unsafe_unlink_2.34) | 破損したチャンクに対する free を悪用して、任意書き込みを得ます。 | latest | | [HITCON CTF 2014-stkof](http://acez.re/ctf-writeup-hitcon-ctf-2014-stkof-or-modern-heap-overflow/), [Insomni'hack 2017-Wheel of Robots](https://gist.github.com/niklasb/074428333b817d2ecb63f7926074427a) |
| [house_of_spirit.c](glibc_2.35/house_of_spirit.c) | [ブラウザで試す](https://wargames.ret2.systems/level/how2heap_house_of_spirit_2.23) | 偽の fastbin チャンクを free して、malloc にほぼ任意のポインタを返させます。 | latest | | [hack.lu CTF 2014-OREO](https://github.com/ctfs/write-ups-2014/tree/master/hack-lu-ctf-2014/oreo) |
| [poison_null_byte.c](glibc_2.35/poison_null_byte.c) | [ブラウザで試す](https://wargames.ret2.systems/level/how2heap_poison_null_byte_2.34) | null バイト1バイトのオーバーフローを悪用します。 | latest | | [PlaidCTF 2015-plaiddb](https://github.com/ctfs/write-ups-2015/tree/master/plaidctf-2015/pwnable/plaiddb), [BalsnCTF 2019-PlainNote](https://gist.github.com/st424204/6b5c007cfa2b62ed3fd2ef30f6533e94?fbclid=IwAR3n0h1WeL21MY6cQ_C51wbXimdts53G3FklVIHw2iQSgtgGo0kR3Lt-1Ek)|
| [house_of_lore.c](glibc_2.35/house_of_lore.c) | [ブラウザで試す](https://wargames.ret2.systems/level/how2heap_house_of_lore_2.34) | small binのfree listを悪用して、malloc にほぼ任意のポインタを返させます。 | latest | | |
| [overlapping_chunks.c](glibc_2.27/overlapping_chunks.c) | [ブラウザで試す](https://wargames.ret2.systems/level/how2heap_overlapping_chunks_2.34) | unsorted bin内の解放済みチャンクのサイズを上書きして、新しい確保領域を既存のチャンクと重ねます。 | < 2.29 | [patch](https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=b90ddd08f6dd688e651df9ee89ca3a69ff88cd0c) | [hack.lu CTF 2015-bookstore](https://github.com/ctfs/write-ups-2015/tree/master/hack-lu-ctf-2015/exploiting/bookstore), [Nuit du Hack 2016-night-deamonic-heap](https://github.com/ctfs/write-ups-2016/tree/master/nuitduhack-quals-2016/exploit-me/night-deamonic-heap-400) |
| [overlapping_chunks_2.c](glibc_2.23/overlapping_chunks_2.c) | [ブラウザで試す](https://wargames.ret2.systems/level/how2heap_overlapping_chunks_2_2.23) | 使用中チャンクのサイズを上書きして、新しい確保領域を既存のチャンクと重ねます。  | < 2.29|[patch](https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=b90ddd08f6dd688e651df9ee89ca3a69ff88cd0c) | |
| [mmap_overlapping_chunks.c](glibc_2.35/mmap_overlapping_chunks.c) | |  使用中の mmap チャンクを悪用して、新しい確保領域を現在の mmap チャンクと重ねます。 | latest | | |
| [house_of_force.c](glibc_2.27/house_of_force.c) | [ブラウザで試す](https://wargames.ret2.systems/level/how2heap_house_of_force_2.27) | top chunk(Wilderness)のヘッダを悪用して、malloc にほぼ任意のポインタを返させます。 | < 2.29 | [patch](https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=30a17d8c95fbfb15c52d1115803b63aaa73a285c) | [Boston Key Party 2016-cookbook](https://github.com/ctfs/write-ups-2016/tree/master/boston-key-party-2016/pwn/cookbook-6), [BCTF 2016-bcloud](https://github.com/ctfs/write-ups-2016/tree/master/bctf-2016/exploit/bcloud-200) |
| [unsorted_bin_into_stack.c](glibc_2.27/unsorted_bin_into_stack.c) | [ブラウザで試す](https://wargames.ret2.systems/level/how2heap_unsorted_bin_into_stack_2.23) | unsorted bin のfree list上にある解放済みチャンクの上書きを悪用して、ほぼ任意のポインタを返させます。  | < 2.29 | [patch](https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=b90ddd08f6dd688e651df9ee89ca3a69ff88cd0c)| |
| [unsorted_bin_attack.c](glibc_2.27/unsorted_bin_attack.c) | [ブラウザで試す](https://wargames.ret2.systems/level/how2heap_unsorted_bin_attack_2.27) | unsorted bin のfree list上にある解放済みチャンクの上書きを悪用して、任意のアドレスに大きな値を書き込みます。  | < 2.29 | [patch](https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=b90ddd08f6dd688e651df9ee89ca3a69ff88cd0c) | [0ctf 2016-zerostorage](https://github.com/ctfs/write-ups-2016/tree/master/0ctf-2016/exploit/zerostorage-6) |
| [large_bin_attack.c](glibc_2.35/large_bin_attack.c) | [ブラウザで試す](https://wargames.ret2.systems/level/how2heap_large_bin_attack_2.34) | large binのfree list上にある解放済みチャンクの上書きを悪用して、任意のアドレスに大きな値を書き込みます。  | < 2.42 | [patch](https://patchwork.sourceware.org/project/glibc/patch/20250214053454.2346370-1-benjamin.p.kallus.gr@dartmouth.edu/) | [0ctf 2018-heapstorm2](https://dangokyo.me/2018/04/07/0ctf-2018-pwn-heapstorm2-write-up/) |
| [house_of_einherjar.c](glibc_2.35/house_of_einherjar.c) | [ブラウザで試す](https://wargames.ret2.systems/level/how2heap_house_of_einherjar_2.34) | null バイト1バイトのオーバーフローを悪用して、malloc に制御可能なポインタを返させます。  | latest | | [Seccon 2016-tinypad](https://gist.github.com/hhc0null/4424a2a19a60c7f44e543e32190aaabf) |
| [house_of_water.c](glibc_2.36/house_of_water.c) | | UAF(use after free)または double free を悪用して、リークなしで tcache のメタデータを制御し、リークなしで libc を tcache にリンクします。 | latest | | [37c3 Potluck - Tamagoyaki](https://github.com/UDPctf/CTF-challenges/tree/main/Potluck-CTF-2023/Tamagoyaki)|
| [sysmalloc_int_free.c](glibc_2.39/sysmalloc_int_free.c) | | malloc(sysmalloc の `_int_free()`)を使って、ほぼ任意のサイズのtop chunk(Wilderness)を解放する例を示します。 | latest | | |
| [house_of_orange.c](glibc_2.23/house_of_orange.c) | [ブラウザで試す](https://wargames.ret2.systems/level/how2heap_house_of_orange_2.23) | top chunk(Wilderness)を悪用して、任意コード実行を得ます。  | < 2.26 | [patch](https://sourceware.org/git/?p=glibc.git;a=blobdiff;f=stdlib/abort.c;h=117a507ff88d862445551f2c07abb6e45a716b75;hp=19882f3e3dc1ab830431506329c94dcf1d7cc252;hb=91e7cf982d0104f0e71770f5ae8e3faf352dea9f;hpb=0c25125780083cbba22ed627756548efe282d1a0) | [Hitcon 2016 houseoforange](https://github.com/ctfs/write-ups-2016/tree/master/hitcon-ctf-2016/pwn/house-of-orange-500) |
| [house_of_tangerine.c](glibc_2.39/house_of_tangerine.c) |  | top chunk(Wilderness)を悪用し、tcache のfree listを悪用して、malloc に完全に任意のポインタを返させます。 | >= 2.26 |  | [PicoCTF 2024- high frequency troubles](https://learn.cylabacademy.org/library/441?page=1&search=high+frequency+troubles) |
| [house_of_roman.c](glibc_2.23/house_of_roman.c) | [ブラウザで試す](https://wargames.ret2.systems/level/how2heap_house_of_roman_2.23) | 偽の fastbin、unsorted\_bin attack、相対上書き(relative overwrite)を使って、リークなしでリモートコード実行を得る技法です。 |< 2.29 |[patch](https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=b90ddd08f6dd688e651df9ee89ca3a69ff88cd0c) ||
| [tcache_poisoning.c](glibc_2.35/tcache_poisoning.c) | [ブラウザで試す](https://wargames.ret2.systems/level/how2heap_tcache_poisoning_2.34) | tcache のfree listを悪用して、malloc に完全に任意のポインタを返させます。(2.32 以降はヒープのリークが必要です) | > 2.25  | [patch](https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=a1a486d70ebcc47a686ff5846875eacad0940e41) | |
| [tcache_house_of_spirit.c](glibc_2.35/tcache_house_of_spirit.c) | [ブラウザで試す](https://wargames.ret2.systems/level/how2heap_tcache_house_of_spirit_2.34) | 偽のチャンクを free して、malloc にほぼ任意のポインタを返させます。 | > 2.25 | | |
| [house_of_botcake.c](glibc_2.35/house_of_botcake.c) | [ブラウザで試す](https://wargames.ret2.systems/level/how2heap_house_of_botcake_2.34) | tcache の double free 対策を回避します。`tcache_dup` をもう一度使えるようにします。 | > 2.25 | | |
| [tcache_stashing_unlink_attack.c](glibc_2.35/tcache_stashing_unlink_attack.c) | [ブラウザで試す](https://wargames.ret2.systems/level/how2heap_tcache_stashing_unlink_attack_2.34) | small bin のfree list上にある解放済みチャンクの上書きを悪用して、malloc に任意のポインタを返させ、さらに calloc を利用して任意のアドレスに大きな値を書き込みます。 | > 2.25 | | [Hitcon 2019 one punch man](https://github.com/xmzyshypnc/xz_files/tree/master/hitcon2019_one_punch_man) |
| [fastbin_reverse_into_tcache.c](glibc_2.35/fastbin_reverse_into_tcache.c) | [ブラウザで試す](https://wargames.ret2.systems/level/how2heap_fastbin_reverse_into_tcache_2.34) | fastbin 内の解放済みチャンクの上書きを悪用して、任意のアドレスに大きな値を書き込みます。 | 2.26 - 2.42 | [patch](https://sourceware.org/git/?p=glibc.git;a=blobdiff;f=malloc/malloc.c;h=fa854fc4b8f75b09902ea7ed1180487beb6e4683;hp=7811152d9d9eba3e0f0a3416d9944cc142caaafe;hb=bf1015fb2d7e4057925481960626533f8571a2fb;hpb=e3062b06c5767f672baf9574c4d7cbebf7d0ee6e) | |
| [house_of_mind_fastbin.c](glibc_2.35/house_of_mind_fastbin.c) | [ブラウザで試す](https://wargames.ret2.systems/level/how2heap_house_of_mind_fastbin_2.34) | arenaの扱いを利用した1バイトの上書きを悪用して、任意のアドレスに大きな値(ヒープポインタ)を書き込みます。 | < 2.43 | [patch](https://sourceware.org/git/?p=glibc.git;a=blobdiff;f=malloc/malloc.c;h=fa854fc4b8f75b09902ea7ed1180487beb6e4683;hp=7811152d9d9eba3e0f0a3416d9944cc142caaafe;hb=bf1015fb2d7e4057925481960626533f8571a2fb;hpb=e3062b06c5767f672baf9574c4d7cbebf7d0ee6e) | |
| [house_of_storm.c](glibc_2.27/house_of_storm.c) | [ブラウザで試す](https://wargames.ret2.systems/level/how2heap_house_of_storm_2.27) | large bin と unsorted bin 両方のチャンクに対する use after free を悪用して、malloc から任意のチャンクを返させます。| < 2.29 | | |
| [house_of_gods.c](glibc_2.24/house_of_gods.c) | [ブラウザで試す](https://wargames.ret2.systems/level/how2heap_house_of_gods_2.24) | 8回の確保以内にスレッドのarenaを乗っ取る技法です。 | < 2.27 | | |
| [decrypt_safe_linking.c](glibc_2.35/decrypt_safe_linking.c) | [ブラウザで試す](https://wargames.ret2.systems/level/how2heap_decrypt_safe_linking_2.34) | 連結リスト内の汚染された値を復号して、実際のポインタを復元します。 | >= 2.32 | | |
| [safe_link_double_protect.c](glibc_2.36/safe_link_double_protect.c) | | ポインタを二重に保護することで、リークなしで PROTECT_PTR を回避し、tcache に任意のポインタをリンクできるようにします。 | >= 2.32 | | [37c3 Potluck - Tamagoyaki](https://github.com/UDPctf/CTF-challenges/tree/main/Potluck-CTF-2023/Tamagoyaki)|
| [tcache_dup.c](obsolete/glibc_2.27/tcache_dup.c)(廃止) | |  tcache のfree listを悪用して、malloc に確保済みのヒープポインタを返させます。 | 2.26 - 2.28 | [patch](https://sourceware.org/git/?p=glibc.git;a=commit;h=bcdaad21d4635931d1bd3b54a7894276925d081d) | |
| [tcache_metadata_poisoning.c](glibc_2.27/tcache_metadata_poisoning.c) | | tcache のメタデータ構造体を操作して、tcache に任意のポインタを返させます。 | >= 2.26 | | |
| [house_of_io.c](glibc_2.31/house_of_io.c) | | 解放済みの tcache チャンクに対する UAF で tcache の管理構造体を操作し、malloc に任意のメモリへのポインタを返させます。 | 2.31 - 2.33 | | |
| [tcache_relative_write.c](glibc_2.41/tcache_relative_write.c) | | tcache メタデータへの範囲外書き込みによって、ヒープ内に任意の10進数値とチャンクポインタを書き込みます。 | 2.30-2.41 | [patch](https://sourceware.org/git/?p=glibc.git;a=commit;h=cbfd7988107b27b9ff1d0b57fa2c8f13a932e508) | |
| [tcache_metadata_hijacking](glibc_2.42/tcache_metadata_hijacking.c) | | tcache メタデータへのオーバーフローによって、任意の場所に確保させます。 | >= 2.42 | | |

GNU libc(GnuLibc)は継続的に開発されており、上記の技法のいくつかをきっかけに、malloc/free の処理に整合性チェックが導入されました。
その結果、これらのチェックによって一部の技法が定期的に動かなくなり、回避するための調整が(可能であれば)必要になります。
この問題には、調整が必要になった Glibc リリースごとに、同じ技法の複数のバージョンを保持することで対応しています。
構成は `glibc_<version>/technique.c` です。

よい例はありますか?
ここに追加してください!
技法全体を1つの `.c` ファイルにまとめるようにしてください。その方がずっと学びやすくなります。

# はじめに

## クイックセットアップ

- 次のパッケージ/ツールがインストールされていることを確認してください: `patchelf zstd wget`(もちろん、コンパイラ用の `build-essential` などや `make` なども必要です)
- また、`/usr/bin/python` は、お使いの `python` バイナリ(例: `/usr/bin/python3`)であるか、そこを指している必要があります

```shell
git clone https://github.com/shellphish/how2heap
cd how2heap
make clean base
./malloc_playground
```
これではバイナリがシステムの libc にリンクされる点に注意してください。ほかの libc バージョンで試したい場合は、`Complete Setup` を参照してください。

## 完全なセットアップ(Complete Setup)

ホストマシンでコンパイルしたバイナリに対して libc を `LD_PRELOAD` しようとすると、シンボルバージョニングの問題([こちら](https://github.com/shellphish/how2heap/issues/169)を参照)が発生します。
これを回避する方法は2つあります。

### 方法1: 古い libc に対してリンクする
この方法では、対象のバイナリを対象の libc にリンクするようリンカに指示します。
```shell
git clone https://github.com/shellphish/how2heap
cd how2heap
H2H_USE_SYSTEM_LIBC=N make v2.23
```
これにより、すべてのバイナリが対応する libc にリンクされます。さらに、デバッグシンボルも付いてきます。これで、ホストマシン上で任意の libc バージョンを試せます。
この例では、glibc-2.23 用のバイナリをすべてコンパイルして libc-2.23 にリンクします。数字を変えれば、ほかの libc バージョンも試せます。

### 方法2: docker を使う
この方法では Docker を使い、古い ubuntu のコンテナ内でバイナリをコンパイルして、対象の libc バージョンで実行できるようにします。

```shell
git clone https://github.com/shellphish/how2heap
cd how2heap

# 次のコマンドは、期待する libc バージョンで動くように
# 対象のバイナリを準備します
make base
./glibc_run.sh 2.30 ./malloc_playground -d -p

# これで glibc-2.30 でバイナリを試せます。
# 正しいシンボル付きでデバッグすることもできます
readelf -d -W malloc_playground | grep RUNPATH # または checksec を使います
readelf -l -W malloc_playground | grep interpreter
gdb -q -ex "start" ./malloc_playground
```

# ヒープエクスプロイト用ツール

ヒープエクスプロイトに使えるツールが、いくつか出回っています。

## Malloc Playground

付属の `malloc_playground.c` は、メモリの確保と解放のコマンドを対話的に入力して実行するプログラムのソースです。

## Pwngdb

gdb で glibc のヒープを調べます: https://github.com/scwuaptx/Pwngdb

## pwndbg

エクスプロイトに重点を置いた gdb プラグインで、glibc のヒープを閲覧・改変できます: https://github.com/pwndbg/pwndbg

## gef

glibc のヒープを調べられる、もう1つの優れた gdb プラグインです: https://github.com/hugsy/gef

## heap-viewer

IDA Pro で glibc のヒープを調べます: https://github.com/danigargu/heap-viewer

## heaptrace

アドレスをシンボルに置き換えて、ヒープ操作を見やすくします: https://github.com/Arinerron/heaptrace

# その他のリソース

ヒープエクスプロイトに関する優れたリソースを、おおむね公開が新しい順に挙げます。

## 役立つヒープエクスプロイトのチュートリアル
- Overview of GLIBC heap exploitation techniques (https://0x434b.dev/overview-of-glibc-heap-exploitation-techniques/) <!-- 2022 -->
- glibc in-depth tutorial (https://heap-exploitation.dhavalkapil.com/) - 書籍とエクスプロイトのサンプル <!-- 2022 -->
- Heap exploitation techniques that work on glibc-2.31 (https://github.com/StarCross-Tech/heap_exploit_2.31) <!-- 2020 -->
- Painless intro to the Linux userland heap (https://sensepost.com/blog/2017/painless-intro-to-the-linux-userland-heap/) <!-- 2017 -->
- ptmalloc fanzine, a set of resources and examples related to meta-data attacks on ptmalloc (http://tukan.farm/2016/07/26/ptmalloc-fanzine/) <!-- 2016 -->
- Glibc Adventures: The Forgotten Chunk (https://github.com/bash-c/slides/blob/master/pwn_heap/Glibc%20Adventures:%20The%20forgotten%20chunks.pdf) - 高度なヒープエクスプロイト <!-- 2015 -->

## ヒープエクスプロイトの歴史(The History)
- Pseudomonarchia jemallocum (http://www.phrack.org/issues/68/10.html) <!-- 2012 -->
- The House Of Lore: Reloaded (http://phrack.org/issues/67/8.html) <!-- 2010 -->
- Malloc Des-Maleficarum (http://phrack.org/issues/66/10.html) - malloc エクスプロイトの技法いくつか <!-- 2009 -->
- Yet another free() exploitation technique (http://phrack.org/issues/66/6.html) <!-- 2009 -->
- The use of set_head to defeat the wilderness (http://phrack.org/issues/64/9.html) <!-- 2007 -->
- Understanding the heap by breaking it (https://www.blackhat.com/presentations/bh-usa-07/Ferguson/Whitepaper/bh-usa-07-ferguson-WP.pdf) - ヒープの実装と、いくつかのエクスプロイトを解説 <!-- 2007 -->
- OS X heap exploitation techniques (http://phrack.org/issues/63/5.html) <!-- 2005 -->
- The Malloc Maleficarum (http://seclists.org/bugtraq/2005/Oct/118) <!-- 2005 -->
- Exploiting The Wilderness (http://seclists.org/vuln-dev/2004/Feb/25) <!-- 2004 -->
- Advanced Doug lea's malloc exploits (http://phrack.org/issues/61/6.html) <!-- 2003 -->

# ハードニング(Hardening)
glibc には、いくつかの「ハードニング」対策が組み込まれています。たとえば、`export MALLOC_CHECK_=1`(一部のチェックを有効にします)、`export MALLOC_PERTURB_=1`(データを上書きします)、`export MALLOC_MMAP_THRESHOLD_=1`(常に mmap() を使います)などです。

詳細: [mcheck()](http://www.gnu.org/software/libc/manual/html_node/Heap-Consistency-Checking.html), [mallopt()](http://www.gnu.org/software/libc/manual/html_node/Malloc-Tunable-Parameters.html).

トレース用の機能として、 [mtrace()](http://manpages.ubuntu.com/mtrace), [malloc_stats()](http://manpages.ubuntu.com/malloc_stats), [malloc_info()](http://manpages.ubuntu.com/malloc_info), [memusage](http://manpages.ubuntu.com/memusage)、およびこの系統のその他の関数もあります。

