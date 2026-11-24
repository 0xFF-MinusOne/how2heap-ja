# 訳語集

この翻訳で使っている訳語の方針です。

## 英語のまま使うもの

glibc のヒープの内部名と、攻撃手法の名前は、日本語の解説でも英語のまま使われることが多いため、訳していません。

| 用語 | 備考 |
|---|---|
| tcache | glibc 2.26 以降のスレッドごとのキャッシュ |
| fastbin / small bin / large bin / unsorted bin | 解放されたチャンクを管理する bin |
| top chunk | ヒープの末尾の、まだ使っていない領域 |
| arena / main_arena | |
| wilderness | top chunk の別名 |
| free list | 解放されたチャンクのリスト |
| double free | 同じチャンクを 2 回 free すること |
| safe-linking | tcache と fastbin の next ポインタの保護 |
| house of ○○、tcache poisoning など | 手法の名前 |

## 日本語にするもの

| 英語 | 日本語 |
|---|---|
| chunk | チャンク |
| pointer | ポインタ |
| free(する) | 解放(する) |
| allocate | 確保(する) |
| consolidation | 統合 |
| primitive | プリミティブ |
| bruteforce | ブルートフォース |
| use after free | UAF(use after free) |

## 訳さないもの

- 関数名、変数名、構造体名、マクロ名、ファイル名、コマンド名
- 著作者の表記
- glibc のソースコードを引用した部分
