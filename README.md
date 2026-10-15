# Bitwarden Merger

Bitwarden の保管庫に大量にできてしまった「同じパスワードのログインアイテム」を、
1件にまとめる（URI を統合する）ためのデスクトップツールです。Rust + egui 製で Windows / macOS / Linux で動作します。

## 仕組み

- 保管庫の操作は [Bitwarden CLI](https://bitwarden.com/help/cli/) (`bw`) を裏で呼び出して行います。
- **パスワードが一致するアイテム同士だけ**をマージ候補としてグループ化します（組織が異なるものは別グループ）。
  オプションでユーザー名の一致も条件にできます。
- マージでは「主アイテム」を1つ選び、他アイテムの URI（重複除去）・メモ・カスタムフィールド・TOTP を主アイテムへ統合し、
  統合元はゴミ箱へ移動します（`--permanent` は使わないので 30 日間は Web 保管庫から復元可能）。
- パスキーまたは添付ファイルを持つアイテムは、主アイテムにしない限り統合できません（失われるため）。

## ダウンロード

[Releases](https://github.com/ponkotuy/bitwarden-marger/releases/latest) から、使う OS のファイルをダウンロードして展開してください。

| OS | ファイル |
| --- | --- |
| Windows (x86_64) | `bitwarden-merger-<version>-windows-x86_64.zip` |
| macOS (Apple Silicon / Intel) | `bitwarden-merger-<version>-macos-universal.tar.gz` |
| Linux (x86_64) | `bitwarden-merger-<version>-linux-x86_64.tar.gz` |

- 展開した中の `bitwarden-merger`（Windows は `bitwarden-merger.exe`）が本体です。
- チェックサムは `SHA256SUMS.txt` で確認できます。
- macOS 版は署名していないため、初回は Gatekeeper にブロックされます。右クリック →「開く」で起動するか、次のコマンドで隔離属性を外してください。
  ```sh
  xattr -d com.apple.quarantine bitwarden-merger
  ```

ソースからビルドする場合は `cargo build --release` を実行します（Rust 1.85 以降が必要）。

## 使い方

1. `bw` をインストールし、ターミナルで一度ログインしておきます。
   ```sh
   bw config server https://your.server   # セルフホストの場合のみ
   bw login
   ```
2. `bitwarden-merger` を起動し（ソースからなら `cargo run --release`）、マスターパスワードでロック解除します。
3. 左の候補グループを選び、統合するアイテムと主アイテムを選んで「マージ実行」。

環境変数:

| 変数 | 内容 |
| --- | --- |
| `BW_CLI_PATH` | `bw` の場所を明示する（未設定なら PATH から探す） |
| `BWM_FONT` | 日本語表示に使うフォントファイル（未設定なら OS 標準の CJK フォントを探す） |

## セキュリティ上の配慮

- アイテムのパスワード・TOTP は読み込み直後にプロセスごとのランダム鍵による BLAKE3 keyed hash に変換し、平文は保持しません。
  一致判定はハッシュ同士で行います。
- `bw` の出力や編集用 JSON などパスワードを含むバッファは `zeroize` で使用後にゼロ埋めします。
- 書き込み時はアイテム JSON を標準入力で `bw` に渡します（コマンドライン引数に載せない）。
- マージ直前に最新のアイテムを取得し直し、パスワードが一覧取得時のハッシュと一致することを再検証します。
- セッションキーはワーカースレッド内だけで保持し、終了時に `bw lock` します。親シェルの `BW_SESSION` は引き継ぎません。

### 限界

- `bw edit item` は渡した JSON でアイテム全体を置き換える仕様のため、マージ実行の瞬間だけは主アイテムの平文パスワードがメモリ上に存在します（直後にゼロ埋め）。
- マスターパスワードは環境変数経由で `bw unlock` に渡します。子プロセスの環境変数は同一ユーザーからは読める点に注意してください。
- egui / OS / Node.js (`bw`) 内部でのコピーまでは制御できません。
