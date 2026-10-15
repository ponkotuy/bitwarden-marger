//! 秘密情報の取り扱い。
//!
//! パスワードや TOTP シードは平文で保持せず、プロセス起動ごとに生成する
//! ランダム鍵を用いた BLAKE3 keyed hash に変換してからメモリに置く。
//! 鍵がプロセス外に出ることはないため、ハッシュ値が漏れても辞書攻撃に使えない。

use std::fmt;
use std::ops::Range;

use eframe::egui::TextBuffer;
use eframe::egui::text::CharIndex;
use zeroize::{Zeroize, Zeroizing};

/// 秘密値の keyed hash。比較・グルーピング専用で、元の値は復元できない。
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct SecretHash([u8; 32]);

impl fmt::Debug for SecretHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretHash(..)")
    }
}

/// プロセス固有の鍵で秘密値をハッシュ化する。
pub struct SecretHasher {
    key: Zeroizing<[u8; 32]>,
}

impl SecretHasher {
    pub fn new() -> anyhow::Result<Self> {
        let mut key = Zeroizing::new([0u8; 32]);
        getrandom::fill(&mut *key).map_err(|e| anyhow::anyhow!("乱数の取得に失敗しました: {e}"))?;
        Ok(Self { key })
    }

    pub fn hash(&self, secret: &str) -> SecretHash {
        let mut hash = *blake3::keyed_hash(&self.key, secret.as_bytes()).as_bytes();
        let out = SecretHash(hash);
        hash.zeroize();
        out
    }

    /// 空文字列は「値なし」として扱う。
    pub fn hash_opt(&self, secret: Option<&str>) -> Option<SecretHash> {
        secret.filter(|s| !s.is_empty()).map(|s| self.hash(s))
    }
}

/// マスターパスワード入力用のテキストバッファ。
///
/// 再確保で古い領域に平文が残らないよう容量を先に確保し、
/// drop 時にはゼロ埋めする。
pub struct SecretInput(Zeroizing<String>);

impl SecretInput {
    const CAPACITY: usize = 1024;

    pub fn new() -> Self {
        Self(Zeroizing::new(String::with_capacity(Self::CAPACITY)))
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// 中身を取り出し、自身は空の新しいバッファに置き換える。
    pub fn take_secret(&mut self) -> Zeroizing<String> {
        std::mem::replace(self, Self::new()).0
    }
}

impl TextBuffer for SecretInput {
    fn is_mutable(&self) -> bool {
        true
    }

    fn as_str(&self) -> &str {
        self.0.as_str()
    }

    fn insert_text(&mut self, text: &str, char_index: CharIndex) -> usize {
        if self.0.len() + text.len() > self.0.capacity() {
            // 再確保させない。上限を超える入力は捨てる。
            return 0;
        }
        TextBuffer::insert_text(&mut *self.0, text, char_index)
    }

    fn delete_char_range(&mut self, char_range: Range<CharIndex>) {
        TextBuffer::delete_char_range(&mut *self.0, char_range);
    }

    fn type_id(&self) -> std::any::TypeId {
        std::any::TypeId::of::<Self>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_secret_same_hash() {
        let h = SecretHasher::new().unwrap();
        assert_eq!(h.hash("hunter2"), h.hash("hunter2"));
        assert_ne!(h.hash("hunter2"), h.hash("hunter3"));
    }

    #[test]
    fn different_process_key_different_hash() {
        let a = SecretHasher::new().unwrap();
        let b = SecretHasher::new().unwrap();
        assert_ne!(a.hash("hunter2"), b.hash("hunter2"));
    }

    #[test]
    fn empty_is_none() {
        let h = SecretHasher::new().unwrap();
        assert!(h.hash_opt(Some("")).is_none());
        assert!(h.hash_opt(None).is_none());
    }
}
