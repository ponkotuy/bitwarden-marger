//! Bitwarden CLI (`bw`) のラッパー。
//!
//! - セッションキーはこの構造体の中だけに保持し、子プロセスへは環境変数で渡す。
//! - 子プロセスの標準出力（平文パスワードを含みうる）は `Zeroizing` で受け取る。
//! - アイテムの JSON はコマンドライン引数ではなく標準入力で渡す（`ps` から見えないように）。

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use anyhow::{Context, bail};
use base64::Engine;
use serde::Deserialize;
use serde_json::Value;
use zeroize::{Zeroize, Zeroizing};

use crate::model::{LoginItem, UriEntry};
use crate::secret::SecretHasher;

const PASSWORD_ENV: &str = "BWM_MASTER_PASSWORD";

pub struct BwCli {
    program: PathBuf,
    session: Option<Zeroizing<String>>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusInfo {
    pub server_url: Option<String>,
    pub user_email: Option<String>,
    pub status: String,
}

impl BwCli {
    /// `BW_CLI_PATH` 環境変数、なければ PATH から `bw` を探す。
    /// Windows では npm 版の `bw.cmd` も PATHEXT 経由で見つかる。
    pub fn locate() -> anyhow::Result<Self> {
        let program = match std::env::var_os("BW_CLI_PATH") {
            Some(p) => PathBuf::from(p),
            None => which::which("bw").context(
                "Bitwarden CLI (bw) が見つかりません。インストールするか BW_CLI_PATH を設定してください",
            )?,
        };
        Ok(Self {
            program,
            session: None,
        })
    }

    pub fn is_unlocked(&self) -> bool {
        self.session.is_some()
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(&self.program);
        cmd.arg("--nointeraction")
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            // 親シェルから継承したセッションは使わず、このアプリで開いたセッションだけを使う
            .env_remove("BW_SESSION");
        if let Some(session) = &self.session {
            cmd.env("BW_SESSION", session.as_str());
        }
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x0800_0000;
            cmd.creation_flags(CREATE_NO_WINDOW);
        }
        cmd
    }

    fn run(&self, mut cmd: Command, stdin: Option<&[u8]>) -> anyhow::Result<Zeroizing<Vec<u8>>> {
        if stdin.is_some() {
            cmd.stdin(Stdio::piped());
        }
        let mut child = cmd
            .spawn()
            .with_context(|| format!("{} を起動できません", self.program.display()))?;
        if let Some(input) = stdin {
            let mut pipe = child.stdin.take().expect("stdin is piped");
            pipe.write_all(input).context("bw への入力に失敗しました")?;
        }
        let output = child
            .wait_with_output()
            .context("bw の実行に失敗しました")?;
        let stdout = Zeroizing::new(output.stdout);
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
            bail!("bw がエラーを返しました ({}): {}", output.status, stderr);
        }
        Ok(stdout)
    }

    pub fn status(&self) -> anyhow::Result<StatusInfo> {
        let out = self.run(self.command(&["status"]), None)?;
        serde_json::from_slice(&out).context("bw status の出力を解釈できません")
    }

    pub fn unlock(&mut self, password: &str) -> anyhow::Result<()> {
        let mut cmd = self.command(&["unlock", "--raw", "--passwordenv", PASSWORD_ENV]);
        cmd.env(PASSWORD_ENV, password);
        let out = self.run(cmd, None)?;
        let session = std::str::from_utf8(&out)
            .context("セッションキーが不正です")?
            .trim();
        if session.is_empty() {
            bail!("セッションキーを取得できませんでした");
        }
        self.session = Some(Zeroizing::new(session.to_owned()));
        Ok(())
    }

    pub fn lock(&mut self) -> anyhow::Result<()> {
        if self.session.is_none() {
            return Ok(());
        }
        let result = self.run(self.command(&["lock"]), None).map(|_| ());
        self.session = None;
        result
    }

    pub fn sync(&self) -> anyhow::Result<()> {
        self.run(self.command(&["sync"]), None).map(|_| ())
    }

    /// ログインアイテムを列挙する。パスワードと TOTP はここでハッシュ化し、平文は破棄する。
    pub fn list_logins(&self, hasher: &SecretHasher) -> anyhow::Result<Vec<LoginItem>> {
        let out = self.run(self.command(&["list", "items"]), None)?;
        let raw: Vec<RawItem> =
            serde_json::from_slice(&out).context("bw list items の出力を解釈できません")?;
        Ok(raw
            .into_iter()
            .filter(|item| item.kind == 1 && item.deleted_date.is_none())
            .map(|item| item.into_login(hasher))
            .collect())
    }

    /// アイテムを完全な JSON として取得する（編集用）。
    pub fn get_item(&self, id: &str) -> anyhow::Result<SecretJson> {
        let out = self.run(self.command(&["get", "item", id]), None)?;
        let value = serde_json::from_slice(&out).context("bw get item の出力を解釈できません")?;
        Ok(SecretJson(value))
    }

    pub fn edit_item(&self, id: &str, item: &SecretJson) -> anyhow::Result<()> {
        let mut json = Zeroizing::new(Vec::with_capacity(256 * 1024));
        serde_json::to_writer(&mut *json, &item.0)?;
        let mut encoded = Zeroizing::new(String::with_capacity(json.len() * 4 / 3 + 8));
        base64::engine::general_purpose::STANDARD.encode_string(&*json, &mut encoded);
        self.run(
            self.command(&["edit", "item", id]),
            Some(encoded.as_bytes()),
        )
        .map(|_| ())
    }

    /// ゴミ箱へ移動する（`--permanent` は付けないので 30 日間は復元可能）。
    pub fn delete_item(&self, id: &str) -> anyhow::Result<()> {
        self.run(self.command(&["delete", "item", id]), None)
            .map(|_| ())
    }
}

/// 平文を含みうる JSON。drop 時に全文字列をゼロ埋めする。
pub struct SecretJson(pub Value);

impl Drop for SecretJson {
    fn drop(&mut self) {
        zeroize_value(&mut self.0);
    }
}

fn zeroize_value(value: &mut Value) {
    match value {
        Value::String(s) => s.zeroize(),
        Value::Array(items) => items.iter_mut().for_each(zeroize_value),
        Value::Object(map) => map.values_mut().for_each(zeroize_value),
        _ => {}
    }
}

impl SecretJson {
    pub fn login_str(&self, key: &str) -> Option<&str> {
        self.0.get("login")?.get(key)?.as_str()
    }

    pub fn str(&self, key: &str) -> Option<&str> {
        self.0.get(key)?.as_str()
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawItem {
    id: String,
    organization_id: Option<String>,
    folder_id: Option<String>,
    #[serde(rename = "type")]
    kind: u8,
    name: String,
    login: Option<RawLogin>,
    attachments: Option<Vec<serde::de::IgnoredAny>>,
    revision_date: Option<String>,
    deleted_date: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawLogin {
    username: Option<String>,
    password: Option<Zeroizing<String>>,
    totp: Option<Zeroizing<String>>,
    uris: Option<Vec<RawUri>>,
    fido2_credentials: Option<Vec<serde::de::IgnoredAny>>,
}

#[derive(Deserialize)]
struct RawUri {
    uri: Option<String>,
}

impl RawItem {
    fn into_login(self, hasher: &SecretHasher) -> LoginItem {
        let login = self.login;
        let (username, password_hash, totp_hash, uris, has_passkey) = match login {
            Some(l) => (
                l.username.filter(|u| !u.is_empty()),
                hasher.hash_opt(l.password.as_deref().map(String::as_str)),
                hasher.hash_opt(l.totp.as_deref().map(String::as_str)),
                l.uris
                    .unwrap_or_default()
                    .into_iter()
                    .filter_map(|u| Some(UriEntry { uri: u.uri? }))
                    .collect(),
                l.fido2_credentials.is_some_and(|c| !c.is_empty()),
            ),
            None => (None, None, None, Vec::new(), false),
        };
        LoginItem {
            id: self.id,
            name: self.name,
            username,
            uris,
            password_hash,
            totp_hash,
            has_passkey,
            has_attachments: self.attachments.is_some_and(|a| !a.is_empty()),
            organization_id: self.organization_id,
            folder_id: self.folder_id,
            revision_date: self.revision_date,
        }
    }
}
