//! マージの実行。
//!
//! 一覧表示時のデータは古い可能性があるので、実行直前に `bw get item` で最新を取得し、
//! パスワードが期待するハッシュと一致することを再確認してから書き込む。
//! `bw edit item` は渡したオブジェクトで丸ごと置き換えるため、
//! 主アイテムの完全な JSON を元に URI 等だけを書き換えて送る。

use std::collections::HashSet;

use anyhow::{bail, ensure};
use serde_json::{Value, json};

use crate::bw::{BwCli, SecretJson};
use crate::model::UriEntry;
use crate::secret::{SecretHash, SecretHasher};

#[derive(Debug, Clone, Copy)]
pub struct MergeOptions {
    /// 他アイテムのメモを主アイテムのメモに追記する
    pub merge_notes: bool,
    /// 他アイテムのカスタムフィールドを追加する（同名・同値のものは除く）
    pub merge_fields: bool,
    /// 主アイテムに TOTP がなければ他アイテムのものを引き継ぐ
    pub adopt_totp: bool,
}

impl Default for MergeOptions {
    fn default() -> Self {
        Self {
            merge_notes: true,
            merge_fields: true,
            adopt_totp: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct MergeRequest {
    pub primary_id: String,
    pub other_ids: Vec<String>,
    pub expected_hash: SecretHash,
    pub options: MergeOptions,
}

#[derive(Debug, Clone)]
pub struct MergeReport {
    pub primary_name: String,
    pub uri_count: usize,
    pub trashed: Vec<String>,
    pub failed: Vec<(String, String)>,
}

pub fn execute(
    bw: &BwCli,
    hasher: &SecretHasher,
    req: &MergeRequest,
) -> anyhow::Result<MergeReport> {
    ensure!(!req.other_ids.is_empty(), "統合対象がありません");
    ensure!(
        !req.other_ids.contains(&req.primary_id),
        "主アイテムが統合対象に含まれています"
    );

    let mut primary = bw.get_item(&req.primary_id)?;
    verify(&primary, hasher, req.expected_hash)?;
    let mut others = Vec::with_capacity(req.other_ids.len());
    for id in &req.other_ids {
        let other = bw.get_item(id)?;
        verify(&other, hasher, req.expected_hash)?;
        ensure!(
            other.0.get("organizationId") == primary.0.get("organizationId"),
            "「{}」は所属する組織が異なります",
            other.str("name").unwrap_or(id)
        );
        ensure!(
            !has_non_empty_array(&other.0["login"]["fido2Credentials"]),
            "「{}」はパスキーを持っているため統合できません",
            other.str("name").unwrap_or(id)
        );
        ensure!(
            !has_non_empty_array(&other.0["attachments"]),
            "「{}」は添付ファイルを持っているため統合できません",
            other.str("name").unwrap_or(id)
        );
        others.push(other);
    }

    let uri_count = merge_into(&mut primary.0, others.iter().map(|o| &o.0), req.options);
    bw.edit_item(&req.primary_id, &primary)?;

    // 主アイテムの更新に成功した場合のみ、残りをゴミ箱へ移す
    let mut report = MergeReport {
        primary_name: primary.str("name").unwrap_or_default().to_owned(),
        uri_count,
        trashed: Vec::new(),
        failed: Vec::new(),
    };
    for (id, other) in req.other_ids.iter().zip(&others) {
        let name = other.str("name").unwrap_or(id).to_owned();
        match bw.delete_item(id) {
            Ok(()) => report.trashed.push(name),
            Err(e) => report.failed.push((name, e.to_string())),
        }
    }
    Ok(report)
}

fn verify(item: &SecretJson, hasher: &SecretHasher, expected: SecretHash) -> anyhow::Result<()> {
    let name = item.str("name").unwrap_or("(名前なし)");
    ensure!(
        item.0.get("type").and_then(Value::as_u64) == Some(1),
        "「{name}」はログインアイテムではありません"
    );
    ensure!(
        item.0.get("deletedDate").is_none_or(Value::is_null),
        "「{name}」は削除済みです"
    );
    match hasher.hash_opt(item.login_str("password")) {
        Some(h) if h == expected => Ok(()),
        Some(_) => {
            bail!("「{name}」のパスワードが一覧取得時から変わっています。再読込してください")
        }
        None => bail!("「{name}」にパスワードがありません"),
    }
}

fn has_non_empty_array(v: &Value) -> bool {
    v.as_array().is_some_and(|a| !a.is_empty())
}

fn non_empty_str(v: &Value) -> Option<&str> {
    v.as_str().filter(|s| !s.trim().is_empty())
}

/// `others` の内容を `primary` に統合する。統合後の URI 数を返す。
fn merge_into<'a>(
    primary: &mut Value,
    others: impl Iterator<Item = &'a Value> + Clone,
    opts: MergeOptions,
) -> usize {
    // URI
    let mut uris: Vec<Value> = primary["login"]["uris"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let mut seen: HashSet<String> = uris
        .iter()
        .filter_map(|u| u["uri"].as_str())
        .map(UriEntry::dedup_key)
        .collect();
    for other in others.clone() {
        for uri in other["login"]["uris"].as_array().into_iter().flatten() {
            if let Some(s) = non_empty_str(&uri["uri"])
                && seen.insert(UriEntry::dedup_key(s))
            {
                uris.push(json!({ "match": uri["match"].clone(), "uri": s }));
            }
        }
    }
    let uri_count = uris.len();
    primary["login"]["uris"] = Value::Array(uris);

    // メモ
    if opts.merge_notes {
        let mut notes = non_empty_str(&primary["notes"])
            .unwrap_or_default()
            .to_owned();
        for other in others.clone() {
            let Some(other_notes) = non_empty_str(&other["notes"]) else {
                continue;
            };
            if notes.contains(other_notes.trim()) {
                continue;
            }
            if !notes.is_empty() {
                notes.push_str("\n\n");
            }
            let name = other["name"].as_str().unwrap_or_default();
            notes.push_str(&format!(
                "---- {name} から統合 ----\n{}",
                other_notes.trim()
            ));
        }
        if !notes.is_empty() {
            primary["notes"] = Value::String(notes);
        }
    }

    // カスタムフィールド
    if opts.merge_fields {
        let mut fields: Vec<Value> = primary["fields"].as_array().cloned().unwrap_or_default();
        for other in others.clone() {
            for field in other["fields"].as_array().into_iter().flatten() {
                let dup = fields
                    .iter()
                    .any(|f| f["name"] == field["name"] && f["value"] == field["value"]);
                if !dup {
                    fields.push(field.clone());
                }
            }
        }
        if !fields.is_empty() {
            primary["fields"] = Value::Array(fields);
        }
    }

    // TOTP
    if opts.adopt_totp
        && non_empty_str(&primary["login"]["totp"]).is_none()
        && let Some(totp) = others
            .clone()
            .find_map(|o| non_empty_str(&o["login"]["totp"]))
    {
        primary["login"]["totp"] = Value::String(totp.to_owned());
    }

    uri_count
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merges_uris_notes_fields_totp() {
        let mut primary = json!({
            "name": "A", "notes": "memo A", "fields": [{"name": "f", "value": "1", "type": 0}],
            "login": {"password": "pw", "totp": null, "uris": [{"match": null, "uri": "https://a.com"}]}
        });
        let b = json!({
            "name": "B", "notes": "memo B", "fields": [{"name": "f", "value": "1", "type": 0}, {"name": "g", "value": "2", "type": 0}],
            "login": {"password": "pw", "totp": "otpauth://x", "uris": [{"match": 0, "uri": "https://A.com/"}, {"match": 0, "uri": "https://b.com"}]}
        });
        let count = merge_into(&mut primary, [&b].into_iter(), MergeOptions::default());
        assert_eq!(count, 2);
        assert_eq!(primary["login"]["uris"][1]["uri"], "https://b.com");
        assert_eq!(primary["login"]["password"], "pw");
        assert_eq!(primary["login"]["totp"], "otpauth://x");
        assert_eq!(primary["fields"].as_array().unwrap().len(), 2);
        assert!(primary["notes"].as_str().unwrap().contains("memo B"));
    }

    #[test]
    fn keeps_primary_when_options_off() {
        let mut primary =
            json!({"name": "A", "notes": null, "login": {"totp": null, "uris": null}});
        let b = json!({"name": "B", "notes": "x", "login": {"totp": "t", "uris": [{"match": null, "uri": "https://b.com"}]}});
        let opts = MergeOptions {
            merge_notes: false,
            merge_fields: false,
            adopt_totp: false,
        };
        merge_into(&mut primary, [&b].into_iter(), opts);
        assert!(primary["notes"].is_null());
        assert!(primary["login"]["totp"].is_null());
        assert_eq!(primary["login"]["uris"].as_array().unwrap().len(), 1);
    }
}
