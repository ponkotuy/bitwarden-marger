use std::collections::{BTreeSet, HashMap, HashSet};

use crate::secret::SecretHash;

#[derive(Debug, Clone)]
pub struct UriEntry {
    pub uri: String,
}

impl UriEntry {
    /// 重複判定用のキー。前後の空白と末尾スラッシュ、大文字小文字の差を無視する。
    pub fn dedup_key(uri: &str) -> String {
        uri.trim().trim_end_matches('/').to_lowercase()
    }

    pub fn host(&self) -> Option<String> {
        host_of(&self.uri)
    }
}

pub fn host_of(uri: &str) -> Option<String> {
    let uri = uri.trim();
    let parsed = url::Url::parse(uri)
        .ok()
        .filter(|u| u.host_str().is_some())
        .or_else(|| url::Url::parse(&format!("https://{uri}")).ok())?;
    let host = parsed.host_str()?.trim_start_matches("www.");
    Some(host.to_owned())
}

/// 平文パスワードを持たないログインアイテム。
#[derive(Debug, Clone)]
pub struct LoginItem {
    pub id: String,
    pub name: String,
    pub username: Option<String>,
    pub uris: Vec<UriEntry>,
    pub password_hash: Option<SecretHash>,
    pub totp_hash: Option<SecretHash>,
    pub has_passkey: bool,
    pub has_attachments: bool,
    pub organization_id: Option<String>,
    pub folder_id: Option<String>,
    pub revision_date: Option<String>,
}

impl LoginItem {
    pub fn hosts(&self) -> BTreeSet<String> {
        self.uris.iter().filter_map(UriEntry::host).collect()
    }
}

/// 同じパスワードを持つアイテムの集合（マージ候補）。
#[derive(Debug, Clone)]
pub struct Group {
    pub password_hash: SecretHash,
    /// `items` へのインデックス
    pub members: Vec<usize>,
    pub hosts: BTreeSet<String>,
}

impl Group {
    pub fn title(&self, items: &[LoginItem]) -> String {
        let mut names: Vec<&str> = self
            .members
            .iter()
            .map(|&i| items[i].name.as_str())
            .collect();
        names.sort_unstable();
        names.dedup();
        match names.as_slice() {
            [] => String::new(),
            [one] => (*one).to_owned(),
            [first, rest @ ..] => format!("{first} ほか{}件", rest.len()),
        }
    }

    pub fn matches(&self, items: &[LoginItem], query: &str) -> bool {
        if query.is_empty() {
            return true;
        }
        let q = query.to_lowercase();
        self.hosts.iter().any(|h| h.contains(&q))
            || self.members.iter().any(|&i| {
                let item = &items[i];
                item.name.to_lowercase().contains(&q)
                    || item
                        .username
                        .as_deref()
                        .is_some_and(|u| u.to_lowercase().contains(&q))
            })
    }
}

/// パスワードが一致するアイテムをグループ化する。2件以上のグループだけを返す。
///
/// 組織が異なるアイテム同士は統合できないので別グループにする。
/// `by_username` が真ならユーザー名も一致条件に加える。
pub fn build_groups(items: &[LoginItem], by_username: bool) -> Vec<Group> {
    type Key<'a> = (SecretHash, Option<&'a str>, Option<String>);
    let mut map: HashMap<Key, Vec<usize>> = HashMap::new();
    let mut order: Vec<Key> = Vec::new();
    for (i, item) in items.iter().enumerate() {
        let Some(hash) = item.password_hash else {
            continue;
        };
        let user = by_username.then(|| item.username.as_deref().unwrap_or("").to_lowercase());
        let key = (hash, item.organization_id.as_deref(), user);
        let entry = map.entry(key.clone()).or_default();
        if entry.is_empty() {
            order.push(key);
        }
        entry.push(i);
    }
    let mut groups: Vec<Group> = order
        .into_iter()
        .filter_map(|key| {
            let members = map.remove(&key)?;
            (members.len() >= 2).then(|| Group {
                password_hash: key.0,
                hosts: members.iter().flat_map(|&i| items[i].hosts()).collect(),
                members,
            })
        })
        .collect();
    groups.sort_by(|a, b| {
        b.members
            .len()
            .cmp(&a.members.len())
            .then_with(|| a.title(items).cmp(&b.title(items)))
    });
    groups
}

/// 統合後の URI 一覧（主アイテムの URI を先頭に、重複を除いて追加）。
pub fn merged_uris<'a>(
    primary: &'a LoginItem,
    others: impl IntoIterator<Item = &'a LoginItem>,
) -> Vec<&'a UriEntry> {
    let mut seen = HashSet::new();
    std::iter::once(primary)
        .chain(others)
        .flat_map(|item| item.uris.iter())
        .filter(|u| !u.uri.trim().is_empty() && seen.insert(UriEntry::dedup_key(&u.uri)))
        .collect()
}

/// マージ前のチェック結果。
#[derive(Debug, Default)]
pub struct MergeCheck {
    /// 実行不可の理由
    pub errors: Vec<String>,
    /// 実行は可能だが注意が必要な点
    pub warnings: Vec<String>,
}

pub fn check_merge(primary: &LoginItem, others: &[&LoginItem]) -> MergeCheck {
    let mut check = MergeCheck::default();
    if others.is_empty() {
        check
            .errors
            .push("統合するアイテムを2件以上選択してください".into());
        return check;
    }
    if primary.password_hash.is_none() {
        check
            .errors
            .push("主アイテムにパスワードがありません".into());
    }
    for other in others {
        if other.password_hash != primary.password_hash {
            check
                .errors
                .push(format!("「{}」はパスワードが一致しません", other.name));
        }
        if other.organization_id != primary.organization_id {
            check
                .errors
                .push(format!("「{}」は所属する組織が異なります", other.name));
        }
        if other.has_passkey {
            check.errors.push(format!(
                "「{}」はパスキーを持っています。主アイテムにしてください",
                other.name
            ));
        }
        if other.has_attachments {
            check.errors.push(format!(
                "「{}」は添付ファイルを持っています。主アイテムにしてください",
                other.name
            ));
        }
    }

    let users: BTreeSet<&str> = std::iter::once(primary)
        .chain(others.iter().copied())
        .map(|i| i.username.as_deref().unwrap_or("(なし)"))
        .collect();
    if users.len() > 1 {
        check.warnings.push(format!(
            "ユーザー名が異なります: {}（主アイテムのものが残ります）",
            users.into_iter().collect::<Vec<_>>().join(", ")
        ));
    }
    let totps: HashSet<_> = std::iter::once(primary)
        .chain(others.iter().copied())
        .filter_map(|i| i.totp_hash)
        .collect();
    if totps.len() > 1 {
        check
            .warnings
            .push("異なる TOTP 設定が含まれています（主アイテムのものが優先されます）".into());
    }
    let folders: HashSet<_> = others
        .iter()
        .map(|i| &i.folder_id)
        .filter(|f| **f != primary.folder_id)
        .collect();
    if !folders.is_empty() {
        check.warnings.push(
            "フォルダが異なるアイテムがあります（主アイテムのフォルダに統合されます）".into(),
        );
    }
    check
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret::SecretHasher;

    fn item(h: &SecretHasher, id: &str, pw: &str, user: &str, uris: &[&str]) -> LoginItem {
        LoginItem {
            id: id.into(),
            name: id.into(),
            username: Some(user.into()),
            uris: uris.iter().map(|u| UriEntry { uri: (*u).into() }).collect(),
            password_hash: h.hash_opt(Some(pw)),
            totp_hash: None,
            has_passkey: false,
            has_attachments: false,
            organization_id: None,
            folder_id: None,
            revision_date: None,
        }
    }

    #[test]
    fn groups_by_password() {
        let h = SecretHasher::new().unwrap();
        let items = vec![
            item(&h, "a", "pw1", "u", &["https://a.example.com"]),
            item(&h, "b", "pw1", "v", &["https://b.example.com"]),
            item(&h, "c", "pw2", "u", &[]),
        ];
        let groups = build_groups(&items, false);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].members, vec![0, 1]);
        assert!(build_groups(&items, true).is_empty());
    }

    #[test]
    fn merged_uris_dedup() {
        let h = SecretHasher::new().unwrap();
        let a = item(
            &h,
            "a",
            "pw",
            "u",
            &["https://example.com/", "https://x.com"],
        );
        let b = item(
            &h,
            "b",
            "pw",
            "u",
            &["https://EXAMPLE.com", "https://y.com"],
        );
        let uris: Vec<_> = merged_uris(&a, [&b])
            .into_iter()
            .map(|u| u.uri.as_str())
            .collect();
        assert_eq!(
            uris,
            ["https://example.com/", "https://x.com", "https://y.com"]
        );
    }

    #[test]
    fn check_rejects_different_password() {
        let h = SecretHasher::new().unwrap();
        let a = item(&h, "a", "pw", "u", &[]);
        let b = item(&h, "b", "other", "u", &[]);
        assert!(!check_merge(&a, &[&b]).errors.is_empty());
    }

    #[test]
    fn host_parsing() {
        assert_eq!(
            host_of("https://www.example.com/login").as_deref(),
            Some("example.com")
        );
        assert_eq!(host_of("example.com").as_deref(), Some("example.com"));
        assert_eq!(
            host_of("androidapp://com.example").as_deref(),
            Some("com.example")
        );
    }
}
