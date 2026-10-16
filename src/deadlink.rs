//! ドメインが死んでいる（アクセスできない）ログインアイテムの検出。
//!
//! URI のホストを名前解決し、解決できたものには TCP 接続を試みる。
//! HTTP リクエストは送らない（名前解決と接続だけで判定する）。
//! ローカルネットワークや IP 直書きのホストは外から判定できないので対象外にする。

use std::collections::{BTreeSet, HashMap};
use std::net::{IpAddr, TcpStream, ToSocketAddrs};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use crate::model::LoginItem;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const THREADS: usize = 32;
/// 1ホストあたり接続を試すアドレス数の上限
const MAX_ADDRS: usize = 4;

/// 確認対象のホストとポート。
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Target {
    pub host: String,
    pub port: u16,
}

impl std::fmt::Display for Target {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.port == 443 {
            f.write_str(&self.host)
        } else {
            write!(f, "{}:{}", self.host, self.port)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostStatus {
    Alive,
    /// 名前解決できない
    NoDns,
    /// 名前解決はできるが接続できない
    Unreachable,
}

impl HostStatus {
    pub fn label(self) -> &'static str {
        match self {
            HostStatus::Alive => "応答あり",
            HostStatus::NoDns => "名前解決できない",
            HostStatus::Unreachable => "接続できない",
        }
    }
}

/// URI から確認対象を取り出す。Web 以外（アプリ ID 等）や外から判定できないホストは `None`。
pub fn web_target(uri: &str) -> Option<Target> {
    let uri = uri.trim();
    if uri.is_empty() {
        return None;
    }
    let parsed = url::Url::parse(uri)
        .ok()
        .filter(|u| u.host_str().is_some())
        // "example.com" や "example.com:8080" のようにスキーム無しで登録されているもの
        .or_else(|| {
            (!uri.contains("://"))
                .then(|| url::Url::parse(&format!("https://{uri}")).ok())
                .flatten()
        })?;
    let port = match parsed.scheme() {
        "https" | "http" => parsed.port_or_known_default()?,
        _ => return None,
    };
    let host = match parsed.host()? {
        url::Host::Domain(d) => d.trim_end_matches('.').to_lowercase(),
        // IP 直書きは家庭内機器などが多く、到達できなくても「死んでいる」とは言えない
        url::Host::Ipv4(_) | url::Host::Ipv6(_) => return None,
    };
    if is_local_name(&host) {
        return None;
    }
    Some(Target { host, port })
}

/// ドットを含まない名前や、ローカル用の TLD は外から判定できない。
fn is_local_name(host: &str) -> bool {
    const LOCAL_SUFFIXES: &[&str] = &[
        "localhost",
        "local",
        "lan",
        "home",
        "internal",
        "intranet",
        "corp",
        "home.arpa",
        "test",
        "example",
        "invalid",
    ];
    !host.contains('.')
        || LOCAL_SUFFIXES
            .iter()
            .any(|s| host == *s || host.ends_with(&format!(".{s}")))
}

/// アイテム群から重複のない確認対象を集める。
pub fn collect_targets(items: &[LoginItem]) -> Vec<Target> {
    items
        .iter()
        .flat_map(|item| item.uris.iter())
        .filter_map(|u| web_target(&u.uri))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn check_one(target: &Target) -> HostStatus {
    let addrs: Vec<_> = match (target.host.as_str(), target.port).to_socket_addrs() {
        Ok(addrs) => addrs.collect(),
        Err(_) => return HostStatus::NoDns,
    };
    // 0.0.0.0 や 127.0.0.1 を返す「死んだドメイン」もあるので、それらは解決できないものと同じ扱い
    let usable: Vec<_> = addrs
        .into_iter()
        .filter(|a| is_global(a.ip()))
        .take(MAX_ADDRS)
        .collect();
    if usable.is_empty() {
        return HostStatus::NoDns;
    }
    if usable
        .iter()
        .any(|addr| TcpStream::connect_timeout(addr, CONNECT_TIMEOUT).is_ok())
    {
        HostStatus::Alive
    } else {
        HostStatus::Unreachable
    }
}

fn is_global(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !(v4.is_unspecified() || v4.is_loopback() || v4.is_private() || v4.is_link_local())
        }
        IpAddr::V6(v6) => !(v6.is_unspecified()
            || v6.is_loopback()
            || v6.is_unique_local()
            || v6.is_unicast_link_local()),
    }
}

/// 対象を並列に確認する。`progress(done, total)` は確認が1件終わるたびに呼ばれる。
pub fn check_targets(
    targets: &[Target],
    progress: impl Fn(usize, usize) + Sync,
) -> HashMap<Target, HostStatus> {
    let next = AtomicUsize::new(0);
    let done = AtomicUsize::new(0);
    let results = Mutex::new(HashMap::with_capacity(targets.len()));
    std::thread::scope(|s| {
        for _ in 0..THREADS.min(targets.len()) {
            s.spawn(|| {
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some(target) = targets.get(i) else {
                        break;
                    };
                    let status = check_one(target);
                    results.lock().unwrap().insert(target.clone(), status);
                    let n = done.fetch_add(1, Ordering::Relaxed) + 1;
                    progress(n, targets.len());
                }
            });
        }
    });
    results.into_inner().unwrap()
}

/// 死んでいると判定されたアイテム。
#[derive(Debug, Clone)]
pub struct DeadItem {
    pub id: String,
    /// 確認したホストと結果（すべて Alive 以外）
    pub hosts: Vec<(Target, HostStatus)>,
}

impl DeadItem {
    /// 1つでも名前解決できないホストがあれば真（接続不可より確度が高い）
    pub fn has_no_dns(&self) -> bool {
        self.hosts.iter().any(|(_, s)| *s == HostStatus::NoDns)
    }
}

/// Web の URI を1つ以上持ち、そのすべてが応答しないアイテムを返す。
/// 1つでも生きているホストや未確認のホストがあれば対象外。
pub fn find_dead(items: &[LoginItem], results: &HashMap<Target, HostStatus>) -> Vec<DeadItem> {
    items
        .iter()
        .filter_map(|item| {
            let targets: BTreeSet<Target> =
                item.uris.iter().filter_map(|u| web_target(&u.uri)).collect();
            if targets.is_empty() {
                return None;
            }
            let mut hosts = Vec::with_capacity(targets.len());
            for target in targets {
                match results.get(&target) {
                    Some(HostStatus::Alive) | None => return None,
                    Some(&status) => hosts.push((target, status)),
                }
            }
            Some(DeadItem {
                id: item.id.clone(),
                hosts,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::UriEntry;

    fn t(host: &str, port: u16) -> Target {
        Target {
            host: host.into(),
            port,
        }
    }

    fn item(id: &str, uris: &[&str]) -> LoginItem {
        LoginItem {
            id: id.into(),
            name: id.into(),
            username: None,
            uris: uris.iter().map(|u| UriEntry { uri: (*u).into() }).collect(),
            password_hash: None,
            totp_hash: None,
            has_passkey: false,
            has_attachments: false,
            organization_id: None,
            folder_id: None,
            revision_date: None,
        }
    }

    #[test]
    fn targets_from_uris() {
        assert_eq!(
            web_target("https://www.Example.com/login"),
            Some(t("www.example.com", 443))
        );
        assert_eq!(web_target("example.com"), Some(t("example.com", 443)));
        assert_eq!(
            web_target("http://example.com:8080/"),
            Some(t("example.com", 8080))
        );
        assert_eq!(web_target("http://example.com"), Some(t("example.com", 80)));
        assert_eq!(
            web_target("example.com:8443"),
            Some(t("example.com", 8443))
        );
        assert_eq!(web_target("androidapp://com.example"), None);
        assert_eq!(web_target("https://192.168.0.1"), None);
        assert_eq!(web_target("https://nas.local"), None);
        assert_eq!(web_target("https://router"), None);
        assert_eq!(web_target(""), None);
    }

    #[test]
    fn dead_only_when_all_hosts_dead() {
        let items = vec![
            item("dead", &["https://a.com", "https://b.com/x"]),
            item("mixed", &["https://a.com", "https://c.com"]),
            item("app", &["androidapp://com.example"]),
            item("unknown", &["https://d.com"]),
        ];
        let results = HashMap::from([
            (t("a.com", 443), HostStatus::NoDns),
            (t("b.com", 443), HostStatus::Unreachable),
            (t("c.com", 443), HostStatus::Alive),
        ]);
        let dead = find_dead(&items, &results);
        assert_eq!(dead.len(), 1);
        assert_eq!(dead[0].id, "dead");
        assert!(dead[0].has_no_dns());
    }
}
