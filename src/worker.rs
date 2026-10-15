//! `bw` の呼び出しは1回あたり数百ms〜数秒かかるため、専用スレッドで実行する。
//! セッションキーとハッシュ鍵はこのスレッドだけが持ち、UI スレッドには渡らない。

use std::sync::mpsc::{Receiver, Sender, channel};
use std::thread::JoinHandle;

use eframe::egui;
use zeroize::Zeroizing;

use crate::bw::{BwCli, StatusInfo};
use crate::merge::{self, MergeReport, MergeRequest};
use crate::model::LoginItem;
use crate::secret::SecretHasher;

pub enum Request {
    Status,
    Unlock(Zeroizing<String>),
    Load { sync: bool },
    Merge(MergeRequest),
    Lock,
}

pub enum Response {
    Status(Result<StatusInfo, String>),
    Unlocked(Result<(), String>),
    Loaded(Result<Vec<LoginItem>, String>),
    Merged(Result<MergeReport, String>),
    Locked(Result<(), String>),
}

pub struct Worker {
    tx: Option<Sender<Request>>,
    rx: Receiver<Response>,
    handle: Option<JoinHandle<()>>,
}

impl Worker {
    pub fn spawn(ctx: egui::Context) -> Self {
        let (req_tx, req_rx) = channel::<Request>();
        let (res_tx, res_rx) = channel::<Response>();
        let handle = std::thread::Builder::new()
            .name("bw-worker".into())
            .spawn(move || run(req_rx, res_tx, ctx))
            .expect("failed to spawn worker thread");
        Self {
            tx: Some(req_tx),
            rx: res_rx,
            handle: Some(handle),
        }
    }

    pub fn send(&self, req: Request) {
        if let Some(tx) = &self.tx {
            let _ = tx.send(req);
        }
    }

    pub fn try_recv(&self) -> Option<Response> {
        self.rx.try_recv().ok()
    }
}

impl Drop for Worker {
    /// 終了時にワーカーを止め、開いていたセッションをロックする。
    fn drop(&mut self) {
        self.tx.take();
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn run(rx: Receiver<Request>, tx: Sender<Response>, ctx: egui::Context) {
    let mut init = BwCli::locate().and_then(|bw| Ok((bw, SecretHasher::new()?)));
    let reply = |res: Response| {
        let _ = tx.send(res);
        ctx.request_repaint();
    };

    while let Ok(req) = rx.recv() {
        let (bw, hasher) = match &mut init {
            Ok((bw, hasher)) => (bw, &*hasher),
            Err(e) => {
                let msg = format!("{e:#}");
                reply(match req {
                    Request::Status => Response::Status(Err(msg)),
                    Request::Unlock(_) => Response::Unlocked(Err(msg)),
                    Request::Load { .. } => Response::Loaded(Err(msg)),
                    Request::Merge(_) => Response::Merged(Err(msg)),
                    Request::Lock => Response::Locked(Ok(())),
                });
                continue;
            }
        };
        let res = match req {
            Request::Status => Response::Status(bw.status().map_err(fmt)),
            Request::Unlock(password) => Response::Unlocked(bw.unlock(&password).map_err(fmt)),
            Request::Load { sync } => Response::Loaded(
                (|| {
                    if sync {
                        bw.sync()?;
                    }
                    bw.list_logins(hasher)
                })()
                .map_err(fmt),
            ),
            Request::Merge(req) => Response::Merged(merge::execute(bw, hasher, &req).map_err(fmt)),
            Request::Lock => Response::Locked(bw.lock().map_err(fmt)),
        };
        reply(res);
    }

    if let Ok((bw, _)) = &mut init
        && bw.is_unlocked()
    {
        let _ = bw.lock();
    }
}

fn fmt(e: anyhow::Error) -> String {
    format!("{e:#}")
}
