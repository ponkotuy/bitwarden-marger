use std::collections::{HashMap, HashSet};

use eframe::egui::text_edit::TextEditState;
use eframe::egui::{self, Color32, RichText};

use crate::bw::StatusInfo;
use crate::deadlink::{self, DeadItem, HostStatus, Target};
use crate::merge::{MergeOptions, MergeRequest};
use crate::model::{self, Group, LoginItem};
use crate::secret::SecretInput;
use crate::worker::{Request, Response, Worker};

const PASSWORD_ID: &str = "master_password";

#[derive(PartialEq, Eq)]
enum Phase {
    Starting,
    Unauthenticated,
    Locked,
    Ready,
}

#[derive(PartialEq, Eq, Clone, Copy)]
enum View {
    Merge,
    Dead,
}

enum LogLevel {
    Info,
    Error,
}

pub struct MergerApp {
    worker: Worker,
    phase: Phase,
    busy: Option<&'static str>,
    status: Option<StatusInfo>,
    password: SecretInput,
    items: Vec<LoginItem>,
    groups: Vec<Group>,
    by_username: bool,
    query: String,
    selected_group: Option<usize>,
    checked: HashSet<String>,
    primary: Option<String>,
    options: MergeOptions,
    confirming: bool,
    view: View,
    /// ドメイン確認の結果（未確認なら `None`）
    host_status: Option<HashMap<Target, HostStatus>>,
    dead: Vec<DeadItem>,
    check_progress: Option<(usize, usize)>,
    include_unreachable: bool,
    dead_query: String,
    /// ゴミ箱への移動を依頼中のアイテム ID
    trashing: HashSet<String>,
    log: Vec<(LogLevel, String)>,
}

impl MergerApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let mut app = Self {
            worker: Worker::spawn(cc.egui_ctx.clone()),
            phase: Phase::Starting,
            busy: None,
            status: None,
            password: SecretInput::new(),
            items: Vec::new(),
            groups: Vec::new(),
            by_username: false,
            query: String::new(),
            selected_group: None,
            checked: HashSet::new(),
            primary: None,
            options: MergeOptions::default(),
            confirming: false,
            view: View::Merge,
            host_status: None,
            dead: Vec::new(),
            check_progress: None,
            include_unreachable: true,
            dead_query: String::new(),
            trashing: HashSet::new(),
            log: Vec::new(),
        };
        app.request(Request::Status, "状態を確認しています…");
        app
    }

    /// 他の操作を受け付けられる状態か（ゴミ箱への移動待ちがあるときも不可）
    fn idle(&self) -> bool {
        self.busy.is_none() && self.trashing.is_empty()
    }

    fn request(&mut self, req: Request, busy: &'static str) {
        self.busy = Some(busy);
        self.worker.send(req);
    }

    fn info(&mut self, msg: impl Into<String>) {
        self.log.push((LogLevel::Info, msg.into()));
    }

    fn error(&mut self, msg: impl Into<String>) {
        self.log.push((LogLevel::Error, msg.into()));
    }

    fn handle_responses(&mut self) {
        while let Some(res) = self.worker.try_recv() {
            // 進捗とゴミ箱移動は busy 表示を伴わないので、それ以外の応答でだけ解除する
            if !matches!(
                res,
                Response::CheckProgress { .. } | Response::Trashed { .. }
            ) {
                self.busy = None;
            }
            match res {
                Response::Status(Ok(status)) => {
                    self.phase = if status.status == "unauthenticated" {
                        Phase::Unauthenticated
                    } else {
                        Phase::Locked
                    };
                    self.status = Some(status);
                }
                Response::Status(Err(e)) => {
                    self.phase = Phase::Unauthenticated;
                    self.error(e);
                }
                Response::Unlocked(Ok(())) => {
                    self.info("ロックを解除しました");
                    self.request(
                        Request::Load { sync: true },
                        "同期して保管庫を読み込んでいます…",
                    );
                }
                Response::Unlocked(Err(e)) => self.error(format!("ロック解除に失敗しました: {e}")),
                Response::Loaded(Ok(items)) => {
                    self.info(format!("{} 件のログインを読み込みました", items.len()));
                    self.items = items;
                    self.rebuild_groups();
                    self.refresh_dead();
                    self.phase = Phase::Ready;
                }
                Response::Loaded(Err(e)) => self.error(format!("読み込みに失敗しました: {e}")),
                Response::Merged(Ok(report)) => {
                    self.info(format!(
                        "「{}」に統合しました（URI {} 件）。ゴミ箱へ移動: {}",
                        report.primary_name,
                        report.uri_count,
                        report.trashed.join(", ")
                    ));
                    for (name, e) in report.failed {
                        self.error(format!("「{name}」をゴミ箱へ移動できませんでした: {e}"));
                    }
                    self.request(Request::Load { sync: false }, "再読み込みしています…");
                }
                Response::Merged(Err(e)) => self.error(format!("マージに失敗しました: {e}")),
                Response::CheckProgress { done, total } => {
                    self.check_progress = Some((done, total));
                }
                Response::HostsChecked(results) => self.on_hosts_checked(results),
                Response::Trashed { id, name, result } => {
                    self.trashing.remove(&id);
                    match result {
                        Ok(()) => {
                            self.info(format!("「{name}」をゴミ箱へ移動しました"));
                            self.items.retain(|it| it.id != id);
                            self.dead.retain(|d| d.id != id);
                            self.rebuild_groups();
                        }
                        Err(e) => {
                            self.error(format!("「{name}」をゴミ箱へ移動できませんでした: {e}"))
                        }
                    }
                }
                Response::Locked(result) => {
                    if let Err(e) = result {
                        self.error(format!("ロックに失敗しました: {e}"));
                    }
                    self.items.clear();
                    self.groups.clear();
                    self.host_status = None;
                    self.dead.clear();
                    self.select_group(None);
                    self.phase = Phase::Locked;
                }
            }
        }
    }

    fn rebuild_groups(&mut self) {
        let prev = self
            .selected_group
            .and_then(|g| self.groups.get(g))
            .map(|g| g.password_hash);
        self.groups = model::build_groups(&self.items, self.by_username);
        let next = prev.and_then(|h| self.groups.iter().position(|g| g.password_hash == h));
        self.select_group(next);
    }

    fn refresh_dead(&mut self) {
        self.dead = match &self.host_status {
            Some(results) => deadlink::find_dead(&self.items, results),
            None => Vec::new(),
        };
    }

    fn start_host_check(&mut self) {
        let targets = deadlink::collect_targets(&self.items);
        if targets.is_empty() {
            self.info("確認できる Web の URI がありません");
            return;
        }
        self.check_progress = Some((0, targets.len()));
        self.request(Request::CheckHosts(targets), "ドメインを確認しています…");
    }

    fn on_hosts_checked(&mut self, results: HashMap<Target, HostStatus>) {
        self.check_progress = None;
        let count = |s: HostStatus| results.values().filter(|&&v| v == s).count();
        let (alive, no_dns, unreachable) = (
            count(HostStatus::Alive),
            count(HostStatus::NoDns),
            count(HostStatus::Unreachable),
        );
        self.info(format!(
            "{} ホストを確認しました（応答あり {alive} / 名前解決できない {no_dns} / 接続できない {unreachable}）",
            results.len()
        ));
        if alive == 0 {
            self.error("応答したホストがありません。ネットワークに接続されているか確認してください");
        }
        self.host_status = Some(results);
        self.refresh_dead();
    }

    fn select_group(&mut self, index: Option<usize>) {
        self.selected_group = index;
        self.confirming = false;
        let Some(group) = index.and_then(|g| self.groups.get(g)) else {
            self.checked.clear();
            self.primary = None;
            return;
        };
        self.checked = group
            .members
            .iter()
            .map(|&i| self.items[i].id.clone())
            .collect();
        // パスキーや添付ファイルは移せないので、それを持つアイテムを優先して主にする
        self.primary = group
            .members
            .iter()
            .map(|&i| &self.items[i])
            .max_by_key(|it| {
                (
                    it.has_passkey,
                    it.has_attachments,
                    it.uris.len(),
                    it.revision_date.clone(),
                )
            })
            .map(|it| it.id.clone());
    }

    fn item(&self, id: &str) -> Option<&LoginItem> {
        self.items.iter().find(|i| i.id == id)
    }

    fn top_bar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.heading("Bitwarden Merger");
            if let Some(status) = &self.status {
                ui.label(format!(
                    "{} @ {}",
                    status.user_email.as_deref().unwrap_or("-"),
                    status.server_url.as_deref().unwrap_or("bitwarden.com")
                ));
            }
            if self.phase == Phase::Ready {
                ui.separator();
                ui.selectable_value(&mut self.view, View::Merge, "マージ候補");
                ui.selectable_value(&mut self.view, View::Dead, "リンク切れ");
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let idle = self.idle();
                if self.phase == Phase::Ready {
                    if ui.add_enabled(idle, egui::Button::new("ロック")).clicked() {
                        self.request(Request::Lock, "ロックしています…");
                    }
                    if ui
                        .add_enabled(idle, egui::Button::new("同期して再読込"))
                        .clicked()
                    {
                        self.request(Request::Load { sync: true }, "同期しています…");
                    }
                }
                if let Some(msg) = self.busy {
                    ui.label(msg);
                    ui.spinner();
                }
            });
        });
    }

    fn log_panel(&self, ui: &mut egui::Ui) {
        egui::ScrollArea::vertical()
            .stick_to_bottom(true)
            .auto_shrink([false, false])
            .show(ui, |ui| {
                for (level, msg) in &self.log {
                    let text = RichText::new(msg);
                    ui.label(match level {
                        LogLevel::Info => text,
                        LogLevel::Error => text.color(Color32::from_rgb(0xe0, 0x50, 0x50)),
                    });
                }
            });
    }

    fn unauthenticated_view(&mut self, ui: &mut egui::Ui) {
        ui.vertical_centered(|ui| {
            ui.add_space(60.0);
            ui.heading("Bitwarden CLI にログインしていません");
            ui.add_space(8.0);
            ui.label("ターミナルで以下を実行してログインしてから「再確認」を押してください。");
            ui.add_space(4.0);
            ui.code("bw config server https://your.server   # セルフホストの場合のみ");
            ui.code("bw login");
            ui.add_space(12.0);
            if ui
                .add_enabled(self.busy.is_none(), egui::Button::new("再確認"))
                .clicked()
            {
                self.request(Request::Status, "状態を確認しています…");
            }
        });
    }

    fn locked_view(&mut self, ui: &mut egui::Ui) {
        let id = egui::Id::new(PASSWORD_ID);
        let mut submit = false;
        ui.vertical_centered(|ui| {
            ui.add_space(60.0);
            ui.heading("保管庫のロックを解除");
            ui.add_space(12.0);
            let response = ui.add(
                egui::TextEdit::singleline(&mut self.password)
                    .id(id)
                    .password(true)
                    .hint_text("マスターパスワード")
                    .desired_width(320.0),
            );
            if response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                submit = true;
            }
            ui.add_space(8.0);
            let enabled = self.busy.is_none() && !self.password.is_empty();
            if ui
                .add_enabled(enabled, egui::Button::new("ロック解除"))
                .clicked()
            {
                submit = true;
            }
        });
        // egui の undo 履歴に平文が溜まらないよう毎フレーム消す
        if let Some(mut state) = TextEditState::load(ui.ctx(), id) {
            state.clear_undoer();
            state.store(ui.ctx(), id);
        }
        if submit && self.busy.is_none() && !self.password.is_empty() {
            let secret = self.password.take_secret();
            ui.ctx().memory_mut(|m| m.data.remove::<TextEditState>(id));
            self.request(Request::Unlock(secret), "ロックを解除しています…");
        }
    }

    fn group_list(&mut self, ui: &mut egui::Ui) {
        ui.add_space(4.0);
        ui.add(
            egui::TextEdit::singleline(&mut self.query)
                .hint_text("名前・ドメイン・ユーザー名で絞り込み"),
        );
        if ui
            .checkbox(&mut self.by_username, "ユーザー名の一致も条件にする")
            .changed()
        {
            self.rebuild_groups();
        }
        ui.label(format!("候補グループ: {} 件", self.groups.len()));
        ui.separator();
        let mut clicked = None;
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                for (gi, group) in self.groups.iter().enumerate() {
                    if !group.matches(&self.items, &self.query) {
                        continue;
                    }
                    let hosts: Vec<&str> = group.hosts.iter().take(3).map(String::as_str).collect();
                    let more = if group.hosts.len() > 3 { " …" } else { "" };
                    let text = format!(
                        "{}  ({}件)\n{}{}",
                        group.title(&self.items),
                        group.members.len(),
                        hosts.join(", "),
                        more
                    );
                    if ui
                        .selectable_label(self.selected_group == Some(gi), text)
                        .clicked()
                    {
                        clicked = Some(gi);
                    }
                }
            });
        if let Some(gi) = clicked {
            self.select_group(Some(gi));
        }
    }

    fn group_detail(&mut self, ui: &mut egui::Ui) {
        let Some(group) = self
            .selected_group
            .and_then(|g| self.groups.get(g))
            .cloned()
        else {
            ui.centered_and_justified(|ui| {
                ui.label("左の一覧から統合したいグループを選んでください")
            });
            return;
        };
        ui.heading(group.title(&self.items));
        ui.label("同じパスワードを持つアイテムです。統合するものにチェックを入れ、残すアイテム（主）を選んでください。");
        ui.horizontal(|ui| {
            if ui.button("すべてチェック").clicked() {
                self.checked = group
                    .members
                    .iter()
                    .map(|&i| self.items[i].id.clone())
                    .collect();
            }
            // 主アイテムは常に統合先なのでチェックを残す
            if ui.button("すべて外す").clicked() {
                self.checked.retain(|id| self.primary.as_deref() == Some(id));
            }
        });
        ui.add_space(6.0);

        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                egui::Grid::new("members")
                    .striped(true)
                    .num_columns(6)
                    .spacing([12.0, 6.0])
                    .show(ui, |ui| {
                        ui.strong("統合");
                        ui.strong("主");
                        ui.strong("名前");
                        ui.strong("ユーザー名");
                        ui.strong("URI");
                        ui.strong("属性");
                        ui.end_row();
                        for &i in &group.members {
                            let item = &self.items[i];
                            let mut on = self.checked.contains(&item.id);
                            if ui.checkbox(&mut on, "").changed() {
                                if on {
                                    self.checked.insert(item.id.clone());
                                } else {
                                    self.checked.remove(&item.id);
                                }
                            }
                            if ui
                                .radio(self.primary.as_deref() == Some(&item.id), "")
                                .clicked()
                            {
                                self.primary = Some(item.id.clone());
                                self.checked.insert(item.id.clone());
                            }
                            ui.label(&item.name);
                            ui.label(item.username.as_deref().unwrap_or("-"));
                            ui.vertical(|ui| {
                                for uri in &item.uris {
                                    ui.label(&uri.uri);
                                }
                            });
                            let mut tags = Vec::new();
                            if item.organization_id.is_some() {
                                tags.push("組織");
                            }
                            if item.totp_hash.is_some() {
                                tags.push("TOTP");
                            }
                            if item.has_passkey {
                                tags.push("パスキー");
                            }
                            if item.has_attachments {
                                tags.push("添付");
                            }
                            ui.label(tags.join(" / "));
                            ui.end_row();
                        }
                    });

                ui.add_space(12.0);
                ui.separator();
                self.merge_preview(ui);
            });
    }

    fn dead_view(&mut self, ui: &mut egui::Ui) {
        ui.heading("リンク切れのアイテム");
        ui.label(
            "各 URI のドメインを名前解決し、Web サーバー（443 / 80 番ポート等）へ接続できるかを確認します。\
             Web の URI がすべて応答しないアイテムだけを表示します。",
        );
        ui.label(
            RichText::new(
                "確認のため DNS サーバーと各サイトへ通信が発生します。IP 直書きやローカルネットワークのホスト、アプリの URI は対象外です。",
            )
            .weak(),
        );
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            let label = if self.host_status.is_some() {
                "もう一度確認"
            } else {
                "ドメインを確認"
            };
            if ui
                .add_enabled(self.idle(), egui::Button::new(label))
                .clicked()
            {
                self.start_host_check();
            }
            if let Some((done, total)) = self.check_progress {
                ui.add(
                    egui::ProgressBar::new(done as f32 / total.max(1) as f32)
                        .text(format!("{done} / {total}"))
                        .desired_width(240.0),
                );
            }
        });
        if self.host_status.is_none() {
            return;
        }

        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.add(
                egui::TextEdit::singleline(&mut self.dead_query)
                    .hint_text("名前・ドメイン・ユーザー名で絞り込み"),
            );
            ui.checkbox(
                &mut self.include_unreachable,
                "接続できないだけのものも表示（一時的な障害やアクセス制限の可能性あり）",
            );
        });
        let query = self.dead_query.to_lowercase();
        let by_id: HashMap<&str, &LoginItem> =
            self.items.iter().map(|it| (it.id.as_str(), it)).collect();
        let visible: Vec<(&DeadItem, &LoginItem)> = self
            .dead
            .iter()
            .filter(|d| self.include_unreachable || d.has_no_dns())
            .filter_map(|d| Some((d, *by_id.get(d.id.as_str())?)))
            .filter(|(d, item)| {
                query.is_empty()
                    || item.name.to_lowercase().contains(&query)
                    || item
                        .username
                        .as_deref()
                        .is_some_and(|u| u.to_lowercase().contains(&query))
                    || d.hosts.iter().any(|(t, _)| t.host.contains(&query))
            })
            .collect();
        ui.label(format!(
            "{} 件（全 {} 件中）。「ゴミ箱へ」は 1 件ずつ移動します（30日間は Web 保管庫から復元できます）。",
            visible.len(),
            self.dead.len()
        ));
        ui.separator();

        let can_trash = self.busy.is_none();
        let mut clicked: Option<(String, String)> = None;
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                egui::Grid::new("dead_items")
                    .striped(true)
                    .num_columns(5)
                    .spacing([12.0, 6.0])
                    .show(ui, |ui| {
                        ui.strong("");
                        ui.strong("名前");
                        ui.strong("ユーザー名");
                        ui.strong("ドメインと判定");
                        ui.strong("属性");
                        ui.end_row();
                        for (dead, item) in &visible {
                            if self.trashing.contains(&item.id) {
                                ui.horizontal(|ui| {
                                    ui.spinner();
                                    ui.label("移動中…");
                                });
                            } else if ui
                                .add_enabled(can_trash, egui::Button::new("ゴミ箱へ"))
                                .clicked()
                            {
                                clicked = Some((item.id.clone(), item.name.clone()));
                            }
                            ui.label(&item.name);
                            ui.label(item.username.as_deref().unwrap_or("-"));
                            ui.vertical(|ui| {
                                for (target, status) in &dead.hosts {
                                    let color = match status {
                                        HostStatus::NoDns => Color32::from_rgb(0xe0, 0x50, 0x50),
                                        _ => Color32::from_rgb(0xd0, 0xa0, 0x20),
                                    };
                                    ui.horizontal(|ui| {
                                        ui.label(target.to_string());
                                        ui.colored_label(color, status.label());
                                    });
                                }
                            });
                            let mut tags = Vec::new();
                            if item.organization_id.is_some() {
                                tags.push("組織");
                            }
                            if item.totp_hash.is_some() {
                                tags.push("TOTP");
                            }
                            if item.has_passkey {
                                tags.push("パスキー");
                            }
                            if item.has_attachments {
                                tags.push("添付");
                            }
                            ui.label(tags.join(" / "));
                            ui.end_row();
                        }
                    });
            });
        if let Some((id, name)) = clicked {
            self.trashing.insert(id.clone());
            self.worker.send(Request::Trash { id, name });
        }
    }

    /// 現在の選択から主アイテムと統合対象を取り出す。
    fn selection(&self) -> Option<(&LoginItem, Vec<&LoginItem>)> {
        let group = self.groups.get(self.selected_group?)?;
        let primary = self.item(self.primary.as_deref()?)?;
        let others = group
            .members
            .iter()
            .map(|&i| &self.items[i])
            .filter(|it| it.id != primary.id && self.checked.contains(&it.id))
            .collect();
        Some((primary, others))
    }

    fn merge_preview(&mut self, ui: &mut egui::Ui) {
        let Some((primary, others)) = self.selection() else {
            ui.label("主アイテムを選んでください");
            return;
        };
        ui.strong(format!("統合後の URI（「{}」に集約）", primary.name));
        for uri in model::merged_uris(primary, others.iter().copied()) {
            ui.label(format!("・{}", uri.uri));
        }
        ui.add_space(8.0);
        let check = model::check_merge(primary, &others);
        for e in &check.errors {
            ui.colored_label(Color32::from_rgb(0xe0, 0x50, 0x50), format!("✖ {e}"));
        }
        for w in &check.warnings {
            ui.colored_label(Color32::from_rgb(0xd0, 0xa0, 0x20), format!("⚠ {w}"));
        }
        let can_merge = check.errors.is_empty() && self.idle();
        let other_count = others.len();

        ui.add_space(8.0);
        ui.checkbox(&mut self.options.merge_notes, "メモを追記して統合する");
        ui.checkbox(
            &mut self.options.merge_fields,
            "カスタムフィールドを統合する",
        );
        ui.checkbox(
            &mut self.options.adopt_totp,
            "主アイテムに TOTP がなければ他から引き継ぐ",
        );
        ui.add_space(8.0);
        let label = format!("マージ実行（{other_count} 件をゴミ箱へ）");
        if ui
            .add_enabled(can_merge, egui::Button::new(label))
            .clicked()
        {
            self.confirming = true;
        }
    }

    fn confirm_modal(&mut self, ctx: &egui::Context) {
        if !self.confirming {
            return;
        }
        let Some((primary, others)) = self.selection() else {
            self.confirming = false;
            return;
        };
        let primary_name = primary.name.clone();
        let other_names: Vec<String> = others.iter().map(|o| o.name.clone()).collect();
        let request = MergeRequest {
            primary_id: primary.id.clone(),
            other_ids: others.iter().map(|o| o.id.clone()).collect(),
            expected_hash: primary.password_hash.expect("checked by check_merge"),
            options: self.options,
        };

        let mut decision = None;
        egui::Modal::new(egui::Id::new("confirm_merge")).show(ctx, |ui| {
            ui.heading("マージの確認");
            ui.label(format!(
                "「{primary_name}」を残し、次のアイテムの内容を統合します。"
            ));
            for name in &other_names {
                ui.label(format!("・{name}"));
            }
            ui.label(
                "統合元のアイテムはゴミ箱へ移動されます（30日間は Web 保管庫から復元できます）。",
            );
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if ui.button("実行").clicked() {
                    decision = Some(true);
                }
                if ui.button("キャンセル").clicked()
                    || ui.input(|i| i.key_pressed(egui::Key::Escape))
                {
                    decision = Some(false);
                }
            });
        });
        match decision {
            Some(true) => {
                self.confirming = false;
                self.request(Request::Merge(request), "マージしています…");
            }
            Some(false) => self.confirming = false,
            None => {}
        }
    }
}

impl eframe::App for MergerApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.handle_responses();
        let ctx = ui.ctx().clone();

        egui::Panel::top("top_bar").show(ui, |ui| {
            ui.add_space(4.0);
            self.top_bar(ui);
            ui.add_space(4.0);
        });
        egui::Panel::bottom("log")
            .resizable(true)
            .default_size(120.0)
            .show(ui, |ui| self.log_panel(ui));

        match self.phase {
            Phase::Starting => {
                egui::CentralPanel::default().show(ui, |ui| {
                    ui.centered_and_justified(|ui| ui.spinner());
                });
            }
            Phase::Unauthenticated => {
                egui::CentralPanel::default().show(ui, |ui| self.unauthenticated_view(ui));
            }
            Phase::Locked => {
                egui::CentralPanel::default().show(ui, |ui| self.locked_view(ui));
            }
            Phase::Ready => match self.view {
                View::Merge => {
                    egui::Panel::left("groups")
                        .resizable(true)
                        .default_size(320.0)
                        .show(ui, |ui| self.group_list(ui));
                    egui::CentralPanel::default().show(ui, |ui| self.group_detail(ui));
                    self.confirm_modal(&ctx);
                }
                View::Dead => {
                    egui::CentralPanel::default().show(ui, |ui| self.dead_view(ui));
                }
            },
        }
    }
}
