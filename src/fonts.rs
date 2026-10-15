//! 日本語表示のため、OS に入っている CJK フォントを探してフォールバックとして登録する。
//! `BWM_FONT` 環境変数でフォントファイルを直接指定することもできる。

use std::path::PathBuf;

use eframe::egui::{self, FontData, FontFamily};
use eframe::epaint::text::{FontInsert, FontPriority, InsertFontFamily};

#[cfg(target_os = "windows")]
const CANDIDATES: &[&str] = &[
    r"C:\Windows\Fonts\YuGothM.ttc",
    r"C:\Windows\Fonts\meiryo.ttc",
    r"C:\Windows\Fonts\msgothic.ttc",
];

#[cfg(target_os = "macos")]
const CANDIDATES: &[&str] = &[
    "/System/Library/Fonts/ヒラギノ角ゴシック W3.ttc",
    "/System/Library/Fonts/Hiragino Sans GB.ttc",
    "/System/Library/Fonts/Supplemental/Arial Unicode.ttf",
    "/Library/Fonts/Arial Unicode.ttf",
];

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
const CANDIDATES: &[&str] = &[
    "/usr/share/fonts/noto-cjk/NotoSansCJK-Regular.ttc",
    "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
    "/usr/share/fonts/google-noto-cjk/NotoSansCJK-Regular.ttc",
    "/usr/share/fonts/noto-cjk/NotoSansJP-Regular.otf",
    "/usr/share/fonts/OTF/ipagp.ttf",
    "/usr/share/fonts/opentype/ipafont-gothic/ipagp.ttf",
    "/usr/share/fonts/truetype/fonts-japanese-gothic.ttf",
];

pub fn install_japanese_font(ctx: &egui::Context) {
    let paths = std::env::var_os("BWM_FONT")
        .map(PathBuf::from)
        .into_iter()
        .chain(CANDIDATES.iter().map(PathBuf::from));
    for path in paths {
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        ctx.add_font(FontInsert::new(
            "japanese",
            FontData::from_owned(bytes),
            vec![
                InsertFontFamily {
                    family: FontFamily::Proportional,
                    priority: FontPriority::Lowest,
                },
                InsertFontFamily {
                    family: FontFamily::Monospace,
                    priority: FontPriority::Lowest,
                },
            ],
        ));
        return;
    }
    eprintln!(
        "日本語フォントが見つかりませんでした。BWM_FONT 環境変数でフォントファイルを指定してください"
    );
}
