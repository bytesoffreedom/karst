//! egui-view — ТОНКИЙ слой над `controller::App`. Читает состояние, рисует, шлёт
//! `Cmd` в worker, вливает `Evt` каждый кадр. Никакой логики/крипты здесь.
//!
//! Экраны входа: Welcome (создать/восстановить) · Unlock (возврат) · CreateShow
//! (показ фразы) · CreateConfirm (сверка) · Restore (ввод фразы) · Ready.
//!
//! **Не run-verified в headless-среде** (реального окна не запустить); логика
//! экранов покрыта тестами контроллера, worker — интеграционными.

use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::mpsc::{Receiver, Sender};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use eframe::egui;

use gui::controller::{App as State, Cmd, Evt, Screen};

// --- Палитра (тёмная тема) ---
const BG: egui::Color32 = egui::Color32::from_rgb(0x14, 0x16, 0x1B);
const PANEL: egui::Color32 = egui::Color32::from_rgb(0x1B, 0x1E, 0x26);
const BUBBLE_ME: egui::Color32 = egui::Color32::from_rgb(0x2F, 0x6F, 0xEB);
const BUBBLE_THEM: egui::Color32 = egui::Color32::from_rgb(0x26, 0x2A, 0x34);
const TEXT: egui::Color32 = egui::Color32::from_rgb(0xE7, 0xE9, 0xEF);
const MUTED: egui::Color32 = egui::Color32::from_rgb(0x8A, 0x90, 0xA0);
const ACCENT: egui::Color32 = egui::Color32::from_rgb(0x4C, 0x8B, 0xF5);
const WARN: egui::Color32 = egui::Color32::from_rgb(0xE5, 0xA5, 0x4B);
/// Фон полей ввода — тёмный «колодец», ЗАМЕТНО темнее карточки (PANEL), иначе
/// пустое поле сливается с карточкой и его не видно (был визуальный баг).
const INPUT: egui::Color32 = egui::Color32::from_rgb(0x0E, 0x10, 0x15);
/// Тонкая рамка неактивных элементов — гарантирует видимость пустого поля даже
/// когда заливка близка к фону.
const BORDER: egui::Color32 = egui::Color32::from_rgb(0x39, 0x3F, 0x4C);
/// Зелёный «хорошо» — сверенный контакт, на связи, доставлено.
const GOOD: egui::Color32 = egui::Color32::from_rgb(0x4F, 0xC1, 0x7A);
/// Красный «ошибка» — не отправлено, нет связи.
const BAD: egui::Color32 = egui::Color32::from_rgb(0xE0, 0x6B, 0x5C);

pub struct KarstApp {
    state: State,
    cmd_tx: Sender<Cmd>,
    evt_rx: Receiver<Evt>,
    themed: bool,
    /// Экран, на котором уже выставили автофокус на первое поле (чтобы не воровать
    /// фокус каждый кадр). Смена экрана → новый автофокус. `None` = ещё не фокусили.
    focused_on: Option<Screen>,
    /// Последний заголовок окна — чтобы слать `ViewportCommand::Title` только на
    /// смене (счётчик непрочитанных), а не каждый кадр.
    last_title: String,
    /// Avatar texture cache, keyed by IK (own avatar under `own_ik`). Value is
    /// `(hash-of-bytes, texture)` so we only re-upload when the avatar bytes change —
    /// never `load_texture` every frame.
    avatar_tex: HashMap<[u8; 32], (u64, egui::TextureHandle)>,
    /// State directory — where the plaintext `lang` preference is written on change.
    dir: std::path::PathBuf,
}

impl KarstApp {
    /// `has_account` — есть ли уже корень на диске (`seed.key`): да → экран входа
    /// паролем; нет → приветствие (создать/восстановить). Решает вызывающий (main),
    /// т.к. контроллер чист (без диска).
    pub fn new(
        cmd_tx: Sender<Cmd>,
        evt_rx: Receiver<Evt>,
        has_account: bool,
        dir: std::path::PathBuf,
        lang: gui::i18n::Lang,
    ) -> Self {
        let mut state = State::new();
        state.lang = lang;
        state.screen = if has_account { Screen::Unlock } else { Screen::Welcome };
        // Предзаполнение из env (харнесс `karst-gui.sh` подставляет relay-id,
        // чтобы не копировать руками). Пусто → значения по умолчанию/ручной ввод.
        if let Ok(r) = std::env::var("KARST_RELAY") {
            if !r.is_empty() {
                state.in_relay_addr = r;
            }
        }
        if let Ok(id) = std::env::var("KARST_RELAY_ID") {
            state.in_relay_id = id;
        }
        if let Ok(s) = std::env::var("KARST_SOCKS5") {
            state.in_socks5 = s;
        }
        // Extra failover routes: prefill from the operator envs so an existing setup
        // keeps working, but the field is the source of truth — what the user sees is
        // what gets used (the worker no longer reads these envs).
        let env_routes = [
            std::env::var("KARST_RELAY_ALTS").unwrap_or_default(),
            std::env::var("KARST_PATHS").unwrap_or_default(),
        ]
        .into_iter()
        .filter(|v| !v.trim().is_empty())
        .collect::<Vec<_>>()
        .join(",");
        if !env_routes.is_empty() {
            state.in_routes = env_routes;
        }
        KarstApp {
            state,
            cmd_tx,
            evt_rx,
            themed: false,
            focused_on: None,
            last_title: String::new(),
            avatar_tex: HashMap::new(),
            dir,
        }
    }

    /// Switch UI language and persist the choice to the plaintext `lang` file (so it
    /// survives restart and is available before unlock). Best-effort write.
    fn set_lang(&mut self, lang: gui::i18n::Lang) {
        if self.state.lang == lang {
            return;
        }
        self.state.lang = lang;
        // KARST_HOME may not exist yet (no account created) — ensure it before writing.
        let _ = std::fs::create_dir_all(&self.dir);
        let _ = std::fs::write(self.dir.join("lang"), lang.code());
    }

    /// Compact language switcher: a combo of endonyms. Reachable pre-unlock.
    fn language_switcher(&mut self, ui: &mut egui::Ui) {
        use gui::i18n::{Key, Lang};
        let cur = self.state.lang;
        let mut pick = cur;
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new(self.state.tr(Key::LangLabel)).color(MUTED).small());
            egui::ComboBox::from_id_salt("lang_switcher")
                .selected_text(egui::RichText::new(cur.native_name()).color(TEXT).small())
                .show_ui(ui, |ui| {
                    for l in Lang::ALL {
                        ui.selectable_value(&mut pick, l, l.native_name());
                    }
                });
        });
        if pick != cur {
            self.set_lang(pick);
        }
    }

    /// Get-or-build a texture for `bytes` under `key`, re-uploading only when the
    /// bytes change. `None` if the bytes don't decode (render falls back to nothing).
    fn avatar_texture(
        &mut self,
        ctx: &egui::Context,
        key: [u8; 32],
        bytes: &[u8],
    ) -> Option<egui::TextureHandle> {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        bytes.hash(&mut hasher);
        let h = hasher.finish();
        if let Some((cached, tex)) = self.avatar_tex.get(&key) {
            if *cached == h {
                return Some(tex.clone());
            }
        }
        let (w, ht, rgba) = gui::avatar::to_rgba(bytes)?;
        let img = egui::ColorImage::from_rgba_unmultiplied([w, ht], &rgba);
        let tex = ctx.load_texture(format!("av-{}", hex::encode(&key[..6])), img, egui::TextureOptions::LINEAR);
        self.avatar_tex.insert(key, (h, tex.clone()));
        Some(tex)
    }

    /// Draw an avatar `bytes` at `size` px (square), or a muted placeholder dot.
    fn avatar_widget(&mut self, ui: &mut egui::Ui, key: [u8; 32], bytes: Option<&[u8]>, size: f32) {
        let ctx = ui.ctx().clone();
        if let Some(b) = bytes {
            if let Some(tex) = self.avatar_texture(&ctx, key, b) {
                ui.add(egui::Image::new(&tex).fit_to_exact_size(egui::vec2(size, size)).rounding(size / 2.0));
                return;
            }
        }
        // Placeholder: a muted filled circle.
        let (rect, _) = ui.allocate_exact_size(egui::vec2(size, size), egui::Sense::hover());
        ui.painter().circle_filled(rect.center(), size / 2.0, BUBBLE_THEM);
    }

    /// Wire the bundled CJK fallback font so Chinese/Japanese render (egui's default
    /// fonts cover only Latin + Cyrillic). Appended to BOTH families' fallback lists,
    /// so missing glyphs in any string fall back to it. Embedded (not read from a
    /// system path) so it works wherever the binary runs.
    fn setup_fonts(ctx: &egui::Context) {
        const CJK: &[u8] = include_bytes!("../assets/fonts/DroidSansFallbackFull.ttf");
        let mut fonts = egui::FontDefinitions::default();
        fonts.font_data.insert("cjk".to_string(), egui::FontData::from_static(CJK));
        for fam in [egui::FontFamily::Proportional, egui::FontFamily::Monospace] {
            fonts.families.entry(fam).or_default().push("cjk".to_string());
        }
        ctx.set_fonts(fonts);
    }

    /// Применить тему один раз (тёмная + акцент + просторные отступы).
    fn apply_theme(ctx: &egui::Context) {
        let mut v = egui::Visuals::dark();
        v.panel_fill = BG;
        v.window_fill = PANEL;
        // Поля ввода (TextEdit) рисуются `extreme_bg_color` — тёмный колодец,
        // видимый и на карточке (PANEL), и на панели (BG).
        v.extreme_bg_color = INPUT;
        v.override_text_color = Some(TEXT);
        v.selection.bg_fill = ACCENT.gamma_multiply(0.45);
        v.widgets.inactive.bg_fill = PANEL;
        // Тонкая рамка вокруг неактивных виджетов/полей → пустое поле не исчезает.
        v.widgets.inactive.bg_stroke = egui::Stroke::new(1.0_f32, BORDER);
        v.widgets.hovered.bg_fill = BUBBLE_THEM;
        v.widgets.hovered.bg_stroke = egui::Stroke::new(1.0_f32, ACCENT.gamma_multiply(0.7));
        v.widgets.active.bg_stroke = egui::Stroke::new(1.0_f32, ACCENT);
        v.hyperlink_color = ACCENT;
        ctx.set_visuals(v);

        let mut style = (*ctx.style()).clone();
        style.spacing.item_spacing = egui::vec2(8.0, 8.0);
        style.spacing.button_padding = egui::vec2(10.0, 6.0);
        ctx.set_style(style);
    }

    fn drain_events(&mut self) {
        while let Ok(evt) = self.evt_rx.try_recv() {
            self.state.apply(evt);
        }
    }

    fn send(&self, cmd: Cmd) {
        let _ = self.cmd_tx.send(cmd);
    }

    /// Нужно ли выставить автофокус первому полю этого экрана в этом кадре.
    fn take_focus(&mut self, screen: Screen) -> bool {
        if self.focused_on != Some(screen) {
            self.focused_on = Some(screen);
            true
        } else {
            false
        }
    }

    // ---------- экраны входа ----------

    /// Общий центрированный «конверт» бренда + карточка заданной ширины.
    fn brand_card(
        ctx: &egui::Context,
        subtitle: &str,
        width: f32,
        body: impl FnOnce(&mut egui::Ui),
    ) {
        egui::CentralPanel::default().show(ctx, |ui| {
            let avail = ui.available_height();
            ui.add_space((avail * 0.10).clamp(18.0, 90.0));
            ui.vertical_centered(|ui| {
                ui.label(egui::RichText::new("◆").size(28.0).color(ACCENT));
                ui.label(egui::RichText::new("KARST").size(38.0).strong().color(TEXT));
                ui.add_space(2.0);
                ui.label(egui::RichText::new(subtitle).size(13.0).color(MUTED));
                ui.add_space(20.0);
                egui::Frame::none()
                    .fill(PANEL)
                    .rounding(egui::Rounding::same(14.0))
                    .inner_margin(egui::Margin::same(22.0))
                    .show(ui, |ui| {
                        ui.set_width(width);
                        body(ui);
                    });
            });
        });
    }

    /// Полноширинная акцентная кнопка. `true` при клике.
    fn primary(ui: &mut egui::Ui, label: &str) -> bool {
        let btn = egui::Button::new(egui::RichText::new(label).size(15.0).color(egui::Color32::WHITE))
            .fill(ACCENT)
            .min_size(egui::vec2(ui.available_width(), 36.0))
            .rounding(egui::Rounding::same(8.0));
        ui.add(btn).clicked()
    }

    /// Полноширинная второстепенная кнопка (контур). `true` при клике.
    fn secondary(ui: &mut egui::Ui, label: &str) -> bool {
        let btn = egui::Button::new(egui::RichText::new(label).size(14.0).color(TEXT))
            .fill(BUBBLE_THEM)
            .min_size(egui::vec2(ui.available_width(), 34.0))
            .rounding(egui::Rounding::same(8.0));
        ui.add(btn).clicked()
    }

    /// Поле пароля с подписью. Возвращает ответ (для Enter/фокуса).
    fn password_field(ui: &mut egui::Ui, label: &str, value: &mut String) -> egui::Response {
        ui.label(egui::RichText::new(label).color(MUTED).small());
        ui.add(
            egui::TextEdit::singleline(value)
                .password(true)
                .desired_width(f32::INFINITY)
                .margin(egui::Margin::symmetric(10.0, 8.0)),
        )
    }

    /// Поля сети (relay / relay-id / socks5). `collapsible` — прятать ли под
    /// раскрывашку (на входе — да, если relay-id уже задан; на восстановлении —
    /// нет: новое устройство обязано их ввести).
    fn network_fields(ui: &mut egui::Ui, state: &mut State, collapsible: bool) {
        use gui::i18n::Key;
        let draw = |ui: &mut egui::Ui, state: &mut State| {
            // Precompute labels/hints (each &'static) so the state borrow is released
            // before the &mut state.in_* TextEdit borrows.
            let l_relay = state.tr(Key::NetRelay);
            let l_relay_id = state.tr(Key::NetRelayId);
            let h_relay_id = state.tr(Key::NetRelayIdHint);
            let l_socks = state.tr(Key::NetSocks5);
            let h_socks = state.tr(Key::NetSocks5Hint);
            let l_routes = state.tr(Key::NetRoutes);
            let h_routes = state.tr(Key::NetRoutesHint);
            ui.label(egui::RichText::new(l_relay).color(MUTED).small());
            ui.add(
                egui::TextEdit::singleline(&mut state.in_relay_addr)
                    .desired_width(f32::INFINITY)
                    .margin(egui::Margin::symmetric(10.0, 7.0)),
            );
            ui.label(egui::RichText::new(l_relay_id).color(MUTED).small());
            ui.add(
                egui::TextEdit::singleline(&mut state.in_relay_id)
                    .desired_width(f32::INFINITY)
                    .margin(egui::Margin::symmetric(10.0, 7.0))
                    .hint_text(h_relay_id),
            );
            ui.label(egui::RichText::new(l_socks).color(MUTED).small());
            ui.add(
                egui::TextEdit::singleline(&mut state.in_socks5)
                    .desired_width(f32::INFINITY)
                    .margin(egui::Margin::symmetric(10.0, 7.0))
                    .hint_text(h_socks),
            );
            // Extra §15 routes: what makes failover reachable without env vars.
            ui.label(egui::RichText::new(l_routes).color(MUTED).small());
            ui.add(
                egui::TextEdit::singleline(&mut state.in_routes)
                    .desired_width(f32::INFINITY)
                    .margin(egui::Margin::symmetric(10.0, 7.0))
                    .hint_text(h_routes),
            );
            // SECONDARY relays (multi-homing): distinct relay identities, one per line.
            // Unlike routes above (extra paths to the SAME relay), these let a contact
            // reach you through more than one relay so blocking one does not cut you off.
            let l_extra = state.tr(Key::NetExtraRelays);
            let h_extra = state.tr(Key::NetExtraRelaysHint);
            ui.label(egui::RichText::new(l_extra).color(MUTED).small());
            ui.add(
                egui::TextEdit::multiline(&mut state.in_extra_relays)
                    .desired_width(f32::INFINITY)
                    .desired_rows(2)
                    .margin(egui::Margin::symmetric(10.0, 7.0))
                    .hint_text(h_extra),
            );
        };
        if collapsible {
            let open = state.in_relay_id.trim().is_empty();
            let section = state.tr(Key::NetSection);
            egui::CollapsingHeader::new(egui::RichText::new(section).color(MUTED).small())
                .default_open(open)
                .show(ui, |ui| draw(ui, state));
        } else {
            draw(ui, state);
        }
    }

    fn status_line(ui: &mut egui::Ui, status: &str) {
        if !status.is_empty() {
            ui.add_space(10.0);
            ui.label(egui::RichText::new(status).color(MUTED).small());
        }
    }

    /// Приветствие: создать или восстановить. В режиме ДОБАВЛЕНИЯ (vault уже
    /// разблокирован) — заголовок про новый аккаунт + «Отмена» к активному чату.
    fn welcome_ui(&mut self, ctx: &egui::Context) {
        use gui::i18n::Key;
        let adding = self.state.adding_account;
        let subtitle = if adding {
            self.state.tr(Key::WelcomeSubtitleAdd)
        } else {
            self.state.tr(Key::WelcomeSubtitleNew)
        };
        Self::brand_card(ctx, subtitle, 320.0, |ui| {
            if adding {
                ui.label(egui::RichText::new(self.state.tr(Key::WelcomeAddTitle)).color(TEXT));
                ui.add_space(4.0);
                ui.label(egui::RichText::new(self.state.tr(Key::WelcomeAddNote)).color(MUTED).small());
            } else {
                ui.label(egui::RichText::new(self.state.tr(Key::WelcomeNewTitle)).color(TEXT));
                ui.add_space(4.0);
                ui.label(egui::RichText::new(self.state.tr(Key::WelcomeNewNote)).color(MUTED).small());
            }
            ui.add_space(16.0);
            if Self::primary(ui, self.state.tr(Key::BtnCreateAccount)) {
                self.state.action_start_create();
            }
            ui.add_space(8.0);
            if Self::secondary(ui, self.state.tr(Key::BtnRestorePhrase)) {
                self.state.action_start_restore();
            }
            if adding {
                ui.add_space(8.0);
                if Self::secondary(ui, self.state.tr(Key::BtnCancel)) {
                    self.state.action_cancel_add();
                }
            }
            Self::status_line(ui, &self.state.status);
            ui.add_space(6.0);
            ui.separator();
            self.language_switcher(ui);
        });
    }

    /// Возврат: ввод пароля к существующему аккаунту.
    fn unlock_ui(&mut self, ctx: &egui::Context) {
        use gui::i18n::Key;
        let want_focus = self.take_focus(Screen::Unlock);
        let subtitle = self.state.tr(Key::UnlockSubtitle);
        let pw_label = self.state.tr(Key::FieldPassword);
        Self::brand_card(ctx, subtitle, 340.0, |ui| {
            let mut submit = false;
            let pw = Self::password_field(ui, pw_label, &mut self.state.in_passphrase);
            if want_focus {
                pw.request_focus();
            }
            if pw.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                submit = true;
            }
            ui.add_space(10.0);
            Self::network_fields(ui, &mut self.state, true);
            ui.add_space(16.0);
            if Self::primary(ui, self.state.tr(Key::BtnLogin)) || submit {
                if let Some(cmd) = self.state.action_unlock() {
                    self.send(cmd);
                }
            }
            ui.add_space(6.0);
            if ui
                .add(egui::Label::new(egui::RichText::new(self.state.tr(Key::LinkOtherAccount)).color(MUTED).small()).sense(egui::Sense::click()))
                .clicked()
            {
                self.state.action_back_to_welcome();
            }
            Self::status_line(ui, &self.state.status);
            ui.add_space(6.0);
            ui.separator();
            self.language_switcher(ui);
        });
    }

    /// Создание, шаг 1: показать фразу для записи.
    fn create_show_ui(&mut self, ctx: &egui::Context) {
        use gui::i18n::Key;
        let phrase = self.state.new_phrase.clone().unwrap_or_default();
        let words: Vec<&str> = phrase.split_whitespace().collect();
        let subtitle = self.state.tr(Key::OnbSubtitleWrite);
        Self::brand_card(ctx, subtitle, 380.0, |ui| {
            ui.label(egui::RichText::new(self.state.tr(Key::RecoveryPhraseTitle)).strong().color(TEXT));
            ui.add_space(2.0);
            ui.label(egui::RichText::new(self.state.tr(Key::RecoveryPhraseWarn)).color(WARN).small());
            ui.add_space(12.0);
            // Сетка 2 колонки × 6 строк, слова пронумерованы.
            egui::Frame::none()
                .fill(BG)
                .rounding(egui::Rounding::same(10.0))
                .inner_margin(egui::Margin::same(12.0))
                .show(ui, |ui| {
                    egui::Grid::new("phrase_grid").num_columns(2).spacing(egui::vec2(24.0, 8.0)).show(ui, |ui| {
                        for row in 0..6 {
                            for col in 0..2 {
                                let i = col * 6 + row;
                                if let Some(w) = words.get(i) {
                                    ui.horizontal(|ui| {
                                        ui.label(egui::RichText::new(format!("{:>2}.", i + 1)).color(MUTED).monospace());
                                        ui.label(egui::RichText::new(*w).color(TEXT).monospace().size(15.0));
                                    });
                                }
                            }
                            ui.end_row();
                        }
                    });
                });
            ui.add_space(8.0);
            if ui.add(egui::Button::new(egui::RichText::new(self.state.tr(Key::BtnCopy)).color(MUTED).small()).fill(PANEL)).clicked() {
                ui.output_mut(|o| o.copied_text = phrase.clone());
            }
            ui.add_space(12.0);
            if Self::primary(ui, self.state.tr(Key::BtnWroteItDown)) {
                self.state.action_create_continue();
            }
            ui.add_space(8.0);
            if Self::secondary(ui, self.state.tr(Key::BtnBack)) {
                self.state.action_back_to_welcome();
            }
            Self::status_line(ui, &self.state.status);
        });
    }

    /// Создание, шаг 2: сверка слов + пароль + сеть.
    fn create_confirm_ui(&mut self, ctx: &egui::Context) {
        use gui::i18n::Key;
        let positions = self.state.confirm_positions;
        let want_focus = self.take_focus(Screen::CreateConfirm);
        let subtitle = self.state.tr(Key::OnbSubtitleVerify);
        Self::brand_card(ctx, subtitle, 340.0, |ui| {
            ui.label(egui::RichText::new(self.state.tr(Key::ConfirmPrompt)).color(TEXT).small());
            ui.add_space(8.0);
            for (k, pos) in positions.iter().enumerate() {
                let word_label = self.state.tr(Key::WordNoTpl).replace("{}", &(pos + 1).to_string());
                ui.label(egui::RichText::new(word_label).color(MUTED).small());
                let resp = ui.add(
                    egui::TextEdit::singleline(&mut self.state.in_confirm[k])
                        .desired_width(f32::INFINITY)
                        .margin(egui::Margin::symmetric(10.0, 7.0)),
                );
                if want_focus && k == 0 {
                    resp.request_focus();
                }
            }
            ui.add_space(10.0);
            if self.state.adding_account {
                // Добавление: пароль/сеть уже есть — только метка (необязательно).
                let hint = self.state.tr(Key::AccountLabelHintWork);
                ui.label(egui::RichText::new(self.state.tr(Key::AccountLabelOptional)).color(MUTED).small());
                ui.add(
                    egui::TextEdit::singleline(&mut self.state.in_account_label)
                        .desired_width(f32::INFINITY)
                        .margin(egui::Margin::symmetric(10.0, 7.0))
                        .hint_text(hint),
                );
            } else {
                let pw_label = self.state.tr(gui::i18n::Key::FieldPassword);
                Self::password_field(ui, pw_label, &mut self.state.in_passphrase);
                ui.add_space(8.0);
                Self::network_fields(ui, &mut self.state, true);
            }
            ui.add_space(16.0);
            if Self::primary(ui, self.state.tr(Key::BtnCreateAccount)) {
                if let Some(cmd) = self.state.action_confirm_create() {
                    self.send(cmd);
                }
            }
            ui.add_space(8.0);
            if Self::secondary(ui, self.state.tr(Key::BtnBackToPhrase)) {
                self.state.screen = Screen::CreateShow;
            }
            if self.state.adding_account {
                ui.add_space(6.0);
                if Self::secondary(ui, self.state.tr(Key::BtnCancel)) {
                    self.state.action_cancel_add();
                }
            }
            Self::status_line(ui, &self.state.status);
        });
    }

    /// Восстановление: ввод фразы + пароль + сеть (сеть НЕ прячем — новое устройство).
    fn restore_ui(&mut self, ctx: &egui::Context) {
        use gui::i18n::Key;
        let want_focus = self.take_focus(Screen::Restore);
        let subtitle = self.state.tr(Key::OnbSubtitleRestore);
        Self::brand_card(ctx, subtitle, 360.0, |ui| {
            let phrase_hint = self.state.tr(Key::RestoreHint);
            ui.label(egui::RichText::new(self.state.tr(Key::RestorePrompt)).color(TEXT).small());
            ui.add_space(6.0);
            let resp = ui.add(
                egui::TextEdit::multiline(&mut self.state.in_restore_phrase)
                    .desired_width(f32::INFINITY)
                    .desired_rows(3)
                    .hint_text(phrase_hint),
            );
            if want_focus {
                resp.request_focus();
            }
            ui.add_space(10.0);
            if self.state.adding_account {
                // Добавление: пароль/сеть уже есть — только метка (необязательно).
                let hint = self.state.tr(Key::AccountLabelHintPersonal);
                ui.label(egui::RichText::new(self.state.tr(Key::AccountLabelOptional)).color(MUTED).small());
                ui.add(
                    egui::TextEdit::singleline(&mut self.state.in_account_label)
                        .desired_width(f32::INFINITY)
                        .margin(egui::Margin::symmetric(10.0, 7.0))
                        .hint_text(hint),
                );
            } else {
                let pw_label = self.state.tr(Key::FieldPassword);
                Self::password_field(ui, pw_label, &mut self.state.in_passphrase);
                ui.add_space(8.0);
                // Сеть развёрнута: на новом устройстве relay-id надо ввести.
                Self::network_fields(ui, &mut self.state, false);
            }
            ui.add_space(16.0);
            if Self::primary(ui, self.state.tr(Key::BtnRestore)) {
                if let Some(cmd) = self.state.action_restore() {
                    self.send(cmd);
                }
            }
            ui.add_space(8.0);
            if Self::secondary(ui, if self.state.adding_account { self.state.tr(Key::BtnCancel) } else { self.state.tr(Key::BtnBack) }) {
                if self.state.adding_account {
                    self.state.action_cancel_add();
                } else {
                    self.state.action_back_to_welcome();
                }
            }
            Self::status_line(ui, &self.state.status);
        });
    }

    fn ready_ui(&mut self, ctx: &egui::Context) {
        use gui::i18n::Key;
        egui::TopBottomPanel::top("top").show(ctx, |ui| {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("KARST").strong().color(ACCENT));
                ui.separator();
                // Индикатор связи с relay (цветом, без дингбат-глифа → не «тофу»).
                if self.state.connected {
                    ui.label(egui::RichText::new(self.state.tr(Key::StatusConnected)).color(GOOD).small());
                } else {
                    ui.label(egui::RichText::new(self.state.tr(Key::StatusDisconnected)).color(MUTED).small());
                }
                // Active §15 carrier (direct/SOCKS5/wss) — so the transport/proxy is
                // visible, not a silent assumption. Technical label, hover explains.
                if let Some(carrier) = self.state.carrier {
                    ui.separator();
                    ui.label(
                        egui::RichText::new(format!("via {}", carrier.label())).color(MUTED).small(),
                    )
                    .on_hover_text(self.state.tr(Key::CarrierHover));
                }
                ui.separator();
                // "Me": avatar + display name, like a normal messenger — the raw §2.1
                // address is on hover + the copy button, not shouted as a hex blob. The
                // name is MY OWN self-declared name (no spoofing risk for oneself);
                // peers are still shown by their LOCAL label elsewhere.
                let ik = self.state.own_ik.map(hex::encode).unwrap_or_default();
                let short = ik.get(..16).unwrap_or(&ik).to_string();
                let my_name = self.state.my_name.clone();
                let addr_hover = self.state.tr(Key::MyAddress).to_string();
                let copy = self.state.tr(Key::BtnCopy);
                if let Some(own) = self.state.own_ik {
                    let av = self.state.my_avatar.clone();
                    self.avatar_widget(ui, own, av.as_deref(), 20.0);
                }
                let display = if my_name.is_empty() {
                    egui::RichText::new(&short).monospace().color(TEXT)
                } else {
                    egui::RichText::new(&my_name).color(TEXT)
                };
                ui.label(display).on_hover_text(format!("{addr_hover} {ik}"));
                if ui.small_button(copy).clicked() {
                    ui.output_mut(|o| o.copied_text = ik.clone());
                }
            });
            ui.add_space(4.0);
        });

        egui::SidePanel::left("contacts")
            .resizable(true)
            .default_width(230.0)
            .min_width(160.0)
            .max_width(360.0)
            .show(ctx, |ui| {
            ui.add_space(6.0);

            // Переключатель аккаунтов (как в Telegram): активный в заголовке,
            // раскрытие — список + «Добавить аккаунт».
            let active_label = self
                .state
                .accounts
                .iter()
                .find(|a| Some(&a.id) == self.state.active_account.as_ref())
                .map(|a| a.label.clone())
                .unwrap_or_else(|| "—".into());
            let mut switch_to: Option<String> = None;
            let mut add_account = false;
            egui::CollapsingHeader::new(
                egui::RichText::new(self.state.tr(Key::AccountLabelTpl).replace("{}", &active_label)).strong().color(ACCENT),
            )
            .default_open(self.state.accounts.len() > 1)
            .show(ui, |ui| {
                for a in &self.state.accounts {
                    let active = self.state.active_account.as_deref() == Some(a.id.as_str());
                    let mut label = egui::RichText::new(&a.label);
                    label = if active { label.color(ACCENT).strong() } else { label.color(TEXT) };
                    if ui.selectable_label(active, label).clicked() {
                        switch_to = Some(a.id.clone());
                    }
                }
                ui.add_space(2.0);
                if ui.button(self.state.tr(Key::BtnAddAccount)).clicked() {
                    add_account = true;
                }
            });
            if let Some(id) = switch_to {
                if let Some(cmd) = self.state.action_switch_account(id) {
                    self.send(cmd);
                }
            }
            if add_account {
                self.state.action_start_add_account();
            }

            // "My profile" (name + bio + avatar) — self-declared, broadcast to contacts
            // over E2E. Not identity.
            let prof_title = if self.state.my_name.is_empty() {
                self.state.tr(Key::ProfileTitle).to_string()
            } else {
                self.state.tr(Key::ProfileTitleNamedTpl).replace("{}", &self.state.my_name)
            };
            let own_key = self.state.own_ik.unwrap_or([0u8; 32]);
            let my_avatar = self.state.my_avatar.clone();
            egui::CollapsingHeader::new(egui::RichText::new(prof_title).color(MUTED))
                .id_salt("my_profile")
                .show(ui, |ui| {
                    if self.state.editing_profile {
                        ui.horizontal(|ui| {
                            self.avatar_widget(ui, own_key, my_avatar.as_deref(), 44.0);
                            ui.vertical(|ui| {
                                let avatar_hint = self.state.tr(Key::AvatarPathHint);
                                ui.add(
                                    egui::TextEdit::singleline(&mut self.state.in_avatar_path)
                                        .hint_text(avatar_hint)
                                        .desired_width(f32::INFINITY),
                                );
                                ui.horizontal(|ui| {
                                    if ui.button(self.state.tr(Key::BtnSetAvatar)).clicked() {
                                        let p = self.state.in_avatar_path.clone();
                                        if let Some(cmd) = self.state.action_set_avatar(&p) {
                                            self.send(cmd);
                                            self.state.in_avatar_path.clear();
                                        }
                                    }
                                    if my_avatar.is_some() && ui.button(self.state.tr(Key::BtnRemove)).clicked() {
                                        let cmd = self.state.action_remove_avatar();
                                        self.send(cmd);
                                    }
                                });
                            });
                        });
                        ui.add_space(2.0);
                        let name_hint = self.state.tr(Key::ProfileNameHint);
                        ui.add(
                            egui::TextEdit::singleline(&mut self.state.in_profile_name)
                                .hint_text(name_hint)
                                .char_limit(64)
                                .desired_width(f32::INFINITY),
                        );
                        ui.add_space(2.0);
                        let bio_hint = self.state.tr(Key::ProfileBioHint);
                        ui.add(
                            egui::TextEdit::multiline(&mut self.state.in_profile_bio)
                                .hint_text(bio_hint)
                                .desired_rows(2)
                                .desired_width(f32::INFINITY),
                        );
                        ui.add_space(2.0);
                        ui.horizontal(|ui| {
                            if ui.button(self.state.tr(Key::BtnSave)).clicked() {
                                let cmd = self.state.action_save_profile();
                                self.send(cmd);
                            }
                            if ui.button(self.state.tr(Key::BtnCancel)).clicked() {
                                self.state.action_cancel_edit_profile();
                            }
                        });
                    } else {
                        ui.horizontal(|ui| {
                            self.avatar_widget(ui, own_key, my_avatar.as_deref(), 44.0);
                            if self.state.my_bio.is_empty() {
                                ui.label(egui::RichText::new(self.state.tr(Key::ProfileNoDescription)).color(MUTED).small());
                            } else {
                                ui.label(egui::RichText::new(&self.state.my_bio).color(TEXT).small());
                            }
                        });
                        ui.add_space(2.0);
                        if ui.button(self.state.tr(Key::BtnEdit)).clicked() {
                            self.state.action_begin_edit_profile();
                        }
                    }
                });

            ui.separator();
            ui.add_space(4.0);

            // Backup relays (multi-homing): show the configured secondaries with a remove
            // button each, plus a one-line add field. Collapsed by default — it is
            // configuration, not the main flow.
            egui::CollapsingHeader::new(
                egui::RichText::new(self.state.tr(Key::NetExtraRelays)).color(MUTED).small(),
            )
            .id_salt("backup_relays")
            .show(ui, |ui| {
                let mut remove: Option<usize> = None;
                // The health vector is keyed to the POLLED set ([primary, ...valid extras]),
                // which drops any MALFORMED secondary; this list is the RAW saved extras, which
                // keeps them. They line up index-for-index only when nothing was dropped —
                // provably so when `health == extras + 1` (primary + every extra survived). If
                // they diverge we show every dot as "unknown" rather than colour the wrong row.
                let aligned = self.state.relay_health.len() == self.state.extra_relays.len() + 1;
                for (i, (addr, _rid)) in self.state.extra_relays.iter().enumerate() {
                    ui.horizontal(|ui| {
                        if ui.small_button("✕").clicked() {
                            remove = Some(i);
                        }
                        // Reachability dot for this backup: relay_health index 0 is the
                        // primary, so this secondary is at i+1. PAINTED, not a glyph — the
                        // bundled text font has no dingbat coverage (see the connection
                        // indicator, which colours text for the same reason), so a `●` would
                        // ship as tofu. Colour by state; the hover spells it out (unknown
                        // until the first poll fills the vector, or if the lists diverge).
                        let health = if aligned { self.state.relay_health.get(i + 1) } else { None };
                        let (dot, tip) = match health {
                            Some(true) => (GOOD, self.state.tr(Key::RelayReachable)),
                            Some(false) => (BAD, self.state.tr(Key::RelayUnreachable)),
                            None => (MUTED, self.state.tr(Key::RelayUnknown)),
                        };
                        let (rect, resp) =
                            ui.allocate_exact_size(egui::vec2(12.0, 12.0), egui::Sense::hover());
                        ui.painter().circle_filled(rect.center(), 4.0, dot);
                        resp.on_hover_text(tip);
                        ui.label(egui::RichText::new(addr).color(TEXT).small());
                    });
                }
                if let Some(i) = remove {
                    if let Some(cmd) = self.state.action_remove_extra_relay(i) {
                        self.send(cmd);
                    }
                }
                let hint = self.state.tr(Key::NetExtraRelaysHint);
                ui.add(
                    egui::TextEdit::singleline(&mut self.state.in_extra_relays)
                        .hint_text(hint)
                        .desired_width(f32::INFINITY)
                        .margin(egui::Margin::symmetric(8.0, 5.0)),
                );
                if ui.button(self.state.tr(Key::BtnAdd)).clicked() {
                    if let Some(cmd) = self.state.action_add_extra_relay() {
                        self.send(cmd);
                    }
                }
            });

            ui.separator();
            ui.add_space(4.0);

            // Баннер режима пересылки: клик по контакту = «переслать сюда».
            let forwarding = self.state.is_forwarding();
            if forwarding {
                egui::Frame::none()
                    .fill(BUBBLE_THEM)
                    .rounding(egui::Rounding::same(8.0))
                    .inner_margin(egui::Margin::same(8.0))
                    .show(ui, |ui| {
                        ui.label(egui::RichText::new(self.state.tr(Key::ForwardBanner)).color(ACCENT).small());
                        if ui.add(egui::Button::new(egui::RichText::new(self.state.tr(Key::BtnCancel)).color(MUTED).small()).fill(PANEL)).clicked() {
                            self.state.action_cancel_forward();
                        }
                    });
                ui.add_space(4.0);
            }

            // Поиск по переписке (локально; исчезающие исключены). Результаты — над
            // списком контактов, клик открывает чат.
            let search_hint = self.state.tr(Key::SearchHint);
            ui.add(
                egui::TextEdit::singleline(&mut self.state.in_search)
                    .hint_text(search_hint)
                    .desired_width(f32::INFINITY)
                    .margin(egui::Margin::symmetric(8.0, 5.0)),
            );
            let mut search_open: Option<[u8; 32]> = None;
            if self.state.is_searching() {
                let hits = self.state.search_results();
                ui.add_space(2.0);
                ui.label(egui::RichText::new(self.state.tr(Key::SearchFoundTpl).replace("{}", &hits.len().to_string())).color(MUTED).small());
                egui::ScrollArea::vertical().max_height(220.0).id_salt("search_res").show(ui, |ui| {
                    for h in &hits {
                        let name = self
                            .state
                            .contacts
                            .iter()
                            .find(|c| c.ik == h.ik)
                            .map(|c| c.name.clone())
                            .unwrap_or_default();
                        let snippet: String = h.text.chars().take(48).collect();
                        let line = format!("{} · {}  {}", name, fmt_hhmm(h.ts), snippet);
                        if ui
                            .add(egui::Label::new(egui::RichText::new(line).small().color(TEXT)).sense(egui::Sense::click()))
                            .clicked()
                        {
                            search_open = Some(h.ik);
                        }
                    }
                });
                ui.separator();
            }
            if let Some(ik) = search_open {
                self.state.action_select(ik);
                self.state.in_search.clear();
            }
            ui.add_space(4.0);

            ui.label(egui::RichText::new(self.state.tr(Key::ContactsTitle)).strong());
            ui.add_space(4.0);
            let mut select: Option<[u8; 32]> = None;
            let mut delete: Option<[u8; 32]> = None;
            let mut forward_to: Option<[u8; 32]> = None;
            // Snapshot the rows so the loop body can call `avatar_widget` (`&mut self`)
            // without holding an immutable borrow of `self.state.contacts`. The row NAME
            // is the LOCAL label — never the peer's self-declared profile name — so a
            // contact cannot spoof another by re-declaring their name; the avatar bytes
            // are the already-sanitized peer avatar.
            let selected = self.state.selected;
            // (ik, local label, verified, unread, avatar bytes).
            type ContactRow = ([u8; 32], String, bool, usize, Option<Vec<u8>>);
            let rows: Vec<ContactRow> = self
                .state
                .contacts
                .iter()
                .map(|c| {
                    (
                        c.ik,
                        c.name.clone(),
                        c.verified,
                        self.state.unread.get(&c.ik).copied().unwrap_or(0),
                        self.state.peer_avatar(&c.ik).map(|b| b.to_vec()),
                    )
                })
                .collect();
            let del_hover = self.state.tr(Key::DeleteContactHover);
            let ver_hover = self.state.tr(Key::VerifiedHover);
            for (ik, name, verified, unread, avatar) in &rows {
                let sel = selected == Some(*ik);
                ui.horizontal(|ui| {
                    // «×» удаления — слева, компактно (U+00D7, есть в шрифте). В режиме
                    // пересылки прячем, чтобы не удалить вместо выбора цели.
                    if !forwarding
                        && ui.add(egui::Button::new(egui::RichText::new("×").color(MUTED)).frame(false)).on_hover_text(del_hover).clicked()
                    {
                        delete = Some(*ik);
                    }
                    // Avatar (or a fallback tile) — like a normal messenger contact list.
                    self.avatar_widget(ui, *ik, avatar.as_deref(), 22.0);
                    if *verified {
                        // Green "verified" marker (a bullet — present in the font, not tofu).
                        ui.label(egui::RichText::new("•").color(GOOD)).on_hover_text(ver_hover);
                    }
                    let name_rt = egui::RichText::new(name).color(if sel { ACCENT } else { TEXT });
                    if ui.selectable_label(sel, name_rt).clicked() {
                        if forwarding {
                            forward_to = Some(*ik);
                        } else {
                            select = Some(*ik);
                        }
                    }
                    if *unread > 0 {
                        // Бейдж непрочитанных.
                        ui.label(
                            egui::RichText::new(format!(" {unread} "))
                                .color(egui::Color32::WHITE)
                                .background_color(ACCENT)
                                .small(),
                        );
                    }
                });
            }
            if let Some(ik) = select {
                self.state.action_select(ik);
            }
            if let Some(ik) = delete {
                if let Some(cmd) = self.state.action_delete_contact(ik) {
                    self.send(cmd);
                }
            }
            if let Some(ik) = forward_to {
                if let Some(cmd) = self.state.action_forward_to(ik, now_secs()) {
                    self.send(cmd);
                }
            }
            ui.add_space(8.0);
            ui.separator();
            // Add-contact form is collapsed by default so it doesn't permanently
            // occupy the sidebar; expand it when you actually want to add someone.
            egui::CollapsingHeader::new(
                egui::RichText::new(self.state.tr(Key::AddContactTitle)).color(MUTED).small(),
            )
            .id_salt("add_contact")
            .show(ui, |ui| {
                ui.label(egui::RichText::new(self.state.tr(Key::AddContactHint)).color(MUTED).small());
                let cname_hint = self.state.tr(Key::ContactNameHint);
                ui.add(egui::TextEdit::singleline(&mut self.state.in_contact_name).hint_text(cname_hint));
                let cik_hint = self.state.tr(Key::AddressHint);
                ui.add(egui::TextEdit::singleline(&mut self.state.in_contact_ik).hint_text(cik_hint));
                if ui.button(self.state.tr(Key::BtnAdd)).clicked() {
                    self.state.action_add_contact();
                }
            });
        });

        egui::TopBottomPanel::bottom("status").show(ctx, |ui| {
            ui.add_space(2.0);
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new(self.state.tr(Key::HistoryEncrypted)).color(MUTED).small());
                ui.separator();
                ui.label(egui::RichText::new(&self.state.status).color(MUTED).small());
            });
            ui.add_space(2.0);
        });

        // Композитор — ОТДЕЛЬНАЯ нижняя панель (над статусом): всегда внизу, что бы
        // ни было в ленте. Раньше он лежал внутри CentralPanel и «прыгал» вверх на
        // пустом чате (лента схлопывалась). Только когда выбран собеседник.
        let has_chat = self.state.selected.is_some();
        // Заблокированному не пишем: вместо композитора — подсказка разблокировать.
        let chat_blocked = self.state.selected.is_some_and(|ik| self.state.is_blocked(&ik));
        if has_chat && chat_blocked {
            egui::TopBottomPanel::bottom("composer").show(ctx, |ui| {
                ui.add_space(6.0);
                ui.label(
                    egui::RichText::new(self.state.tr(Key::BlockedComposer))
                        .color(MUTED)
                        .small(),
                );
                ui.add_space(6.0);
            });
        }
        if has_chat && !chat_blocked {
            egui::TopBottomPanel::bottom("composer").show(ctx, |ui| {
                ui.add_space(4.0);
                // Баннер ответа / правки (взаимоисключимы) + отмена.
                if let Some(rd) = self.state.replying.clone() {
                    let mut cancel = false;
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new(self.state.tr(Key::ReplyBannerTpl).replace("{}", &rd.preview)).color(MUTED).small());
                        if ui.small_button("✕").on_hover_text(self.state.tr(Key::CancelReplyHover)).clicked() {
                            cancel = true;
                        }
                    });
                    if cancel {
                        self.state.cancel_reply();
                    }
                } else if self.state.is_editing() {
                    let mut cancel = false;
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new(self.state.tr(Key::EditingBanner)).color(WARN).small());
                        if ui.small_button("✕").on_hover_text(self.state.tr(Key::CancelEditHover)).clicked() {
                            cancel = true;
                        }
                    });
                    if cancel {
                        self.state.cancel_edit();
                    }
                }
                ui.horizontal(|ui| {
                    let compose_hint = self.state.tr(Key::ComposeHint);
                    let resp = ui.add(
                        egui::TextEdit::singleline(&mut self.state.in_compose)
                            .hint_text(compose_hint)
                            // Width floor: on a very narrow window don't let the field
                            // collapse into an unreadable sliver (available - button
                            // could otherwise go negative).
                            .desired_width((ui.available_width() - 110.0).max(80.0)),
                    );
                    let enter = resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                    let ttl = self.state.in_expire_ttl;
                    let label = if self.state.is_editing() {
                        self.state.tr(Key::BtnSave)
                    } else if ttl > 0 {
                        self.state.tr(Key::BtnSendTimed)
                    } else {
                        self.state.tr(Key::BtnSend)
                    };
                    let send = egui::Button::new(egui::RichText::new(label).color(egui::Color32::WHITE))
                        .fill(if ttl > 0 { WARN } else { ACCENT });
                    if ui.add(send).clicked() || enter {
                        // Таймер → исчезающее (never-persist). Но ОТВЕТ persistent по
                        // смыслу (цитата должна пережить), поэтому при активном ответе
                        // таймер игнорируется — обычная отправка.
                        let cmd = if ttl > 0 && self.state.replying.is_none() && !self.state.is_editing() {
                            self.state.action_send_expiring(now_secs(), ttl)
                        } else {
                            self.state.action_send(now_secs())
                        };
                        if let Some(cmd) = cmd {
                            self.send(cmd);
                        }
                        // Вернуть фокус в поле — можно печатать следующее без клика.
                        resp.request_focus();
                    }
                });
                // Disappearing-message timer, tucked behind a collapsed header so the
                // presets don't permanently eat composer height. The header keeps the
                // CURRENT choice visible (so an armed timer isn't hidden), and its tint
                // turns to WARN when armed. Honest: storage control only holds on
                // cooperating clients — you cannot force deletion on the recipient.
                let cur = self.state.in_expire_ttl;
                let cur_key = match cur {
                    30 => Key::Expire30s,
                    300 => Key::Expire5m,
                    3600 => Key::Expire1h,
                    _ => Key::ExpireOff,
                };
                let head = format!(
                    "{} {}",
                    self.state.tr(Key::ExpiresLabel),
                    self.state.tr(cur_key)
                );
                let head_color = if cur > 0 { WARN } else { MUTED };
                egui::CollapsingHeader::new(egui::RichText::new(head).color(head_color).small())
                    .id_salt("disappearing")
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            for (secs, key) in [(0u32, Key::ExpireOff), (30, Key::Expire30s), (300, Key::Expire5m), (3600, Key::Expire1h)] {
                                if ui.selectable_label(cur == secs, egui::RichText::new(self.state.tr(key)).small()).clicked() {
                                    self.state.in_expire_ttl = secs;
                                }
                            }
                        });
                        if self.state.in_expire_ttl > 0 {
                            ui.label(
                                egui::RichText::new(self.state.tr(Key::ExpiringNote))
                                    .color(MUTED)
                                    .small(),
                            );
                        }
                    });
                // Счётчик длины — появляется только у длинного сообщения (лимит —
                // один Ratchet-пакет; байтовая длина, чтобы кириллица считалась честно).
                let n = self.state.in_compose.len();
                let max = client::content::MAX_TEXT_BYTES;
                if n > max * 3 / 4 {
                    let color = if n > max { BAD } else { MUTED };
                    let counter = self
                        .state
                        .tr(Key::CharCountTpl)
                        .replace("{n}", &n.to_string())
                        .replace("{max}", &max.to_string());
                    ui.label(egui::RichText::new(counter).color(color).small());
                }
                ui.horizontal(|ui| {
                    // Native picker (zenity/kdialog); fills the field below. The field
                    // stays as a fallback for a box without a picker helper.
                    if ui.button(self.state.tr(Key::BtnAttach)).clicked() {
                        if let Some(path) = pick_file() {
                            self.state.in_file_path = path;
                        }
                    }
                    let file_hint = self.state.tr(Key::FilePathHint);
                    ui.add(
                        egui::TextEdit::singleline(&mut self.state.in_file_path)
                            .hint_text(file_hint)
                            .desired_width((ui.available_width() - 200.0).max(80.0)),
                    );
                    if ui.button(self.state.tr(Key::BtnSendFile)).clicked() {
                        if let Some(cmd) = self.state.action_send_file(now_secs()) {
                            self.send(cmd);
                        }
                    }
                });
                ui.add_space(4.0);
            });
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            if !has_chat {
                ui.vertical_centered(|ui| {
                    ui.add_space(80.0);
                    ui.label(egui::RichText::new(self.state.tr(Key::SelectContact)).color(MUTED));
                });
                return;
            }
            // Chat header: avatar + the LOCAL label (trust anchor) + the self-declared
            // name/bio from the received profile as a HINT (not a replacement).
            if let Some(ik) = self.state.selected {
                let label = self.state.selected_contact().map(|c| c.name.clone()).unwrap_or_default();
                let declared = self.state.peer_declared_name(&ik).map(|s| s.to_string());
                let bio = self.state.peer_bio(&ik).map(|s| s.to_string());
                let avatar = self.state.peer_avatar(&ik).map(|b| b.to_vec());
                ui.horizontal(|ui| {
                    self.avatar_widget(ui, ik, avatar.as_deref(), 36.0);
                    ui.vertical(|ui| {
                        ui.horizontal(|ui| {
                            ui.label(egui::RichText::new(&label).strong().color(TEXT));
                            if let Some(d) = &declared {
                                if d != &label {
                                    ui.label(egui::RichText::new(self.state.tr(Key::ProfileHintTpl).replace("{}", d)).color(MUTED).small());
                                }
                            }
                        });
                        if let Some(b) = &bio {
                            ui.label(egui::RichText::new(b).color(MUTED).small());
                        }
                    });
                });
                ui.add_space(2.0);
            }
            if let Some(sn) = self.state.safety_number() {
                let verified = self.state.selected_contact().map(|c| c.verified).unwrap_or(false);
                let header = if verified {
                    egui::RichText::new(self.state.tr(Key::SafetyVerified)).color(GOOD)
                } else {
                    egui::RichText::new(self.state.tr(Key::SafetyUnverified)).color(MUTED)
                };
                let mut verify = false;
                ui.collapsing(header, |ui| {
                    ui.monospace(&sn);
                    ui.label(egui::RichText::new(self.state.tr(Key::SafetyExplain)).color(MUTED).small());
                    if !verified && ui.button(self.state.tr(Key::BtnMarkVerified)).clicked() {
                        verify = true;
                    }
                });
                if verify {
                    self.state.action_verify_selected();
                }
            }
            // «Очистить переписку» — стереть сообщения этого чата (и на диске),
            // контакт остаётся. Справа, ненавязчиво.
            if let Some(ik) = self.state.selected {
                let blocked = self.state.is_blocked(&ik);
                // Destructive per-chat actions live behind a "•••" overflow menu (like
                // mainstream messengers) instead of two always-visible text links that
                // invite a mis-click. Hoist labels to locals (each is `&'static str`)
                // and defer the mutations so the nested menu closure doesn't borrow
                // `self` while the layout closure holds it.
                let mut toggle_block = false;
                let mut clear_chat = false;
                let (blabel, bcolor) = if blocked {
                    (self.state.tr(Key::BtnUnblock), BAD)
                } else {
                    (self.state.tr(Key::BtnBlock), MUTED)
                };
                let clear_label = self.state.tr(Key::BtnClearChat);
                let menu_hover = self.state.tr(Key::ChatMenuHover);
                let share_label = self.state.tr(Key::BtnShareRoutes);
                let share_hover = self.state.tr(Key::ShareRoutesHover);
                let accept_label = self.state.tr(Key::BtnAcceptRoutes);
                // Per-contact decisions: sharing is only ever this explicit menu click.
                let mut share_routes = false;
                let mut accept_routes = false;
                let has_offer = self.state.pending_routes.contains_key(&ik);
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Min), |ui| {
                    ui.menu_button("•••", |ui| {
                        if ui
                            .add(egui::Button::new(egui::RichText::new(share_label).color(MUTED)).frame(false))
                            .on_hover_text(share_hover)
                            .clicked()
                        {
                            share_routes = true;
                            ui.close_menu();
                        }
                        if has_offer
                            && ui
                                .add(egui::Button::new(egui::RichText::new(accept_label).color(GOOD)).frame(false))
                                .clicked()
                        {
                            accept_routes = true;
                            ui.close_menu();
                        }
                        if ui
                            .add(egui::Button::new(egui::RichText::new(blabel).color(bcolor)).frame(false))
                            .clicked()
                        {
                            toggle_block = true;
                            ui.close_menu();
                        }
                        if ui
                            .add(egui::Button::new(egui::RichText::new(clear_label).color(MUTED)).frame(false))
                            .clicked()
                        {
                            clear_chat = true;
                            ui.close_menu();
                        }
                    })
                    .response
                    .on_hover_text(menu_hover);
                });
                if share_routes {
                    if let Some(cmd) = self.state.action_share_routes(ik) {
                        self.send(cmd);
                    }
                }
                if accept_routes {
                    if let Some(cmd) = self.state.action_accept_routes(ik) {
                        self.send(cmd);
                    }
                }
                if toggle_block {
                    let cmd = self.state.action_toggle_block(ik);
                    self.send(cmd);
                }
                if clear_chat {
                    if let Some(cmd) = self.state.action_clear_chat(ik) {
                        self.send(cmd);
                    }
                }
            }
            ui.separator();

            // Лента сообщений — пузырями. Заполняет ВСЮ оставшуюся высоту
            // (`auto_shrink=false`), композитор — отдельная нижняя панель.
            let lang = self.state.lang;
            let mut begin_forward: Option<String> = None;
            let mut delete: Option<(u64, bool, String)> = None;
            let mut delete_all: Option<(u64, String)> = None;
            let mut react: Option<(bool, u64, String, String)> = None; // (from_me, ts, text, emoji)
            let mut begin_reply: Option<(bool, u64, String)> = None; // (from_me, ts, text)
            let mut begin_edit: Option<(bool, u64, String)> = None; // (from_me, ts, text)
            let mut cancel_transfer: Option<u64> = None; // id of an in-flight transfer
            let mut save_as: Option<String> = None; // vault id of a sealed file to export
            egui::ScrollArea::vertical()
                .stick_to_bottom(true)
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    for m in self.state.selected_messages() {
                        let reactions = self.state.reactions_of(m);
                        let reply_preview = self.state.reply_preview_of(m);
                        let edited = self.state.edited_of(m);
                        match bubble(ui, m, &reactions, reply_preview.as_deref(), edited.as_deref(), lang) {
                            Some(BubbleAct::Forward) => begin_forward = Some(m.text.clone()),
                            Some(BubbleAct::Delete) => delete = Some((m.ts, m.from_me, m.text.clone())),
                            Some(BubbleAct::DeleteEveryone) => delete_all = Some((m.ts, m.text.clone())),
                            Some(BubbleAct::React(emoji)) => {
                                react = Some((m.from_me, m.ts, m.text.clone(), emoji))
                            }
                            Some(BubbleAct::Reply) => {
                                begin_reply = Some((m.from_me, m.ts, m.text.clone()))
                            }
                            Some(BubbleAct::Edit) => {
                                begin_edit = Some((m.from_me, m.ts, m.text.clone()))
                            }
                            Some(BubbleAct::Cancel(id)) => cancel_transfer = Some(id),
                            Some(BubbleAct::SaveAs(fid)) => save_as = Some(fid),
                            None => {}
                        }
                    }
                });
            if let Some((from_me, ts, text)) = begin_reply {
                self.state.action_begin_reply(from_me, ts, &text);
            }
            if let Some((from_me, ts, text)) = begin_edit {
                self.state.action_begin_edit(from_me, ts, &text);
            }
            if let Some(text) = begin_forward {
                self.state.action_begin_forward(text);
            }
            if let (Some(ik), Some((ts, from_me, text))) = (self.state.selected, delete) {
                if let Some(cmd) = self.state.action_delete_message(ik, ts, from_me, text) {
                    self.send(cmd);
                }
            }
            if let (Some(ik), Some((ts, text))) = (self.state.selected, delete_all) {
                if let Some(cmd) = self.state.action_delete_message_everyone(ik, ts, text) {
                    self.send(cmd);
                }
            }
            if let Some((from_me, ts, text, emoji)) = react {
                if let Some(cmd) = self.state.action_react(from_me, ts, &text, &emoji) {
                    self.send(cmd);
                }
            }
            if let Some(id) = cancel_transfer {
                self.send(gui::controller::Cmd::CancelTransfer { id });
            }
            if let Some(fid) = save_as {
                if let Some(dest) = pick_save_path() {
                    if let Some(cmd) = self.state.action_export_file(fid, dest) {
                        self.send(cmd);
                    }
                }
            }
        });
    }
}

/// Текущее unix-время в секундах (для таймеров исчезновения — стамп отправки и
/// подметание). Совпадает с часами worker'а (`wall_clock`).
fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Open the desktop's native file-open dialog (`zenity`, then `kdialog`) and return
/// the chosen path. Best-effort and non-fatal: on a box without either helper it
/// returns `None` and the user can still type the path into the field by hand — the
/// picker is a convenience layered over the honest text field, never a hard
/// dependency. Runs the helper synchronously (the dialog is modal regardless).
/// Native SAVE dialog — where a sealed file should be decrypted to. Mirrors
/// `pick_file`; a cancel returns `None` and nothing is written.
fn pick_save_path() -> Option<String> {
    for (bin, args) in [
        ("zenity", &["--file-selection", "--save", "--confirm-overwrite", "--title=KARST: save decrypted file as"][..]),
        ("kdialog", &["--getsavefilename", "."][..]),
    ] {
        match std::process::Command::new(bin).args(args).output() {
            Ok(out) if out.status.success() => {
                let p = String::from_utf8_lossy(&out.stdout).trim().to_string();
                return (!p.is_empty()).then_some(p);
            }
            Ok(_) => return None, // the user cancelled — respect it
            Err(_) => continue,   // helper missing — try the next
        }
    }
    None
}

fn pick_file() -> Option<String> {
    for (bin, args) in [
        ("zenity", &["--file-selection", "--title=KARST: choose a file"][..]),
        ("kdialog", &["--getopenfilename", "."][..]),
    ] {
        match std::process::Command::new(bin).args(args).output() {
            // Helper ran and the user picked something.
            Ok(out) if out.status.success() => {
                let p = String::from_utf8_lossy(&out.stdout).trim().to_string();
                return (!p.is_empty()).then_some(p);
            }
            // Helper ran but the user cancelled — respect that, don't try the next one.
            Ok(_) => return None,
            // Helper not installed — fall through to the next candidate.
            Err(_) => continue,
        }
    }
    None
}

/// Смещение локальной таймзоны в секундах, прочитанное ОДИН раз (`date +%z` →
/// напр. «+0300»). Без крейта времени: цель — линукс-десктоп, DST в пределах
/// сессии не отслеживаем. Не распарсилось → UTC (0).
fn local_offset_secs() -> i64 {
    use std::sync::OnceLock;
    static OFF: OnceLock<i64> = OnceLock::new();
    *OFF.get_or_init(|| {
        std::process::Command::new("date")
            .arg("+%z")
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .and_then(|s| {
                let s = s.trim();
                if s.len() < 5 {
                    return None;
                }
                let sign: i64 = if s.starts_with('-') { -1 } else { 1 };
                let h: i64 = s.get(1..3)?.parse().ok()?;
                let m: i64 = s.get(3..5)?.parse().ok()?;
                Some(sign * (h * 3600 + m * 60))
            })
            .unwrap_or(0)
    })
}

/// Локальное `ЧЧ:ММ` из unix-секунд. `0` (не отслеживается) → пусто.
fn fmt_hhmm(ts: u64) -> String {
    if ts == 0 {
        return String::new();
    }
    let local = ts as i64 + local_offset_secs();
    let day = local.rem_euclid(86400);
    format!("{:02}:{:02}", day / 3600, (day % 3600) / 60)
}

/// Верхняя граница длины ОДНОГО отображаемого сообщения (анти-DoS раскладки:
/// враждебный отправитель мог бы прислать мегабайт без пробелов и раздуть пузырь).
const MAX_BUBBLE_CHARS: usize = 4096;

/// Нарисовать один «пузырь» сообщения: свои — справа акцентом, чужие — слева серым.
/// ВЕРТИКАЛЬНАЯ раскладка (`top_down`) с горизонтальным выравниванием: иначе
/// горизонтальный layout с `Align::Center` растягивал пузырь на всю высоту ленты
/// (был баг «сообщение в огромном блоке»). `wrap` + `set_max_width` переносят
/// длинный текст, `MAX_BUBBLE_CHARS` обрезает абсурдно длинный (враждебный ввод).
/// У своих внизу — статус доставки (⏳/✓/✕).
/// Действие, запрошенное через контекст-меню пузыря.
enum BubbleAct {
    Forward,
    Delete,
    DeleteEveryone,
    /// Поставить/снять реакцию этим эмодзи (тоггл делает контроллер).
    React(String),
    /// Начать ответ на это сообщение.
    Reply,
    /// Начать правку этого (своего) сообщения.
    Edit,
    /// Cancel an in-flight large-file transfer (the ✕ on the bar). Carries the bubble's `id`.
    Cancel(u64),
    /// Export a received (sealed) file to a path the user picks. Carries its vault id.
    SaveAs(String),
}

/// Рисует пузырь; возвращает запрошенное контекст-меню действие (или `None`).
/// Копирование обрабатывается на месте (клипборд), наружу не выходит.
fn bubble(
    ui: &mut egui::Ui,
    m: &gui::controller::ChatMsg,
    reactions: &[(String, usize, bool)],
    reply_preview: Option<&str>,
    edited: Option<&str>,
    lang: gui::i18n::Lang,
) -> Option<BubbleAct> {
    use gui::controller::{MsgKind, MsgStatus};
    use gui::i18n::{t, Key};
    let mut act: Option<BubbleAct> = None;
    // Реакции/пересылка/копирование — только у ТЕКСТА. У файла `text` — витринная
    // строка, а не адресуемое содержимое; вдобавок у файлов нет сквозного ts
    // (получатель штампует прибытие), поэтому кросс-девайс msg_id не сошёлся бы и
    // реакция была бы видна только у реагирующего — честнее не предлагать вовсе.
    let is_text = matches!(m.kind, MsgKind::Text);
    let (fill, align) = if m.from_me {
        (BUBBLE_ME, egui::Align::Max) // справа
    } else {
        (BUBBLE_THEM, egui::Align::Min) // слева
    };
    let max_w = (ui.available_width() * 0.72).max(120.0);
    // Правка — overlay: показываем изменённый текст вместо текста истории.
    let body = edited.unwrap_or(&m.text);
    let shown: String = if body.chars().count() > MAX_BUBBLE_CHARS {
        body.chars().take(MAX_BUBBLE_CHARS).collect::<String>() + "…"
    } else {
        body.to_string()
    };
    ui.with_layout(egui::Layout::top_down(align), |ui| {
        let inner = egui::Frame::none()
            .fill(fill)
            .rounding(egui::Rounding::same(10.0))
            .inner_margin(egui::Margin::symmetric(10.0, 6.0))
            .show(ui, |ui| {
                ui.set_max_width(max_w);
                // Цитата: над текстом ответа — короткая строка цели, приглушённо.
                if let Some(q) = reply_preview {
                    ui.label(egui::RichText::new(format!("↩ {q}")).color(MUTED).small());
                }
                ui.add(
                    egui::Label::new(egui::RichText::new(shown).color(TEXT))
                        .wrap_mode(egui::TextWrapMode::Wrap),
                );
                if edited.is_some() {
                    ui.label(egui::RichText::new(t(lang, Key::EditedMark)).color(MUTED).small());
                }
                // Large-file progress (off-loop blob): a done/total bar + ✕ cancel,
                // only while the transfer runs. The terminal event clears `progress`,
                // so the bar disappears.
                if let Some((done, total)) = m.progress {
                    let frac = if total > 0 { (done as f32 / total as f32).clamp(0.0, 1.0) } else { 0.0 };
                    ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
                        ui.add(
                            egui::ProgressBar::new(frac)
                                .desired_width(max_w - 40.0)
                                .text(format!("{}%", (frac * 100.0) as u32)),
                        );
                        if ui.small_button("✕").on_hover_text(t(lang, Key::Cancelling)).clicked() {
                            act = Some(BubbleAct::Cancel(m.id));
                        }
                    });
                }
                // Футер пузыря (мелким, справа): время ЧЧ:ММ + статус доставки
                // (только у своих, лишь когда НЕ доставлено) ИЛИ таймер исчезновения.
                // Текст, не глиф-дингбат (✓/✕ рисуются «тофу»).
                let time = fmt_hhmm(m.ts);
                let status_note = if m.from_me {
                    match m.status {
                        MsgStatus::Sending => Some((t(lang, Key::StatusSending), MUTED)),
                        MsgStatus::Sent => None,
                        MsgStatus::Failed => Some((t(lang, Key::StatusFailed), BAD)),
                    }
                } else {
                    None
                };
                let expiry = m.expire_at.map(|exp| {
                    let left = exp.saturating_sub(now_secs());
                    // Round UP: the "5 min" preset must not show "6 min".
                    if left >= 60 {
                        t(lang, Key::ExpiryMinTpl).replace("{}", &left.div_ceil(60).to_string())
                    } else {
                        t(lang, Key::ExpirySecTpl).replace("{}", &left.to_string())
                    }
                });
                if !time.is_empty() || status_note.is_some() || expiry.is_some() {
                    // right_to_left: первый добавленный — крайний справа.
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Min), |ui| {
                        if !time.is_empty() {
                            ui.label(egui::RichText::new(&time).color(MUTED).small());
                        }
                        if let Some((label, color)) = status_note {
                            ui.label(egui::RichText::new(label).color(color).small());
                        }
                        if let Some(e) = &expiry {
                            ui.label(egui::RichText::new(e).color(WARN).small());
                        }
                    });
                }
            });
        // Чипы реакций под пузырём: «эмодзи N», моя — подсвечена; клик по чипу
        // снимает/ставит (тоггл). Только у текста и когда реакции есть.
        if is_text && !reactions.is_empty() {
            ui.horizontal_wrapped(|ui| {
                for (emoji, count, mine) in reactions {
                    let mut chip = egui::Button::new(
                        egui::RichText::new(format!("{emoji} {count}")).small().color(TEXT),
                    )
                    .rounding(egui::Rounding::same(8.0))
                    .small();
                    if *mine {
                        chip = chip.fill(BUBBLE_ME); // моя реакция выделена
                    }
                    if ui.add(chip).on_hover_text(t(lang, Key::ToggleReactionHover)).clicked() {
                        act = Some(BubbleAct::React(emoji.clone()));
                    }
                }
            });
        }
        // Контекст-меню (правый клик). «Удалить» — у любого сообщения; «Переслать»/
        // «Копировать»/реакции — только у текста (файл: витринная строка, не байты).
        inner.response.on_hover_text(t(lang, Key::RightClickHover)).context_menu(|ui| {
            if is_text {
                if ui.button(t(lang, Key::BtnReply)).clicked() {
                    act = Some(BubbleAct::Reply);
                    ui.close_menu();
                }
                // Only your OWN addressable message can be edited (cooperatively).
                if m.from_me && m.ts != 0 && ui.button(t(lang, Key::BtnEdit)).clicked() {
                    act = Some(BubbleAct::Edit);
                    ui.close_menu();
                }
                if ui.button(t(lang, Key::BtnForward)).clicked() {
                    act = Some(BubbleAct::Forward);
                    ui.close_menu();
                }
                if ui.button(t(lang, Key::BtnCopy)).clicked() {
                    ui.output_mut(|o| o.copied_text = m.text.clone());
                    ui.close_menu();
                }
            }
            // A RECEIVED file is sealed in the vault; this is the only way it becomes
            // plaintext — and only where the user points it.
            if let MsgKind::File { file_id: Some(fid), .. } = &m.kind {
                if ui.button(t(lang, Key::BtnSaveAs)).clicked() {
                    act = Some(BubbleAct::SaveAs(fid.clone()));
                    ui.close_menu();
                }
            }
            if ui.button(t(lang, Key::BtnDeleteForMe)).clicked() {
                act = Some(BubbleAct::Delete);
                ui.close_menu();
            }
            // "For everyone" — only for your own sent messages (real ts). Honestly: a
            // recipient on an uncooperative client may not erase it.
            if m.from_me && m.ts != 0 && ui.button(t(lang, Key::BtnDeleteForAll)).on_hover_text(t(lang, Key::CannotForceHover)).clicked() {
                act = Some(BubbleAct::DeleteEveryone);
                ui.close_menu();
            }
            // Реакции — только у текста с адресуемым (сквозным) ts. Пресеты.
            if is_text && m.ts != 0 {
                ui.separator();
                ui.horizontal(|ui| {
                    for e in ["👍", "❤", "😂", "😮", "😢", "🙏"] {
                        if ui.button(e).clicked() {
                            act = Some(BubbleAct::React(e.to_string()));
                            ui.close_menu();
                        }
                    }
                });
            }
        });
    });
    act
}

impl eframe::App for KarstApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if !self.themed {
            Self::apply_theme(ctx);
            Self::setup_fonts(ctx);
            self.themed = true;
        }
        self.drain_events();

        // Подмести исчезающие сообщения, чей срок наступил (repaint ≤500 мс → истечение
        // не позже чем на полсекунды). Стирает только из памяти — на диск они не писались.
        self.state.sweep_expired(now_secs());

        // Заголовок окна со счётчиком непрочитанных (только на смене — не каждый кадр).
        let unread = self.state.total_unread();
        let title = if unread > 0 { format!("KARST ({unread})") } else { "KARST".to_string() };
        if title != self.last_title {
            ctx.send_viewport_cmd(egui::ViewportCommand::Title(title.clone()));
            self.last_title = title;
        }

        match self.state.screen {
            Screen::Welcome => self.welcome_ui(ctx),
            Screen::Unlock => self.unlock_ui(ctx),
            Screen::CreateShow => self.create_show_ui(ctx),
            Screen::CreateConfirm => self.create_confirm_ui(ctx),
            Screen::Restore => self.restore_ui(ctx),
            Screen::Ready => self.ready_ui(ctx),
        }

        // Персист контактов, если менялись (имя/сверка/добавление/удаление). Флаг
        // сбрасываем сразу — worker пишет атомарно, повторов не будет. `id` штампуем
        // ТЕКУЩИМ активным аккаунтом: если в этом же кадре кликнули переключение,
        // Evt::Accounts(B) ещё не слит из очереди, active_account = A — и контакты A
        // уедут в файл A, а не в B (worker сохраняет по id, а не по live-сессии).
        if self.state.contacts_dirty {
            if let Some(id) = self.state.active_account.clone() {
                self.send(Cmd::SaveContacts { id, contacts: self.state.contacts.clone() });
            }
            self.state.contacts_dirty = false;
        }

        // Перерисовка, чтобы вливать входящие от worker (он сам опрашивает relay).
        ctx.request_repaint_after(Duration::from_millis(500));
    }
}
