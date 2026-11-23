use gpui_kit::{
    component::{
        Disableable, Icon, IconName, Sizable, Theme, ThemeMode,
        button::{Button, ButtonVariants},
        input::{Input, InputEvent, InputState},
        label::Label,
        spinner::Spinner,
    },
    prelude::FluentBuilder,
    *,
};

use crate::engine::{Command, Engine, Event, Imports, Resume, Source, log_path};

const PINE: u32 = 0x204030;
const DEEP: u32 = 0x193527;
const PAPER: u32 = 0xfdfcf9;
const RAISED: u32 = 0xf6f4ee;
const RULE: u32 = 0xe4e0d4;
const INK: u32 = 0x1d2019;
const MUTED: u32 = 0x606754;
const PALE: u32 = 0xedf2ea;
const SAGE: u32 = 0xb2c3b5;
const ERROR: u32 = 0x8e2f26;

fn configure_theme(cx: &mut App) {
    init(cx);
    let font = include_bytes!("../assets/HankenGrotesk-Variable.ttf");
    let loaded = cx
        .text_system()
        .add_fonts(vec![std::borrow::Cow::Borrowed(font)])
        .is_ok();
    Theme::change(ThemeMode::Light, None, cx);
    Theme::update(cx, |theme| {
        if loaded {
            theme.font_family = "Hanken Grotesk".into();
        }
        let colors = &mut theme.colors;
        colors.background = rgb(PAPER).into();
        colors.foreground = rgb(INK).into();
        colors.primary = rgb(PINE).into();
        colors.button_primary = rgb(PINE).into();
        colors.button_primary_hover = rgb(0x2c5340).into();
        colors.button_primary_active = rgb(0x12281e).into();
        colors.button_primary_foreground = rgb(0xffffff).into();
        colors.ring = rgb(0x5a8a6d).into();
        colors.border = rgb(RULE).into();
        colors.input = rgb(0xd5d0c0).into();
        colors.muted_foreground = rgb(MUTED).into();
    });
}

pub fn open() {
    application().with_assets(assets::Assets).run(|cx| {
        configure_theme(cx);
        let options = WindowOptions {
            titlebar: Some(TitlebarOptions {
                title: Some("Thelemail Migrator".into()),
                ..Default::default()
            }),
            window_bounds: Some(WindowBounds::Windowed(Bounds::centered(
                None,
                size(px(850.), px(600.)),
                cx,
            ))),
            window_min_size: Some(size(px(430.), px(440.))),
            ..Default::default()
        };
        if let Err(error) = open_window(options, cx, |window, cx| {
            let view = cx.new(|cx| Migrator::new(window, cx));
            let weak = view.downgrade();
            window.on_window_should_close(cx, move |_, cx| {
                weak.update(cx, |view, cx| {
                    if view.page == Page::Transfer && view.busy {
                        view.stop(cx);
                        return false;
                    }
                    true
                })
                .unwrap_or(true)
            });
            view
        }) {
            eprintln!("Could not open Thelemail Migrator: {error}");
            cx.quit();
        }
        cx.on_window_closed(|cx, _| {
            if cx.windows().is_empty() {
                cx.quit();
            }
        })
        .detach();
        cx.activate(true);
    });
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Page {
    SignIn,
    Factor,
    Choose,
    Setup,
    Review,
    Transfer,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Imap,
    Files,
    Export,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Factor {
    Passkey,
    Totp,
    Recovery,
}

impl Factor {
    fn parse(method: &str) -> Option<Self> {
        match method {
            "webauthn" => Some(Self::Passkey),
            "totp" => Some(Self::Totp),
            "backupCode" => Some(Self::Recovery),
            _ => None,
        }
    }
    fn wire(self) -> &'static str {
        match self {
            Self::Passkey => "webauthn",
            Self::Totp => "totp",
            Self::Recovery => "backupCode",
        }
    }
    fn label(self) -> &'static str {
        match self {
            Self::Passkey => "Use a passkey or security key",
            Self::Totp => "Use an authenticator code",
            Self::Recovery => "Use a recovery code",
        }
    }
}

struct Migrator {
    page: Page,
    mode: Mode,
    account: String,
    email: Entity<InputState>,
    password: Entity<InputState>,
    code: Entity<InputState>,
    factors: Vec<Factor>,
    factor: Option<Factor>,
    passkey_code: Option<String>,
    server: Entity<InputState>,
    username: Entity<InputState>,
    source_password: Entity<InputState>,
    files: Entity<InputState>,
    directory: Entity<InputState>,
    engine: Option<Engine>,
    generation: u64,
    scroll: ScrollHandle,
    busy: bool,
    stopping: bool,
    stopped: bool,
    status: String,
    problem: Option<String>,
    detail: Option<String>,
    show_detail: bool,
    imports: Imports,
    resume: Option<Resume>,
    checking_keys: bool,
}

impl Migrator {
    fn new(window: &mut Window, cx: &mut Context<Self>) -> Self {
        let mut input = |placeholder: &'static str, value: &'static str, secret: bool| {
            cx.new(|cx| {
                InputState::new(window, cx)
                    .placeholder(placeholder)
                    .default_value(value)
                    .masked(secret)
            })
        };
        let view = Self {
            page: Page::SignIn,
            mode: Mode::Imap,
            account: String::new(),
            email: input("you@example.com", "", false),
            password: input("Your Thelemail password", "", true),
            code: input("Enter your code", "", true),
            server: input("IMAP server", "imap.hostinger.com", false),
            username: input("you@example.com", "", false),
            source_password: input("Mailbox or app password", "", true),
            files: input("Path to your mail archive", "", false),
            directory: input("Path to a private folder", "", false),
            factors: vec![],
            factor: None,
            passkey_code: None,
            engine: None,
            generation: 0,
            scroll: ScrollHandle::new(),
            busy: false,
            stopping: false,
            stopped: false,
            status: String::new(),
            problem: None,
            detail: None,
            show_detail: false,
            imports: Imports::default(),
            resume: None,
            checking_keys: false,
        };
        for field in [&view.password, &view.code] {
            cx.subscribe_in(field, window, |view, _, event: &InputEvent, window, cx| {
                if matches!(event, InputEvent::PressEnter { .. }) {
                    view.authenticate(window, cx);
                }
            })
            .detach();
        }
        view
    }

    fn show(&mut self, page: Page, cx: &mut Context<Self>) {
        self.page = page;
        self.scroll.set_offset(Point::default());
        self.clear_problem();
        cx.notify();
    }

    fn clear_problem(&mut self) {
        self.problem = None;
        self.detail = None;
        self.show_detail = false;
    }

    fn report(&mut self, message: String, detail: Option<String>) {
        self.problem = Some(message);
        self.detail = detail.filter(|d| !d.trim().is_empty());
        self.show_detail = false;
    }

    fn reset_session(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.generation += 1;
        self.engine = None;
        self.busy = false;
        self.account.clear();
        self.factor = None;
        self.passkey_code = None;
        self.factors.clear();
        self.imports = Imports::default();
        self.resume = None;
        self.checking_keys = false;
        for field in [
            &self.password,
            &self.code,
            &self.source_password,
            &self.username,
            &self.files,
            &self.directory,
        ] {
            field.update(cx, |input, cx| input.set_value("", window, cx));
        }
        self.mode = Mode::Imap;
        self.status.clear();
        self.show(Page::SignIn, cx);
    }

    fn connect(&mut self, window: &mut Window, cx: &mut Context<Self>) -> Result<(), String> {
        if self.engine.is_some() {
            return Ok(());
        }
        let (engine, events) = Engine::open()?;
        self.engine = Some(engine);
        let generation = self.generation;
        cx.spawn_in(window, async move |this, cx| {
            while let Ok(event) = events.recv().await {
                let active = this
                    .update_in(cx, |view, window, cx| {
                        if view.generation != generation {
                            return false;
                        }
                        view.receive(event, window, cx);
                        true
                    })
                    .unwrap_or(false);
                if !active {
                    break;
                }
            }
        })
        .detach();
        Ok(())
    }

    fn send(&mut self, command: Command) -> Result<(), String> {
        self.engine
            .as_ref()
            .ok_or("Sign in again to continue.")?
            .send(command)
    }

    fn authenticate(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.busy {
            return;
        }
        let command = match self.page {
            Page::SignIn => {
                let email = self.email.read(cx).value().trim().to_owned();
                let password = self.password.read(cx).value().to_string();
                if email.is_empty() || password.is_empty() {
                    self.report("Enter your Thelemail address and password.".into(), None);
                    cx.notify();
                    return;
                }
                Command::Login { email, password }
            }
            Page::Factor => {
                let Some(factor) = self.factor else {
                    return;
                };
                let code = self.code.read(cx).value().trim().to_owned();
                if code.is_empty() && factor != Factor::Passkey {
                    self.report("Enter your verification code.".into(), None);
                    cx.notify();
                    return;
                }
                Command::Factor {
                    method: factor.wire().into(),
                    code,
                }
            }
            _ => return,
        };
        match self.connect(window, cx).and_then(|()| self.send(command)) {
            Ok(()) => {
                self.busy = true;
                self.clear_problem();
                for field in [&self.password, &self.code] {
                    field.update(cx, |input, cx| input.set_value("", window, cx));
                }
            }
            Err(error) => self.report(error, None),
        }
        cx.notify();
    }

    fn receive(&mut self, event: Event, window: &mut Window, cx: &mut Context<Self>) {
        match event {
            Event::Challenge { methods, message } => {
                self.busy = false;
                self.passkey_code = None;
                self.factors = methods.iter().filter_map(|m| Factor::parse(m)).collect();
                self.factor = self
                    .factor
                    .filter(|factor| self.factors.contains(factor))
                    .or_else(|| self.factors.first().copied());
                if self.factor.is_some() {
                    self.show(Page::Factor, cx);
                    if let Some(message) = message {
                        self.report(message, None);
                    }
                } else {
                    self.reset_session(window, cx);
                    self.report(
                        "This account requires a verification method this version cannot use."
                            .into(),
                        None,
                    );
                }
            }
            Event::Passkey { confirm } => {
                self.passkey_code = Some(confirm);
            }
            Event::Ready {} => {}
            Event::SignedIn {
                email,
                import,
                resume,
            } => {
                self.busy = false;
                self.account = email;
                self.factor = None;
                self.passkey_code = None;
                self.factors.clear();
                self.imports = import;
                self.resume = resume;
                self.show(Page::Choose, cx);
            }
            Event::KeysChecked { import } => {
                self.busy = false;
                self.checking_keys = false;
                self.imports = import;
            }
            Event::SignedOut { message } => {
                self.reset_session(window, cx);
                if let Some(message) = message.filter(|m| !m.trim().is_empty()) {
                    self.report(message, None);
                }
            }
            Event::Progress { message } => self.status = message,
            Event::Finished { message } => {
                self.busy = false;
                self.stopping = false;
                self.stopped = false;
                if !message.trim().is_empty() {
                    self.status = message;
                }
                self.source_password
                    .update(cx, |s, cx| s.set_value("", window, cx));
            }
            Event::Stopped { message } => {
                self.busy = false;
                self.stopping = false;
                self.checking_keys = false;
                self.stopped = self.page == Page::Transfer;
                self.status = message;
            }
            Event::Error {
                code,
                message,
                detail,
            } => {
                self.busy = false;
                self.stopping = false;
                self.checking_keys = false;
                if self.account.is_empty() && code != "busy" {
                    self.reset_session(window, cx);
                }
                self.report(message, detail);
            }
            Event::Disconnected { message } => {
                self.reset_session(window, cx);
                self.report(message, None);
            }
        }
        cx.notify();
    }

    fn source(&self, cx: &App) -> Result<Source, String> {
        let text = |field: &Entity<InputState>| field.read(cx).value().trim().to_owned();
        match self.mode {
            Mode::Imap => {
                let server = text(&self.server);
                let username = text(&self.username);
                let password = self.source_password.read(cx).value().to_string();
                if server.is_empty() || username.is_empty() || password.is_empty() {
                    return Err("Enter the IMAP server, mailbox login, and password from your old provider.".into());
                }
                Ok(Source::Imap {
                    server,
                    username,
                    password,
                })
            }
            Mode::Files => {
                let path = text(&self.files);
                if !std::path::Path::new(&path).exists() {
                    return Err(
                        "Choose an existing EML file, MBOX file, or folder of mail files.".into(),
                    );
                }
                Ok(Source::Files { path })
            }
            Mode::Export => {
                let directory = text(&self.directory);
                if directory.is_empty() || std::path::Path::new(&directory).is_file() {
                    return Err("Choose a folder to save your mail.".into());
                }
                Ok(Source::Export { directory })
            }
        }
    }

    fn review(&mut self, cx: &mut Context<Self>) {
        match self.source(cx) {
            Ok(_) => self.show(Page::Review, cx),
            Err(message) => self.report(message, None),
        }
        cx.notify();
    }

    fn start(&mut self, cx: &mut Context<Self>) {
        if self.page != Page::Review || self.busy {
            return;
        }
        match self
            .source(cx)
            .and_then(|source| self.send(Command::Transfer { source }))
        {
            Ok(()) => {
                self.busy = true;
                self.stopping = false;
                self.stopped = false;
                self.status = "Preparing transfer…".into();
                self.show(Page::Transfer, cx);
            }
            Err(error) => self.report(error, None),
        }
        cx.notify();
    }

    fn check_keys(&mut self, cx: &mut Context<Self>) {
        if self.busy {
            return;
        }
        match self.send(Command::VerifyKeys) {
            Ok(()) => {
                self.busy = true;
                self.checking_keys = true;
                self.clear_problem();
            }
            Err(message) => self.report(message, None),
        }
        cx.notify();
    }

    fn continue_last(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(last) = self.resume.clone() else {
            return;
        };
        let set = |field: &Entity<InputState>, value: String, window: &mut Window, cx: &mut App| {
            field.update(cx, |s, cx| s.set_value(value, window, cx));
        };
        self.mode = match last.kind.as_str() {
            "imap" => {
                set(&self.server, last.server, window, cx);
                Mode::Imap
            }
            "files" => {
                set(&self.files, last.path, window, cx);
                Mode::Files
            }
            _ => {
                set(&self.directory, last.directory, window, cx);
                Mode::Export
            }
        };
        self.show(Page::Setup, cx);
    }

    fn copy_detail(&mut self, cx: &mut Context<Self>) {
        let mut text = self.problem.clone().unwrap_or_default();
        if let Some(detail) = &self.detail {
            text.push('\n');
            text.push_str(detail);
        }
        if let Some(log) = log_path() {
            text.push_str(&format!("\nLog: {}", log.display()));
        }
        text.push_str(&format!("\nVersion: {}", env!("CARGO_PKG_VERSION")));
        cx.write_to_clipboard(ClipboardItem::new_string(text));
    }

    fn stop(&mut self, cx: &mut Context<Self>) {
        if self.stopping {
            return;
        }
        match self.send(Command::Cancel) {
            Ok(()) => self.stopping = true,
            Err(message) => self.report(message, None),
        }
        cx.notify();
    }

    fn browse(&mut self, directory: bool, window: &mut Window, cx: &mut Context<Self>) {
        let picker = cx.prompt_for_paths(PathPromptOptions {
            files: !directory,
            directories: directory,
            multiple: false,
            prompt: Some(
                if directory {
                    "Choose folder"
                } else {
                    "Choose file"
                }
                .into(),
            ),
        });
        let field = if self.mode == Mode::Export {
            self.directory.clone()
        } else {
            self.files.clone()
        };
        cx.spawn_in(window, async move |this, cx| {
            let selected = picker.await;
            let _ = this.update_in(cx, |view, window, cx| {
                match selected {
                    Ok(Ok(Some(paths))) => {
                        if let Some(path) = paths.first() {
                            if let Some(value) = path.to_str() {
                                field.update(cx, |s, cx| s.set_value(value.to_owned(), window, cx));
                                view.clear_problem();
                            } else {
                                view.problem =
                                    Some("Choose a folder or file with a Unicode name.".into());
                            }
                        }
                    }
                    Ok(Ok(None)) => {}
                    _ => view.report("Enter the path in the field to continue.".into(), None),
                }
                cx.notify();
            });
        })
        .detach();
    }
    fn action(&self) -> &'static str {
        if self.mode == Mode::Export {
            "Export"
        } else {
            "Import"
        }
    }

    fn step(&self) -> usize {
        match self.page {
            Page::SignIn | Page::Factor => 0,
            Page::Choose => 1,
            Page::Setup => 2,
            Page::Review => 3,
            Page::Transfer => 4,
        }
    }

    fn steps(&self) -> [&'static str; 5] {
        let known = self.step() > 1;
        [
            "Sign in",
            "Choose a transfer",
            if !known {
                "Set up"
            } else if self.mode == Mode::Export {
                "Choose a folder"
            } else {
                "Choose a source"
            },
            "Review",
            if known { self.action() } else { "Transfer" },
        ]
    }

    fn sidebar(&self) -> Div {
        let mut steps = column().gap_0().mt(px(48.));
        for (index, label) in self.steps().iter().enumerate() {
            let done = index < self.step()
                || (index == 4
                    && !self.busy
                    && !self.stopped
                    && self.problem.is_none()
                    && self.page == Page::Transfer);
            let current = index == self.step();
            let marker = div()
                .size(px(24.))
                .flex_shrink_0()
                .flex()
                .items_center()
                .justify_center()
                .rounded_full()
                .border_1()
                .border_color(rgb(if current || done { PALE } else { 0x799683 }))
                .when(current || done, |d| {
                    d.bg(rgb(if done { 0xdbe8df } else { PALE }))
                })
                .when(done, |d| d.child(icon(IconName::Check, 14., PINE)))
                .when(!done, |d| {
                    d.child(
                        text(
                            (index + 1).to_string(),
                            12.,
                            if current { DEEP } else { SAGE },
                        )
                        .font_weight(FontWeight::SEMIBOLD),
                    )
                });
            steps = steps.child(row().id(("step", index)).gap_3().child(marker).child(
                text(*label, 15., if current || done { PALE } else { SAGE }).font_weight(
                    if current {
                        FontWeight::SEMIBOLD
                    } else {
                        FontWeight::NORMAL
                    },
                ),
            ));
            if index != 4 {
                steps = steps.child(
                    div()
                        .ml(px(11.5))
                        .my(px(3.))
                        .h(px(17.))
                        .w(px(1.))
                        .bg(rgb(0x647e6a)),
                );
            }
        }
        column()
            .w(px(218.))
            .h_full()
            .flex_shrink_0()
            .bg(rgb(DEEP))
            .px(px(26.))
            .py(px(35.))
            .child(brand(false))
            .child(steps)
            .child(div().flex_1())
            .child(text(
                concat!("Version ", env!("CARGO_PKG_VERSION")),
                12.,
                SAGE,
            ))
    }

    fn compact_header(&self) -> Div {
        row()
            .justify_between()
            .px_4()
            .py_3()
            .bg(rgb(DEEP))
            .child(brand(true))
            .child(text(
                format!("{} / 5   {}", self.step() + 1, self.steps()[self.step()]),
                13.,
                PALE,
            ))
    }

    fn account_bar(&self, cx: &mut Context<Self>) -> Div {
        row()
            .w_full()
            .min_w_0()
            .justify_between()
            .border_b_1()
            .border_color(rgb(RULE))
            .pb_3()
            .child(
                row()
                    .min_w_0()
                    .child(icon(IconName::CircleUser, 16., MUTED))
                    .child(div().min_w_0().truncate().child(text(
                        self.account.clone(),
                        14.,
                        MUTED,
                    ))),
            )
            .child(
                Button::new("sign-out")
                    .small()
                    .ghost()
                    .label("Sign out")
                    .disabled(self.busy)
                    .on_click(cx.listener(|v, _, w, cx| {
                        v.reset_session(w, cx);
                        v.email.update(cx, |s, cx| s.set_value("", w, cx));
                    })),
            )
    }

    fn signin_form(&self, cx: &mut Context<Self>) -> Div {
        column()
            .gap_5()
            .child(title(
                "Sign in to Thelemail",
                "Use the account you want to import into or export from.",
            ))
            .child(field("Email address", &self.email, self.busy))
            .child(field("Password", &self.password, self.busy))
            .child(
                row().child(
                    Button::new("sign-in")
                        .primary()
                        .label(if self.busy {
                            "Signing in…"
                        } else {
                            "Sign in"
                        })
                        .loading(self.busy)
                        .disabled(self.busy)
                        .on_click(cx.listener(|v, _, w, cx| v.authenticate(w, cx))),
                ),
            )
            .child(div().mt_2().child(hint(
                IconName::Info,
                "If you use two-step verification, you’ll verify your account next.",
            )))
    }

    fn factor_form(&self, cx: &mut Context<Self>) -> Div {
        let method = self.factor.unwrap_or(Factor::Passkey);
        let (description, button) = match method {
            Factor::Passkey => (
                "Continue in your browser with your passkey or security key. Then come back here.",
                "Open browser",
            ),
            Factor::Totp => (
                "Enter the six-digit code from your authenticator app.",
                "Verify code",
            ),
            Factor::Recovery => (
                "Enter one of the recovery codes you saved for this account.",
                "Verify code",
            ),
        };
        let mut body = column()
            .gap_4()
            .child(title("Verify your sign-in", description));
        if let (Factor::Passkey, true, Some(code)) = (method, self.busy, &self.passkey_code) {
            body = body.child(
                column()
                    .gap_1()
                    .child(text(
                        "Your browser shows a code too. Continue only if it matches this one.",
                        14.,
                        MUTED,
                    ))
                    .child(text(code.clone(), 24., INK).font_weight(FontWeight::SEMIBOLD)),
            );
        }
        if method != Factor::Passkey {
            body = body.child(field(
                if method == Factor::Recovery {
                    "Recovery code"
                } else {
                    "Authenticator code"
                },
                &self.code,
                self.busy,
            ));
        }
        body = body.child(
            row()
                .child(
                    Button::new("verify")
                        .primary()
                        .label(if self.busy && method == Factor::Passkey {
                            "Waiting for browser…"
                        } else if self.busy {
                            "Verifying…"
                        } else {
                            button
                        })
                        .disabled(self.busy)
                        .loading(self.busy)
                        .on_click(cx.listener(|v, _, w, cx| v.authenticate(w, cx))),
                )
                .child(
                    Button::new("cancel-login")
                        .ghost()
                        .label("Back to sign in")
                        .on_click(cx.listener(|v, _, w, cx| v.reset_session(w, cx))),
                ),
        );
        if !self.busy {
            let others: Vec<_> = self
                .factors
                .iter()
                .copied()
                .filter(|f| *f != method)
                .collect();
            if !others.is_empty() {
                let mut choices = column()
                    .items_start()
                    .gap_1()
                    .mt_2()
                    .pt_3()
                    .border_t_1()
                    .border_color(rgb(RULE));
                for factor in others {
                    choices = choices.child(
                        Button::new(factor.wire())
                            .link()
                            .label(factor.label())
                            .on_click(cx.listener(move |v, _, w, cx| {
                                v.factor = Some(factor);
                                v.code.update(cx, |s, cx| s.set_value("", w, cx));
                                v.clear_problem();
                                cx.notify();
                            })),
                    );
                }
                body = body.child(choices);
            }
        }
        body
    }

    fn choose(&self, cx: &mut Context<Self>) -> Div {
        let mut routes = column().gap_0().border_b_1().border_color(rgb(RULE));
        for (id, mode, glyph, heading, description) in [
            (
                "import",
                Mode::Imap,
                IconName::Inbox,
                "Import mail",
                "Bring an old mailbox or mail files into Thelemail.",
            ),
            (
                "export",
                Mode::Export,
                IconName::FolderOpen,
                "Export mail",
                "Save a readable copy of your Thelemail mailbox.",
            ),
        ] {
            let blocked = mode != Mode::Export && !self.imports.allowed;
            routes = routes.child(
                div().border_t_1().border_color(rgb(RULE)).py_1().child(
                    Button::new(id)
                        .ghost()
                        .w_full()
                        .h(px(85.))
                        .disabled(blocked || self.busy)
                        .accessibility_label(heading)
                        .child(
                            row()
                                .w_full()
                                .gap_4()
                                .child(div().flex_shrink_0().child(icon(glyph, 26., PINE)))
                                .child(
                                    column()
                                        .flex_1()
                                        .min_w_0()
                                        .items_start()
                                        .gap_1()
                                        .child(
                                            text(heading, 19., INK)
                                                .font_weight(FontWeight::SEMIBOLD),
                                        )
                                        .child(text(description, 14., MUTED)),
                                )
                                .child(icon(IconName::ChevronRight, 17., MUTED)),
                        )
                        .on_click(cx.listener(move |v, _, _, cx| {
                            v.mode = mode;
                            v.show(Page::Setup, cx);
                        })),
                ),
            );
        }
        let mut body = column().gap_6().child(title(
            "Choose a transfer",
            "Where would you like your mail to go?",
        ));
        if let Some(last) = &self.resume {
            let (heading, place) = match last.kind.as_str() {
                "imap" => ("Continue your import", last.server.clone()),
                "files" => ("Continue your import", last.path.clone()),
                _ => ("Continue your export", last.directory.clone()),
            };
            let blocked = last.kind != "export" && !self.imports.allowed;
            body = body.child(
                column()
                    .gap_3()
                    .rounded_md()
                    .bg(rgb(RAISED))
                    .p_4()
                    .child(text(heading, 17., INK).font_weight(FontWeight::SEMIBOLD))
                    .child(text(
                        format!("Your last transfer from {place} didn’t finish. Migrator picks up where it stopped and skips mail that’s already copied."),
                        14.,
                        MUTED,
                    ))
                    .child(
                        row().child(
                            Button::new("resume")
                                .primary()
                                .label("Continue")
                                .disabled(blocked || self.busy)
                                .on_click(cx.listener(|v, _, w, cx| v.continue_last(w, cx))),
                        ),
                    ),
            );
        }
        body = body.child(routes);
        if !self.imports.allowed {
            body = body.child(
                column()
                    .gap_3()
                    .child(hint(
                        IconName::CircleAlert,
                        self.imports.reason.clone().unwrap_or_else(|| {
                            "Migrator couldn’t verify your account keys, so importing is paused. Export still works.".into()
                        }),
                    ))
                    .child(
                        row().child(
                            Button::new("check-keys")
                                .label(if self.checking_keys {
                                    "Checking…"
                                } else {
                                    "Check again"
                                })
                                .loading(self.checking_keys)
                                .disabled(self.busy)
                                .on_click(cx.listener(|v, _, _, cx| v.check_keys(cx))),
                        ),
                    ),
            );
        }
        body
    }

    fn setup(&self, cx: &mut Context<Self>) -> Div {
        let exporting = self.mode == Mode::Export;
        let mut body = column().gap_4().child(title(
            if exporting {
                "Choose an export folder"
            } else {
                "Import mail"
            },
            if exporting {
                "Save a copy of your mailbox on this computer."
            } else {
                "Choose where to copy your messages from."
            },
        ));
        if !exporting {
            let mut tabs = row().gap_1();
            for (id, mode, label) in [
                ("imap", Mode::Imap, "IMAP mailbox"),
                ("files", Mode::Files, "EML or MBOX files"),
            ] {
                tabs = tabs.child(
                    Button::new(id)
                        .label(label)
                        .when(self.mode == mode, |b| b.primary())
                        .on_click(cx.listener(move |v, _, _, cx| {
                            v.mode = mode;
                            v.clear_problem();
                            cx.notify();
                        })),
                );
            }
            body = body.child(tabs);
        }
        body = match self.mode {
            Mode::Imap => body
                .child(field("IMAP server", &self.server, false))
                .child(field("Mailbox login", &self.username, false))
                .child(field("Mailbox password", &self.source_password, false))
                .child(hint(IconName::FolderClosed, "All folders are included. For Hostinger Titan, use imap.titan.email."))
                .child(hint(IconName::Info, "Migrator connects with TLS on port 993. For a server on port 143, add :143 and Migrator switches to TLS with STARTTLS before signing in.")),
            Mode::Files => body
                .child(field("Mail file or folder", &self.files, false))
                .child(row().child(Button::new("choose-file").label("Choose file…").on_click(cx.listener(|v,_,w,cx|v.browse(false,w,cx))))
                    .child(Button::new("choose-files-folder").label("Choose folder…").on_click(cx.listener(|v,_,w,cx|v.browse(true,w,cx)))))
                .child(hint(IconName::FileText, "Choose an EML message, an MBOX archive, or a folder containing mail files.")),
            Mode::Export => body.child(field("Save to", &self.directory, false))
                .child(row().child(Button::new("choose-directory").label("Choose folder…").on_click(cx.listener(|v,_,w,cx|v.browse(true,w,cx)))))
                .child(hint(IconName::FolderClosed, "Choose an empty, private folder for the decrypted files. To resume an export, select its original folder.")),
        };
        body.child(
            row()
                .mt_2()
                .child(
                    Button::new("review")
                        .primary()
                        .label(if exporting {
                            "Review export"
                        } else {
                            "Review import"
                        })
                        .on_click(cx.listener(|v, _, _, cx| v.review(cx))),
                )
                .child(back(Page::Choose, cx)),
        )
    }

    fn review_page(&self, cx: &mut Context<Self>) -> Div {
        let exporting = self.mode == Mode::Export;
        let (source, destination, scope, description) = match self.mode {
            Mode::Imap => (
                format!(
                    "{} · {}",
                    self.username.read(cx).value(),
                    self.server.read(cx).value()
                ),
                self.account.clone(),
                "Whole mailbox",
                "Sent mail and custom folders keep their places. Read and unread messages keep their status.",
            ),
            Mode::Files => {
                let path = self.files.read(cx).value().trim().to_owned();
                let description = if std::path::Path::new(&path).is_dir() {
                    "Subfolders and MBOX files keep their grouping. Read status is preserved when the files include it."
                } else {
                    "These messages will be added to Inbox as read."
                };
                (path, self.account.clone(), "EML or MBOX files", description)
            }
            Mode::Export => (
                self.account.clone(),
                self.directory.read(cx).value().to_string(),
                "Per-folder MBOX files",
                "Your export contains readable mail and attachments. Keep the folder private.",
            ),
        };
        column()
            .gap_5()
            .child(title(
                if exporting {
                    "Review your export"
                } else {
                    "Review your import"
                },
                if exporting {
                    "Check where the backup will be saved."
                } else {
                    "Check the source and destination before copying mail."
                },
            ))
            .child(
                column()
                    .gap_0()
                    .border_t_1()
                    .border_color(rgb(RULE))
                    .child(detail("From", source))
                    .child(detail("To", destination))
                    .child(detail("Includes", scope.to_owned())),
            )
            .child(hint(
                if exporting {
                    IconName::FolderClosed
                } else {
                    IconName::Inbox
                },
                description,
            ))
            .child(
                row()
                    .child(
                        Button::new("start")
                            .primary()
                            .label(if exporting {
                                "Start export"
                            } else {
                                "Start import"
                            })
                            .on_click(cx.listener(|v, _, _, cx| v.start(cx))),
                    )
                    .child(back(Page::Setup, cx)),
            )
    }

    fn transfer_page(&self, cx: &mut Context<Self>) -> Div {
        let exporting = self.mode == Mode::Export;
        let headline = match (
            self.busy,
            self.stopping,
            self.stopped,
            self.problem.is_some(),
            exporting,
        ) {
            (true, true, _, _, _) => "Stopping transfer",
            (true, _, _, _, true) => "Exporting mail",
            (true, _, _, _, false) => "Importing mail",
            (_, _, true, _, _) => "Transfer stopped",
            (_, _, _, true, _) => "Transfer interrupted",
            (_, _, _, _, true) => "Export complete",
            _ => "Import complete",
        };
        let mut body = column()
            .gap_5()
            .child(
                row()
                    .gap_3()
                    .when(self.busy, |el| {
                        el.child(Spinner::new().color(rgb(PINE).into()))
                    })
                    .when(!self.busy, |el| {
                        el.child(icon(
                            if self.stopped || self.problem.is_some() {
                                IconName::CircleAlert
                            } else {
                                IconName::CircleCheck
                            },
                            27.,
                            PINE,
                        ))
                    })
                    .child(heading(headline)),
            )
            .child(text(self.status.clone(), 17., INK));
        if self.busy {
            body = body.child(
                row().child(
                    Button::new("stop")
                        .label("Stop transfer")
                        .disabled(self.stopping)
                        .on_click(cx.listener(|v, _, _, cx| v.stop(cx))),
                ),
            );
        } else {
            body = body.child(
                row()
                    .when(self.stopped || self.problem.is_some(), |el| {
                        el.child(
                            Button::new("retry")
                                .primary()
                                .label("Review settings")
                                .on_click(cx.listener(|v, _, _, cx| v.show(Page::Setup, cx))),
                        )
                    })
                    .child(
                        Button::new("again")
                            .label("Choose another transfer")
                            .on_click(cx.listener(|v, _, _, cx| v.show(Page::Choose, cx))),
                    ),
            );
        }
        body
    }
}

impl Migrator {
    fn problem_banner(&self, error: String, cx: &mut Context<Self>) -> Div {
        let mut banner = column().gap_2().bg(rgb(0xf4e5e0)).py_2().px_4().child(
            div()
                .id("form-error")
                .role(Role::Alert)
                .child(text(error, 14., ERROR)),
        );
        if let Some(detail) = self.detail.clone() {
            banner = banner
                .child(
                    row()
                        .child(
                            Button::new("problem-detail")
                                .small()
                                .ghost()
                                .label(if self.show_detail {
                                    "Hide details"
                                } else {
                                    "Show details"
                                })
                                .on_click(cx.listener(|v, _, _, cx| {
                                    v.show_detail = !v.show_detail;
                                    cx.notify();
                                })),
                        )
                        .child(
                            Button::new("copy-detail")
                                .small()
                                .ghost()
                                .label("Copy details")
                                .on_click(cx.listener(|v, _, _, cx| v.copy_detail(cx))),
                        ),
                )
                .when(self.show_detail, |b| {
                    b.child(div().id("problem-text").child(text(detail, 12., MUTED)))
                });
        }
        banner
    }
}

fn row() -> Div {
    div().flex().items_center().gap_2()
}
fn column() -> Div {
    div().flex().flex_col()
}
fn icon(name: IconName, size: f32, color: u32) -> Icon {
    Icon::new(name).with_size(px(size)).text_color(rgb(color))
}
fn brand(compact: bool) -> Div {
    if compact {
        text("Thelemail Migrator", 17., PALE).font_weight(FontWeight::SEMIBOLD)
    } else {
        column()
            .items_start()
            .child(text("Thelemail", 17., SAGE).font_weight(FontWeight::MEDIUM))
            .child(
                text("Migrator", 31., PALE)
                    .line_height(px(34.))
                    .font_weight(FontWeight::SEMIBOLD),
            )
    }
}
#[track_caller]
fn text(value: impl Into<SharedString>, size: f32, color: u32) -> Div {
    let value = value.into();
    div()
        .text_size(px(size))
        .line_height(px(size * 1.36))
        .text_color(rgb(color))
        .child(
            Label::new(value.clone())
                .id((value, std::panic::Location::caller().line() as usize))
                .line_height(px(size * 1.36))
                .text_color(rgb(color)),
        )
}
#[track_caller]
fn heading(value: &'static str) -> Div {
    text(value, 31., INK).font_weight(FontWeight::SEMIBOLD)
}
#[track_caller]
fn title(value: &'static str, description: &'static str) -> Div {
    column()
        .gap_1()
        .mb_2()
        .child(heading(value))
        .child(text(description, 16., MUTED))
}
#[track_caller]
fn field(label: &'static str, input: &Entity<InputState>, disabled: bool) -> Div {
    column()
        .gap_1()
        .child(text(label, 14., INK).font_weight(FontWeight::SEMIBOLD))
        .child(
            Input::new(input)
                .id(label)
                .aria_label(label)
                .disabled(disabled)
                .h(px(37.)),
        )
}
#[track_caller]
fn hint(glyph: IconName, copy: impl Into<SharedString>) -> Div {
    div()
        .flex()
        .items_start()
        .gap_3()
        .rounded_md()
        .bg(rgb(RAISED))
        .p_3()
        .child(
            div()
                .flex_shrink_0()
                .mt(px(1.))
                .child(icon(glyph, 17., PINE)),
        )
        .child(div().min_w_0().flex_1().child(text(copy, 14., MUTED)))
}
#[track_caller]
fn detail(label: &'static str, value: String) -> Div {
    div()
        .flex()
        .items_start()
        .gap_2()
        .py_3()
        .border_b_1()
        .border_color(rgb(RULE))
        .child(
            div()
                .w(px(69.))
                .flex_shrink_0()
                .child(text(label, 14., MUTED)),
        )
        .child(div().min_w_0().flex_1().child(text(value, 16., INK)))
}
fn back(page: Page, cx: &mut Context<Migrator>) -> Button {
    Button::new("back")
        .ghost()
        .label("Back")
        .on_click(cx.listener(move |v, _, _, cx| v.show(page, cx)))
}

impl Render for Migrator {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let compact = window.viewport_size().width < px(680.);
        let content = match self.page {
            Page::SignIn => self.signin_form(cx),
            Page::Factor => self.factor_form(cx),
            Page::Choose => self.choose(cx),
            Page::Setup => self.setup(cx),
            Page::Review => self.review_page(cx),
            Page::Transfer => self.transfer_page(cx),
        };
        let panel = column()
            .w_full()
            .max_w(px(580.))
            .mx_auto()
            .px(px(if compact { 22. } else { 38. }))
            .pt(px(if compact { 20. } else { 31. }))
            .pb_6()
            .when(!self.account.is_empty(), |p| p.child(self.account_bar(cx)))
            .child(
                column()
                    .pt(px(if self.account.is_empty() && !compact {
                        48.
                    } else {
                        20.
                    }))
                    .child(content),
            );
        div()
            .size_full()
            .flex()
            .bg(rgb(PAPER))
            .text_color(rgb(INK))
            .when(compact, |d| d.flex_col().child(self.compact_header()))
            .when(!compact, |d| d.child(self.sidebar()))
            .child(
                column()
                    .flex_1()
                    .min_w_0()
                    .min_h_0()
                    .child(
                        div()
                            .id("form-scroll")
                            .flex_1()
                            .min_h_0()
                            .overflow_y_scroll()
                            .track_scroll(&self.scroll)
                            .child(panel),
                    )
                    .when_some(self.problem.clone(), |el, error| {
                        el.child(self.problem_banner(error, cx))
                    }),
            )
    }
}

#[cfg(test)]
mod tests {
    use super::{Event, Migrator, Page, configure_theme};
    use crate::engine::{Imports, Resume};
    use gpui_kit::{AppContext, TestAppContext, WindowOptions, open_window, test::TestWindowExt};

    #[gpui_kit::test]
    fn sign_in_gates_distinct_import_and_export_steps(cx: &mut TestAppContext) {
        let (handle, view) = cx.update(|cx| {
            configure_theme(cx);
            open_window(WindowOptions::default(), cx, |window, cx| {
                cx.new(|cx| Migrator::new(window, cx))
            })
            .unwrap()
        });
        cx.update_window(handle, |_, window, cx| {
            window.render_frame(cx);
            assert!(window.find("sign-in").visible());
            window.click("sign-in", cx);
            assert!(view.read(cx).problem.is_some());
            view.update(cx, |v, cx| {
                v.receive(
                    Event::Challenge {
                        methods: vec!["webauthn".into(), "backupCode".into(), "totp".into()],
                        message: None,
                    },
                    window,
                    cx,
                )
            });
            window.render_frame(cx);
            assert_eq!(window.find("verify").label(), Some("Open browser"));
            view.update(cx, |v, cx| {
                v.busy = true;
                v.receive(
                    Event::Passkey {
                        confirm: "AKTC-EUFO".into(),
                    },
                    window,
                    cx,
                )
            });
            window.render_frame(cx);
            assert_eq!(window.find("verify").label(), Some("Waiting for browser…"));
            assert_eq!(view.read(cx).passkey_code.as_deref(), Some("AKTC-EUFO"));
            view.update(cx, |v, _| v.busy = false);
            window.click("backupCode", cx);
            window.click("Recovery code", cx);
            window.input("test-recovery-code", cx);
            assert_ne!(
                window.find("Recovery code").value(),
                Some("test-recovery-code")
            );
            view.update(cx, |v, cx| {
                v.receive(
                    Event::Challenge {
                        methods: vec!["webauthn".into(), "backupCode".into(), "totp".into()],
                        message: Some("Try another code.".into()),
                    },
                    window,
                    cx,
                )
            });
            window.render_frame(cx);
            assert!(window.find("Recovery code").visible());
            assert_eq!(view.read(cx).problem.as_deref(), Some("Try another code."));
            window.click("totp", cx);
            assert!(window.find("Authenticator code").visible());
            view.update(cx, |v, cx| {
                v.receive(
                    Event::SignedIn {
                        email: "demo@example.invalid".into(),
                        import: Imports {
                            allowed: true,
                            reason: None,
                        },
                        resume: None,
                    },
                    window,
                    cx,
                )
            });
            window.render_frame(cx);
            window.click("import", cx);
            window.click("review", cx);
            assert!(view.read(cx).problem.is_some());
            window.click("Mailbox login", cx);
            window.input("source@example.invalid", cx);
            window.press("tab", cx);
            window.input("synthetic-secret", cx);
            assert_eq!(
                view.read(cx).source_password.read(cx).value().as_ref(),
                "synthetic-secret"
            );
            window.click("review", cx);
            assert_eq!(window.find("start").label(), Some("Start import"));
            window.click("back", cx);
            window.click("files", cx);
            assert!(window.find("choose-file").visible());
            window.click("back", cx);
            window.click("export", cx);
            assert!(window.find("choose-directory").visible());
            window.click("Save to", cx);
            window.input("/tmp/thelemail-test-export", cx);
            window.click("review", cx);
            assert_eq!(window.find("start").label(), Some("Start export"));
            window.click("sign-out", cx);
            assert!(window.find("sign-in").visible());
            assert!(view.read(cx).source_password.read(cx).value().is_empty());
        })
        .unwrap();
    }

    #[gpui_kit::test]
    fn blocked_imports_resume_and_ended_sessions(cx: &mut TestAppContext) {
        let (handle, view) = cx.update(|cx| {
            configure_theme(cx);
            open_window(WindowOptions::default(), cx, |window, cx| {
                cx.new(|cx| Migrator::new(window, cx))
            })
            .unwrap()
        });
        cx.update_window(handle, |_, window, cx| {
            view.update(cx, |v, cx| {
                v.receive(
                    Event::SignedIn {
                        email: "demo@example.invalid".into(),
                        import: Imports {
                            allowed: false,
                            reason: Some("Account keys could not be verified.".into()),
                        },
                        resume: Some(Resume {
                            kind: "imap".into(),
                            server: "imap.example.invalid".into(),
                            path: String::new(),
                            directory: String::new(),
                        }),
                    },
                    window,
                    cx,
                )
            });
            window.render_frame(cx);
            assert!(window.find("check-keys").visible());
            window.click("import", cx);
            assert!(view.read(cx).page == Page::Choose);
            view.update(cx, |v, cx| {
                v.receive(
                    Event::KeysChecked {
                        import: Imports {
                            allowed: true,
                            reason: None,
                        },
                    },
                    window,
                    cx,
                )
            });
            window.render_frame(cx);
            window.click("resume", cx);
            assert!(view.read(cx).page == Page::Setup);
            assert_eq!(
                view.read(cx).server.read(cx).value().as_ref(),
                "imap.example.invalid"
            );
            assert_eq!(view.read(cx).username.read(cx).value().as_ref(), "");
            view.update(cx, |v, cx| {
                v.receive(
                    Event::Error {
                        code: "quota".into(),
                        message: "Your Thelemail storage is full.".into(),
                        detail: Some("destination returned HTTP 507".into()),
                    },
                    window,
                    cx,
                )
            });
            window.render_frame(cx);
            window.click("problem-detail", cx);
            window.render_frame(cx);
            assert!(view.read(cx).show_detail);
            assert!(window.find("copy-detail").visible());
            view.update(cx, |v, cx| {
                v.receive(
                    Event::SignedOut {
                        message: Some("Your Thelemail session ended.".into()),
                    },
                    window,
                    cx,
                )
            });
            window.render_frame(cx);
            assert!(window.find("sign-in").visible());
            assert_eq!(
                view.read(cx).problem.as_deref(),
                Some("Your Thelemail session ended.")
            );
            assert!(view.read(cx).account.is_empty());
        })
        .unwrap();
    }
}
