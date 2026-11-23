use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Command as Process, Stdio};
use std::{sync::mpsc, thread};

const LOG_LIMIT: u64 = 5 << 20;

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Command {
    Login { email: String, password: String },
    Factor { method: String, code: String },
    Transfer { source: Source },
    CheckSource { source: Source },
    VerifyKeys,
    Cancel,
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Source {
    Imap {
        server: String,
        port: String,
        security: String,
        username: String,
        password: String,
    },
    Files {
        path: String,
    },
    Export {
        directory: String,
    },
}

#[derive(Deserialize, Clone, Default, Debug, PartialEq, Eq)]
pub struct Imports {
    pub allowed: bool,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Resume {
    pub kind: String,
    #[serde(default)]
    pub server: String,
    #[serde(default)]
    pub port: String,
    #[serde(default)]
    pub security: String,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub directory: String,
}

#[derive(Deserialize, Clone, Default, Debug, PartialEq, Eq)]
pub struct SourceCheck {
    pub address: String,
    pub security: String,
    pub folders: usize,
    pub messages: usize,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    Ready {},
    Challenge {
        methods: Vec<String>,
        message: Option<String>,
    },
    Passkey {
        confirm: String,
    },
    SignedIn {
        email: String,
        #[serde(default)]
        import: Imports,
        #[serde(default)]
        resume: Option<Resume>,
    },
    KeysChecked {
        #[serde(default)]
        import: Imports,
    },
    SourceChecked {
        check: SourceCheck,
    },
    SignedOut {
        #[serde(default)]
        message: Option<String>,
    },
    Progress {
        message: String,
    },
    Finished {
        message: String,
    },
    Error {
        #[serde(default)]
        code: String,
        message: String,
        #[serde(default)]
        detail: Option<String>,
    },
    Stopped {
        message: String,
    },
    #[serde(skip)]
    Disconnected {
        message: String,
    },
}

pub fn log_path() -> Option<PathBuf> {
    let home = || std::env::var_os("HOME").map(PathBuf::from);
    let dir = if cfg!(target_os = "macos") {
        home()?.join("Library/Logs/Thelemail Migrator")
    } else if cfg!(windows) {
        PathBuf::from(std::env::var_os("LOCALAPPDATA")?).join("Thelemail\\Migrator\\Logs")
    } else {
        std::env::var_os("XDG_STATE_HOME")
            .map(PathBuf::from)
            .or_else(|| home().map(|h| h.join(".local/state")))?
            .join("thelemail-migrator")
    };
    Some(dir.join("engine.log"))
}

fn log_file() -> Option<File> {
    let path = log_path()?;
    fs::create_dir_all(path.parent()?).ok()?;
    if fs::metadata(&path).is_ok_and(|m| m.len() > LOG_LIMIT) {
        let _ = fs::rename(&path, path.with_extension("log.1"));
    }
    OpenOptions::new().create(true).append(true).open(path).ok()
}

pub struct Engine(mpsc::Sender<Command>);

impl Engine {
    pub fn open() -> Result<(Self, async_channel::Receiver<Event>), String> {
        let path = std::env::current_exe()
            .map_err(|err| err.to_string())?
            .with_file_name(format!("migrator-engine{}", std::env::consts::EXE_SUFFIX));
        let mut cmd = Process::new(path);
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(0x08000000);
        }
        let stderr = log_file().map_or_else(Stdio::null, Stdio::from);
        let mut child = cmd
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(stderr)
            .spawn()
            .map_err(|err| format!("Could not open the transfer engine: {err}"))?;
        let mut input = child.stdin.take().expect("piped stdin");
        let output = child.stdout.take().expect("piped stdout");
        let (commands, receiver) = mpsc::channel();
        let (events, stream) = async_channel::unbounded();
        thread::spawn(move || {
            for command in receiver {
                if serde_json::to_writer(&mut input, &command).is_err()
                    || input.write_all(b"\n").is_err()
                {
                    break;
                }
            }
        });
        thread::spawn(move || {
            for line in BufReader::new(output).lines() {
                let event = line.ok().and_then(|line| serde_json::from_str(&line).ok());
                let Some(event) = event else {
                    let _ = child.kill();
                    break;
                };
                if events.send_blocking(event).is_err() {
                    break;
                }
            }
            let _ = child.wait();
            let _ = events.send_blocking(Event::Disconnected {
                message: "The transfer engine closed. Sign in again to continue.".into(),
            });
        });
        Ok((Self(commands), stream))
    }

    pub fn send(&self, command: Command) -> Result<(), String> {
        self.0
            .send(command)
            .map_err(|_| "The transfer engine is unavailable. Sign in again to continue.".into())
    }
}

#[cfg(test)]
mod tests {
    use super::{Event, Imports};

    #[test]
    fn reads_the_engine_protocol() {
        let signed: Event = serde_json::from_str(
            r#"{"type":"signed_in","email":"me@example.test","import":{"allowed":false,"reason":"keys"},"resume":{"kind":"imap","server":"imap.example.test"}}"#,
        )
        .unwrap();
        let Event::SignedIn { import, resume, .. } = signed else {
            panic!("not a sign-in")
        };
        assert_eq!(
            import,
            Imports {
                allowed: false,
                reason: Some("keys".into())
            }
        );
        assert_eq!(resume.unwrap().server, "imap.example.test");
        let error: Event = serde_json::from_str(
            r#"{"type":"error","code":"quota","message":"Your storage is full.","detail":"HTTP 507"}"#,
        )
        .unwrap();
        assert!(matches!(error, Event::Error { code, detail: Some(_), .. } if code == "quota"));
        let ended: Event = serde_json::from_str(
            r#"{"type":"signed_out","code":"session_ended","message":"Sign in again."}"#,
        )
        .unwrap();
        assert!(matches!(ended, Event::SignedOut { message: Some(_) }));
        assert!(serde_json::from_str::<Event>(r#"{"type":"ready","version":"1.0.0"}"#).is_ok());
    }
}
