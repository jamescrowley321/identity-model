//! Per-test RP logs (`clientSideData` for OIDF RP certification): each test's
//! lines are appended to `$RP_LOG_DIR/<profile>/<test_name>.log`.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// The test a request belongs to, as named by the runner.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ActiveTest {
    pub profile: String,
    pub test_name: String,
}

impl ActiveTest {
    pub fn new(profile: &str, test_name: &str) -> Self {
        Self {
            profile: profile.to_owned(),
            test_name: test_name.to_owned(),
        }
    }
}

/// Reduces `value` to one safe path segment: every character outside
/// `[A-Za-z0-9._-]` becomes `_`, and an empty or dots-only result becomes
/// `fallback` (so `..` cannot walk out of the base).
pub fn sanitize_component(value: &str, fallback: &str) -> String {
    let safe: String = value
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect();
    if safe.is_empty() || safe.chars().all(|c| c == '.') {
        fallback.to_owned()
    } else {
        safe
    }
}

/// The log file for `test` under `base`, or `None` when the test is unnamed or
/// the path would leave `base`.
pub fn log_path(base: &Path, test: &ActiveTest) -> Option<PathBuf> {
    if test.test_name.is_empty() {
        return None;
    }
    let profile = sanitize_component(&test.profile, "default");
    let name = sanitize_component(&test.test_name, "unknown");
    let relative = Path::new(&profile).join(format!("{name}.log"));
    relative
        .components()
        .all(|c| matches!(c, Component::Normal(_)))
        .then(|| base.join(relative))
}

/// Escapes control characters (CR, LF, ESC, ...) so one call yields one line.
fn escape_control(message: &str) -> String {
    let mut out = String::with_capacity(message.len());
    for c in message.chars() {
        if c.is_control() {
            out.extend(c.escape_debug());
        } else {
            out.push(c);
        }
    }
    out
}

/// Writes harness log lines to stderr and to the active test's file.
#[derive(Debug, Clone)]
pub struct RpLog {
    base: PathBuf,
}

impl RpLog {
    pub fn new(base: impl Into<PathBuf>) -> Self {
        Self { base: base.into() }
    }

    /// Logs `message` at `level` for `test` (stderr only when no test is named).
    ///
    /// Control characters are escaped so untrusted text (e.g. a callback's
    /// `error_description`) cannot forge extra lines in the evidence log.
    pub fn log(&self, test: &ActiveTest, level: &str, message: &str) {
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or_default();
        let message = escape_control(message);
        let line = format!("{secs} {level:<8} conformance-rp-rust: {message}");
        eprintln!("{line}");
        let Some(path) = log_path(&self.base, test) else {
            return;
        };
        let written = path
            .parent()
            .map_or(Ok(()), fs::create_dir_all)
            .and_then(|()| OpenOptions::new().create(true).append(true).open(&path))
            .and_then(|mut file| writeln!(file, "{line}"));
        if let Err(error) = written {
            // Never break the flow under test over log capture, but say so: an
            // empty clientSideData bundle is a worthless submission artifact.
            eprintln!(
                "WARNING: RP log capture failed for {}: {error}",
                path.display()
            );
        }
    }

    pub fn info(&self, test: &ActiveTest, message: &str) {
        self.log(test, "INFO", message);
    }

    pub fn error(&self, test: &ActiveTest, message: &str) {
        self.log(test, "ERROR", message);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_replaces_unsafe_characters_and_dot_only_names() {
        let cases = [
            ("basic-rp", "basic-rp"),
            ("oidcc-client-test.v1_x", "oidcc-client-test.v1_x"),
            ("../../etc/passwd", ".._.._etc_passwd"),
            ("a/b\\c d", "a_b_c_d"),
            ("..", "fb"),
            (".", "fb"),
            ("", "fb"),
            ("é", "_"),
        ];
        for (input, expected) in cases {
            assert_eq!(sanitize_component(input, "fb"), expected, "{input:?}");
        }
    }

    #[test]
    fn log_path_stays_inside_the_base() {
        let base = Path::new("/logs");
        assert_eq!(
            log_path(base, &ActiveTest::new("basic-rp", "oidcc-client-test")),
            Some(PathBuf::from("/logs/basic-rp/oidcc-client-test.log"))
        );
        assert_eq!(
            log_path(base, &ActiveTest::new("..", "../x")),
            Some(PathBuf::from("/logs/default/.._x.log"))
        );
        assert_eq!(log_path(base, &ActiveTest::new("basic-rp", "")), None);
    }

    #[test]
    fn log_appends_lines_to_the_test_file() {
        let dir = std::env::temp_dir().join(format!("rp-log-test-{}", std::process::id()));
        let log = RpLog::new(&dir);
        let test = ActiveTest::new("basic-rp", "oidcc-client-test");
        log.info(&test, "first");
        log.error(&test, "second");
        log.info(&ActiveTest::default(), "unrouted");
        let text =
            fs::read_to_string(dir.join("basic-rp/oidcc-client-test.log")).expect("log file");
        // Drop the leading timestamp; the rest of each line is deterministic.
        let lines: Vec<&str> = text
            .lines()
            .filter_map(|l| l.split_once(' ').map(|(_, rest)| rest))
            .collect();
        assert_eq!(
            lines,
            vec![
                "INFO     conformance-rp-rust: first",
                "ERROR    conformance-rp-rust: second",
            ]
        );
        fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn log_escapes_control_characters_into_one_line() {
        let dir = std::env::temp_dir().join(format!("rp-log-inject-{}", std::process::id()));
        let log = RpLog::new(&dir);
        let test = ActiveTest::new("basic-rp", "oidcc-client-test");
        log.error(
            &test,
            "access_denied x\r\nACCEPTED: authentication successful\u{1b}[0m",
        );
        let text =
            fs::read_to_string(dir.join("basic-rp/oidcc-client-test.log")).expect("log file");
        let lines: Vec<&str> = text
            .lines()
            .filter_map(|l| l.split_once(' ').map(|(_, rest)| rest))
            .collect();
        assert_eq!(
            lines,
            vec![
                "ERROR    conformance-rp-rust: access_denied x\\r\\nACCEPTED: authentication successful\\u{1b}[0m",
            ]
        );
        fs::remove_dir_all(&dir).expect("cleanup");
    }
}
