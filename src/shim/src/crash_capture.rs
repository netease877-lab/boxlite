//! Crash capture for shim process.
//!
//! Captures crash information (panics, signals) to an exit file for diagnostics.
//! Signal handlers can't capture closures, so we use global statics for paths.
//!
//! Note: Stderr content is captured separately by the parent process (to shim.stderr).
//! CrashReport reads it directly from file - we don't embed it in the exit file.
//!
//! Uses [`boxlite::vmm::ExitInfo`] for the JSON format.

use boxlite::vmm::ExitInfo;
use std::path::PathBuf;
use std::sync::OnceLock;

/// Unix convention: exit code for signal-terminated process = 128 + signal number.
const SIGNAL_EXIT_CODE_BASE: i32 = 128;

/// Exit code for Rust panics.
const PANIC_EXIT_CODE: i32 = 101;

/// Global exit file path for signal handlers.
static EXIT_FILE_PATH: OnceLock<PathBuf> = OnceLock::new();

/// Crash capture installer.
///
/// Installs panic hook and signal handlers to capture crash info.
pub struct CrashCapture;

impl CrashCapture {
    /// Install crash capture mechanisms (panic hook + signal handlers).
    ///
    /// - `exit_file`: Where to write crash info (JSON format)
    pub fn install(exit_file: PathBuf) {
        install_panic_hook(exit_file.clone());
        install_signal_handlers(exit_file);
    }
}

/// Install panic hook that writes JSON to exit file AND log.
fn install_panic_hook(exit_file: PathBuf) {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        let message = panic_info
            .payload()
            .downcast_ref::<&str>()
            .map(|s| s.to_string())
            .or_else(|| panic_info.payload().downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "Unknown panic".into());

        let location = panic_info
            .location()
            .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
            .unwrap_or_else(|| "unknown".into());

        tracing::error!(message = %message, location = %location, "PANIC");

        let info = ExitInfo::Panic {
            exit_code: PANIC_EXIT_CODE,
            message,
            location,
        };
        if let Ok(json) = serde_json::to_string(&info) {
            let _ = std::fs::write(&exit_file, json);
        }

        default_hook(panic_info);
    }));
}

/// Install Unix signal handlers to catch C library crashes.
fn install_signal_handlers(exit_file: PathBuf) {
    let _ = EXIT_FILE_PATH.set(exit_file);

    unsafe {
        libc::signal(libc::SIGABRT, crash_signal_handler as *const () as usize);
        libc::signal(libc::SIGSEGV, crash_signal_handler as *const () as usize);
        libc::signal(libc::SIGBUS, crash_signal_handler as *const () as usize);
        libc::signal(libc::SIGILL, crash_signal_handler as *const () as usize);
        // SIGSYS fallback via signal(2) first: glibc sets up its own signal
        // restorer, so this registration always works — it just can't deliver
        // siginfo. The sigaction registration below overwrites it when it
        // succeeds.
        libc::signal(libc::SIGSYS, crash_signal_handler as *const () as usize);
        // SIGSYS goes through a sigaction handler with SA_SIGINFO: seccomp's
        // `trap` verdict fills siginfo with the offending syscall number
        // (si_syscall), which plain `signal(2)` cannot deliver. The libc
        // crate's `sigaction` is the raw rt_sigaction syscall, and the kernel
        // requires SA_RESTORER with a valid restorer on x86_64 — without it
        // the call fails with EINVAL and the fallback above stays in effect.
        let mut act: libc::sigaction = std::mem::zeroed();
        // The libc crate hides SA_RESTORER on gnu targets (its own sigaction
        // wrapper handles restorers for Rust users); the raw value is 0x04000000.
        const SA_RESTORER: libc::c_int = 0x0400_0000;
        act.sa_flags = libc::SA_SIGINFO | libc::SA_NODEFER | SA_RESTORER;
        act.sa_sigaction = sigsys_handler as usize;
        act.sa_restorer = Some(sigsys_restorer);
        libc::sigemptyset(&mut act.sa_mask);
        let rc = libc::sigaction(libc::SIGSYS, &act, std::ptr::null_mut());
        if rc != 0 {
            tracing::warn!(
                "sigaction(SIGSYS) failed; falling back to plain signal handler \
                 (no seccomp syscall number will be recorded)"
            );
        }
    }
}

/// Signal trampoline for the raw `rt_sigaction` registration. The kernel
/// jumps here after a handler returns; only the four-arg `rt_sigreturn`
/// syscall restores the interrupted context.
extern "C" fn sigsys_restorer() {
    unsafe {
        libc::syscall(libc::SYS_rt_sigreturn);
    }
}

/// siginfo shape the kernel delivers for a synchronous SIGSYS from seccomp
/// (`SECCOMP_RET_TRAP`). Only the `_sigsys` member matters here.
#[repr(C)]
struct SigSysInfo {
    si_signo: libc::c_int,
    si_errno: libc::c_int,
    si_code: libc::c_int,
    // _sifields._sigsys:
    _call_addr: *const libc::c_void,
    si_syscall: libc::c_int,
    si_arch: libc::c_uint,
}

/// SA_SIGINFO handler for SIGSYS: record the seccomp-killed syscall number in
/// the exit file, then chain into the shared crash path. Runs inside a seccomp
/// `trap` context, so only async-signal-safe operations are used (raw
/// decimal formatting into a stack buffer, open/write/close).
extern "C" fn sigsys_handler(
    sig: libc::c_int,
    info: *mut libc::siginfo_t,
    _ucontext: *mut libc::c_void,
) {
    const SYS_NUMBER_MAX_DIGITS: usize = 7;

    let syscall_no = unsafe { (*(info as *const SigSysInfo)).si_syscall };

    if let Some(exit_file) = EXIT_FILE_PATH.get() {
        // Reuse the exit file name with a fixed suffix; the JSON crash record
        // written below by crash_signal_handler remains intact.
        let mut path = exit_file.clone();
        path.set_extension("sigsys");
        let mut path_buf = [0u8; libc::PATH_MAX as usize];
        let name = path.as_os_str().as_encoded_bytes();
        let name_len = name.len().min(path_buf.len() - 1);
        path_buf[..name_len].copy_from_slice(&name[..name_len]);
        path_buf[name_len] = 0;

        let mut body = [0u8; 64];
        let mut used = 0;
        used += b"{\"seccomp_syscall\":".len();
        body[..used].copy_from_slice(b"{\"seccomp_syscall\":");
        let mut digits = [0u8; SYS_NUMBER_MAX_DIGITS];
        let mut n = syscall_no as u32;
        let mut d = 0;
        loop {
            digits[d] = b'0' + (n % 10) as u8;
            n /= 10;
            d += 1;
            if n == 0 {
                break;
            }
        }
        for digit in digits[..d].iter().rev() {
            body[used] = *digit;
            used += 1;
        }
        body[used] = b'}';
        used += 1;

        let fd = unsafe {
            libc::open(path_buf.as_ptr() as *const libc::c_char, libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC, 0o644)
        };
        if fd >= 0 {
            let mut written = 0;
            while written < used {
                let w = unsafe { libc::write(fd, body[written..used].as_ptr() as *const libc::c_void, used - written) };
                if w <= 0 {
                    break;
                }
                written += w as usize;
            }
            unsafe { libc::close(fd) };
        }
    }

    crash_signal_handler(sig);
}

/// Signal handler that writes JSON crash info to exit file.
///
/// Note: We intentionally don't read stderr here. Signal handlers should be
/// minimal and avoid async-signal-unsafe operations. CrashReport reads stderr
/// directly from the file when formatting the error message.
extern "C" fn crash_signal_handler(sig: libc::c_int) {
    let signal = match sig {
        libc::SIGABRT => "SIGABRT",
        libc::SIGSEGV => "SIGSEGV",
        libc::SIGBUS => "SIGBUS",
        libc::SIGILL => "SIGILL",
        libc::SIGSYS => "SIGSYS",
        _ => "UNKNOWN",
    };

    if let Some(exit_file) = EXIT_FILE_PATH.get() {
        let info = ExitInfo::Signal {
            exit_code: SIGNAL_EXIT_CODE_BASE + sig,
            signal: signal.to_string(),
        };
        if let Ok(json) = serde_json::to_string(&info) {
            let _ = std::fs::write(exit_file, json);
        }
    }

    unsafe {
        libc::signal(sig, libc::SIG_DFL);
        libc::raise(sig);
    }
}
