//! FFI to Apple's Sandbox SPI.
//!
//! These symbols are exported from libSystem (always linked on macOS). They are
//! technically SPI — not stable API — but have been used unchanged by Chromium,
//! Firefox, and every sandboxed browser for well over a decade, and by Apple's
//! own daemons as a first-class policy enforcement mechanism.
//!
//! Policy evaluation happens in the kernel via the Mac OS X Policy Framework
//! (MACF), so there is no userspace interposition overhead.

use std::ffi::{c_char, c_int, c_void, CString};
use std::ptr;

extern "C" {
    /// Apply the given SBPL profile to the current process and all descendants.
    /// Returns 0 on success. On failure, writes a newly-allocated error string
    /// into `errorbuf` which must be freed with `sandbox_free_error`.
    fn sandbox_init(profile: *const c_char, flags: u64, errorbuf: *mut *mut c_char) -> c_int;

    /// Free an error buffer allocated by `sandbox_init`.
    fn sandbox_free_error(errorbuf: *mut c_char);
}

/// Apply an SBPL policy to the current process. Once applied, the policy cannot
/// be loosened — only tightened by a subsequent call. Children inherit.
pub fn apply(sbpl: &str) -> Result<(), String> {
    let c = CString::new(sbpl).map_err(|e| format!("profile contains NUL byte: {e}"))?;
    let mut errbuf: *mut c_char = ptr::null_mut();
    let rc = unsafe { sandbox_init(c.as_ptr(), 0, &mut errbuf) };
    if rc == 0 {
        return Ok(());
    }
    let msg = if errbuf.is_null() {
        format!("sandbox_init failed (rc={rc})")
    } else {
        let s = unsafe { std::ffi::CStr::from_ptr(errbuf) }
            .to_string_lossy()
            .into_owned();
        unsafe { sandbox_free_error(errbuf) };
        format!("sandbox_init failed (rc={rc}): {s}")
    };
    Err(msg)
}

// Silence unused warning if nothing else in the crate references this symbol.
#[allow(dead_code)]
pub(crate) fn _link_check() -> *const c_void {
    sandbox_init as *const c_void
}
