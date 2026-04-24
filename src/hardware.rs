//! Hardware-access presets. Each flag in `[hardware]` expands into the
//! right FS paths, Mach services, and flags for the target platform.

use crate::config::Profile;

pub fn expand(p: &mut Profile) {
    if p.hardware.usb       { apply_usb(p); }
    if p.hardware.serial    { apply_serial(p); }
    if p.hardware.audio     { apply_audio(p); }
    if p.hardware.gpu       { apply_gpu(p); }
    if p.hardware.camera    { apply_camera(p); }
}

fn add_rw(p: &mut Profile, path: &str) {
    if !p.filesystem.read_write.iter().any(|x| x == path) {
        p.filesystem.read_write.push(path.to_string());
    }
}
#[cfg(target_os = "linux")]
fn add_r(p: &mut Profile, path: &str) {
    if !p.filesystem.read.iter().any(|x| x == path) {
        p.filesystem.read.push(path.to_string());
    }
}
fn add_rw_file(p: &mut Profile, path: &str) {
    if !p.filesystem.read_write_files.iter().any(|x| x == path) {
        p.filesystem.read_write_files.push(path.to_string());
    }
}
fn add_mach(p: &mut Profile, svc: &str) {
    if !p.system.mach_services.iter().any(|x| x == svc) {
        p.system.mach_services.push(svc.to_string());
    }
}

// ─── USB / libusb ───────────────────────────────────────────────────────

fn apply_usb(p: &mut Profile) {
    #[cfg(target_os = "linux")]
    {
        // libusb on Linux opens /dev/bus/usb/<bus>/<dev> character devices.
        add_rw(p, "/dev/bus/usb");
        // Some libusb backends also read udev state + /sys for device enumeration.
        add_r(p, "/sys/bus/usb");
        add_r(p, "/sys/class/usb");
        add_r(p, "/sys/devices");
        add_r(p, "/run/udev/data");
        add_r(p, "/proc/bus/usb"); // legacy enumeration
        p.system.allow_sysctl_read = true;
    }
    #[cfg(target_os = "macos")]
    {
        p.system.allow_iokit = true;
        // These are the Mach services IOKit + the USB family publish on.
        // List is derived from Apple's documented USB driver bundles.
        add_mach(p, "com.apple.driver.usb.IOUSBHostFamily");
        add_mach(p, "com.apple.driver.IOUSBHostFamily");
        add_mach(p, "com.apple.IOUSBUserClient");
        add_mach(p, "com.apple.usbmuxd");
    }
    // These are universal conveniences whichever OS.
    add_rw_file(p, "/dev/null");
}

// ─── Serial ─────────────────────────────────────────────────────────────

fn apply_serial(p: &mut Profile) {
    #[cfg(target_os = "linux")]
    {
        // Serial node families: ttyS*, ttyUSB*, ttyACM*, ttyAMA*, ttyXRUSB*.
        // Landlock is allow-list; we can't glob, so expose /dev subtree as rw.
        add_rw(p, "/dev");
        add_r(p, "/sys/class/tty");
    }
    #[cfg(target_os = "macos")]
    {
        // /dev/cu.usbserial* and /dev/tty.usbserial* show up as literal nodes
        // under /dev. We read+write /dev here — narrower profiles can override.
        add_rw(p, "/dev");
        p.system.allow_iokit = true;
        add_mach(p, "com.apple.driver.AppleUSBSerial");
    }
}

// ─── Audio ──────────────────────────────────────────────────────────────

fn apply_audio(p: &mut Profile) {
    #[cfg(target_os = "linux")]
    {
        add_rw(p, "/dev/snd");
        // PulseAudio/PipeWire socket lives under /run/user/<uid>/.
        add_rw(p, "/run/user");
        add_r(p, "/sys/class/sound");
        p.network.allow_unix_sockets = true;
    }
    #[cfg(target_os = "macos")]
    {
        p.system.allow_iokit = true;
        add_mach(p, "com.apple.audio.coreaudiod");
        add_mach(p, "com.apple.audio.audiohald");
        add_mach(p, "com.apple.audio.SystemSoundServer-OSX");
    }
}

// ─── GPU ────────────────────────────────────────────────────────────────

fn apply_gpu(p: &mut Profile) {
    #[cfg(target_os = "linux")]
    {
        add_rw(p, "/dev/dri");
        add_r(p, "/sys/class/drm");
        add_r(p, "/sys/devices");
        // Shader caches
        add_rw(p, "/tmp");
    }
    #[cfg(target_os = "macos")]
    {
        p.system.allow_iokit = true;
        add_mach(p, "com.apple.iokit.IOAcceleratorFamily2");
        add_mach(p, "com.apple.Metal");
        add_mach(p, "com.apple.MetalPerformanceShaders");
        add_mach(p, "com.apple.CoreDisplay.Notification");
    }
}

// ─── Camera ─────────────────────────────────────────────────────────────

fn apply_camera(p: &mut Profile) {
    #[cfg(target_os = "linux")]
    {
        // Video4Linux exposes /dev/video*, /dev/media*.
        add_rw(p, "/dev");
        add_r(p, "/sys/class/video4linux");
    }
    #[cfg(target_os = "macos")]
    {
        p.system.allow_iokit = true;
        add_mach(p, "com.apple.cmio.AssistantService");
        add_mach(p, "com.apple.cmio.VDCAssistant");
        add_mach(p, "com.apple.cmio.registerassistantservice");
    }
}
