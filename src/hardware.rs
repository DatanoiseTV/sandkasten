//! Hardware-access presets. Each flag in `[hardware]` expands into the
//! right FS paths, Mach services, and flags for the target platform.

use crate::config::Profile;

pub fn expand(p: &mut Profile) {
    if p.hardware.usb            { apply_usb(p); }
    if p.hardware.serial         { apply_serial(p); }
    if p.hardware.audio          { apply_audio(p); }
    if p.hardware.gpu            { apply_gpu(p); }
    if p.hardware.camera         { apply_camera(p); }
    if p.hardware.screen_capture { apply_screen_capture(p); }
    apply_video_controls(p);
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
        // ALSA raw device nodes.
        add_rw(p, "/dev/snd");

        // Shared memory — JACK, GStreamer, PipeWire all use it. POSIX shm
        // objects live under /dev/shm; SysV IPC controllers are covered
        // by allow_ipc below.
        add_rw(p, "/dev/shm");
        p.system.allow_ipc = true;

        // PulseAudio native socket: /run/user/<uid>/pulse/native
        // PipeWire socket:          /run/user/<uid>/pipewire-0
        // $XDG_RUNTIME_DIR is usually /run/user/<uid>, so granting the
        // parent covers both.
        add_rw(p, "/run/user");

        // Pulse/Pipewire read configs from /etc + ~/.config
        add_r(p, "/etc/pulse");
        add_r(p, "/etc/pipewire");
        add_r(p, "/etc/asound.conf");
        add_r(p, "/usr/share/alsa");
        add_r(p, "/usr/share/pulseaudio");
        add_r(p, "/usr/share/pipewire");
        add_r(p, "/sys/class/sound");
        add_r(p, "/proc/asound");

        // Client-side config.
        for home_rel in [".config/pulse", ".config/pipewire",
                         ".config/alsa", ".asoundrc"] {
            if let Some(h) = dirs::home_dir() {
                let full = h.join(home_rel);
                let s = full.to_string_lossy().into_owned();
                if home_rel == ".asoundrc" || home_rel.starts_with(".config/") {
                    // Caches/state can be read-only; Pulse writes
                    // $XDG_RUNTIME_DIR not $HOME/.config.
                    add_r(p, &s);
                }
            }
        }

        // Unix-domain sockets for Pulse/Pipewire/JACK IPC.
        p.network.allow_unix_sockets = true;
    }
    #[cfg(target_os = "macos")]
    {
        p.system.allow_iokit = true;
        add_mach(p, "com.apple.audio.coreaudiod");
        add_mach(p, "com.apple.audio.audiohald");
        add_mach(p, "com.apple.audio.SystemSoundServer-OSX");
        add_mach(p, "com.apple.audio.AudioQueueServer");
        add_mach(p, "com.apple.audio.DriverHelper");
        add_mach(p, "com.apple.audio.AudioSession");
        add_mach(p, "com.apple.midiserver");
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
        // Video4Linux exposes /dev/video*, /dev/media*, /dev/v4l*.
        add_rw(p, "/dev");
        add_r(p, "/sys/class/video4linux");
        add_r(p, "/sys/bus/media");
    }
    #[cfg(target_os = "macos")]
    {
        p.system.allow_iokit = true;
        add_mach(p, "com.apple.cmio.AssistantService");
        add_mach(p, "com.apple.cmio.VDCAssistant");
        add_mach(p, "com.apple.cmio.registerassistantservice");
        // AVFoundation's sample buffer pipeline.
        add_mach(p, "com.apple.cmio.CameraAssistant");
        add_mach(p, "com.apple.coremedia.videocompositor");
        add_mach(p, "com.apple.audio.mediaserverd");
    }
}

fn apply_screen_capture(p: &mut Profile) {
    #[cfg(target_os = "linux")]
    {
        // PipeWire screencast + wayland/X compositors. /dev/dri covers GPU
        // capture; /run/user for the PipeWire socket.
        add_rw(p, "/dev/dri");
        add_rw(p, "/run/user");
        p.network.allow_unix_sockets = true;
    }
    #[cfg(target_os = "macos")]
    {
        p.system.allow_iokit = true;
        add_mach(p, "com.apple.windowserver.active");
        add_mach(p, "com.apple.CoreDisplay.Notification");
        add_mach(p, "com.apple.cmio.ScreenCaptureAssistant");
        add_mach(p, "com.apple.screencaptureui");
        // ScreenCaptureKit service (macOS 12.3+).
        add_mach(p, "com.apple.ScreenCaptureKit.AgentBridge");
    }
}

/// Apply the `[hardware.video]` allowlist and redirect table. Converts
/// them into `filesystem.rewire` and `filesystem.hide` entries so the
/// downstream Linux mount layer does the actual work.
fn apply_video_controls(p: &mut Profile) {
    use crate::config::Rewire;

    // Redirects become rewire entries.
    let redirects: Vec<(String, String)> = p
        .hardware
        .video
        .redirect
        .clone()
        .into_iter()
        .collect();
    for (from, to) in redirects {
        if !p.filesystem.rewire.iter().any(|r| r.from == from) {
            p.filesystem.rewire.push(Rewire { from, to });
        }
    }

    // If a devices allowlist is set, hide every /dev/video*, /dev/media*,
    // /dev/v4l-subdev* that isn't listed. Enumeration runs on the host.
    let allow = &p.hardware.video.devices;
    if !allow.is_empty() {
        #[cfg(target_os = "linux")]
        {
            if let Ok(rd) = std::fs::read_dir("/dev") {
                for e in rd.flatten() {
                    let name = e.file_name();
                    let name_s = name.to_string_lossy().into_owned();
                    let is_video = name_s.starts_with("video")
                        || name_s.starts_with("media")
                        || name_s.starts_with("v4l-subdev");
                    if !is_video {
                        continue;
                    }
                    let full = format!("/dev/{name_s}");
                    if !allow.iter().any(|d| d == &full) {
                        if !p.filesystem.hide.iter().any(|x| x == &full) {
                            p.filesystem.hide.push(full);
                        }
                    }
                }
            }
        }
        // On macOS the camera is mediated by Mach services, not device
        // nodes — the allowlist is a no-op there with a soft-warning
        // deferred to run time.
    }
}
