import SwiftUI

// ──────────────────────────────────────────────────────────────────────
// The structured editor. Renders every profile section as native macOS
// form widgets. Edits are mirrored back into `store.rawToml` via the
// Profile round-trip so the "TOML" tab and the on-disk file stay in
// sync. Built-in templates render read-only.
//
// Every section lives in its own small view so navigation + collapse
// work naturally via DisclosureGroup. Widgets chosen to feel native:
//
//   * Toggle            – bool flags
//   * TextField         – strings, with a .help() tooltip for context
//   * NumberField       – thin wrapper giving us Int? binding with
//                         an "off" chip so optional limits stay nil
//   * StringList        – add/remove + inline editing for list fields
//   * KVPairs           – [String: String] editor (env.set, dmi, etc.)
//   * ChipPicker        – multi-select with the sandkasten preset names
//
// Read-only detection happens once at the top; sub-views receive the
// resulting ViewModifier.
// ──────────────────────────────────────────────────────────────────────

struct FormView: View {
    @EnvironmentObject var store: ProfileStore
    let readonly: Bool

    var body: some View {
        ScrollView(.vertical) {
            VStack(alignment: .leading, spacing: 16) {
                // Banners live OUTSIDE the `.disabled(readonly)` scope so
                // their Copy / Open-log buttons stay interactive even
                // while the form fields below are locked.
                if let err = store.parseError {
                    TomlParseError(message: err)
                }
                if !store.profile.parseWarnings.isEmpty {
                    TomlParseWarnings(messages: store.profile.parseWarnings)
                }

                Group {
                    IdentitySection()
                    FilesystemSection()
                    NetworkSection()
                    ProcessSystemEnvSection()
                    LimitsSection()
                    HardwareSection()
                    SpoofSection()
                    WorkspaceOverlayMocksSection()
                }
                .disabled(readonly)
            }
            .padding(.horizontal, 24)
            .padding(.vertical, 18)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(.background)
    }
}

private struct TomlParseError: View {
    let message: String

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: "exclamationmark.triangle.fill")
                .foregroundStyle(.orange)
            VStack(alignment: .leading, spacing: 2) {
                Text("TOML parse error — form is showing the last successfully-parsed state")
                    .font(.callout.weight(.medium))
                Text(message)
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
            }
        }
        .padding(12)
        .background(
            RoundedRectangle(cornerRadius: 8, style: .continuous)
                .fill(Color.orange.opacity(0.08))
        )
        .overlay(
            RoundedRectangle(cornerRadius: 8, style: .continuous)
                .strokeBorder(Color.orange.opacity(0.4), lineWidth: 1)
        )
    }
}

private struct TomlParseWarnings: View {
    let messages: [String]

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: "info.circle.fill")
                .foregroundStyle(.yellow)
            VStack(alignment: .leading, spacing: 6) {
                Text("Some sections couldn't be parsed — they've been reset to defaults. The rest of the profile loaded fine.")
                    .font(.callout.weight(.medium))
                ForEach(messages, id: \.self) { m in
                    Text(m)
                        .font(.caption.monospaced())
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                }
                HStack(spacing: 12) {
                    Button {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(messages.joined(separator: "\n"),
                                                        forType: .string)
                    } label: { Label("Copy warnings", systemImage: "doc.on.doc") }
                    .buttonStyle(.bordered)
                    .controlSize(.small)
                    Button {
                        NSWorkspace.shared.open(URL(fileURLWithPath: "/tmp/sandkasten-ui.log"))
                    } label: { Label("Open debug log", systemImage: "doc.text.magnifyingglass") }
                    .buttonStyle(.bordered)
                    .controlSize(.small)
                    Text("/tmp/sandkasten-ui.log")
                        .font(.caption2.monospaced())
                        .foregroundStyle(.tertiary)
                        .textSelection(.enabled)
                }
                .padding(.top, 4)
            }
        }
        .padding(12)
        .background(
            RoundedRectangle(cornerRadius: 8, style: .continuous)
                .fill(Color.yellow.opacity(0.08))
        )
        .overlay(
            RoundedRectangle(cornerRadius: 8, style: .continuous)
                .strokeBorder(Color.yellow.opacity(0.4), lineWidth: 1)
        )
    }
}

// ─── Identity ─────────────────────────────────────────────────────────

private struct IdentitySection: View {
    @EnvironmentObject var store: ProfileStore

    var body: some View {
        SectionCard(title: "Identity", symbol: "tag.fill") {
            LabeledTextField(
                label: "Name",
                placeholder: "my-profile",
                text: Binding(
                    get: { store.profile.name ?? "" },
                    set: { store.profile.name = $0.isEmpty ? nil : $0
                           store.reserializeFromForm() }
                )
            )
            LabeledTextField(
                label: "Description",
                placeholder: "What this profile is for",
                text: Binding(
                    get: { store.profile.description ?? "" },
                    set: { store.profile.description = $0.isEmpty ? nil : $0
                           store.reserializeFromForm() }
                )
            )
            LabeledTextField(
                label: "Extends",
                placeholder: "strict / self / minimal-cli / browser / …",
                text: Binding(
                    get: { store.profile.extends ?? "" },
                    set: { store.profile.extends = $0.isEmpty ? nil : $0
                           store.reserializeFromForm() }
                )
            )
        }
    }
}

// ─── Filesystem ───────────────────────────────────────────────────────

private struct FilesystemSection: View {
    @EnvironmentObject var store: ProfileStore

    var body: some View {
        SectionCard(title: "Filesystem", symbol: "folder.fill") {
            Toggle("Allow metadata reads on any path", isOn: bind(
                \.filesystem.allow_metadata_read,
                fallback: true))
                .toggleStyle(.switch)
                .help("stat / readdir on any path — most binaries need this")

            StringListEditor(
                title: "Read (subpaths)",
                help: "Directories the sandbox can read recursively",
                placeholder: "/usr/lib",
                values: bind(\.filesystem.read))

            StringListEditor(
                title: "Read + Write (subpaths)",
                help: "Writable directories. ${CWD}, ${HOME}, ~ are expanded at runtime.",
                placeholder: "${CWD}",
                values: bind(\.filesystem.read_write))

            StringListEditor(
                title: "Read (single files)",
                placeholder: "/etc/hosts",
                values: bind(\.filesystem.read_files))

            StringListEditor(
                title: "Read + Write (single files)",
                placeholder: "/dev/null",
                values: bind(\.filesystem.read_write_files))

            StringListEditor(
                title: "Deny",
                help: "Overrides any allow above. Evaluated last.",
                placeholder: "${HOME}/.ssh",
                values: bind(\.filesystem.deny),
                accent: .red)

            StringListEditor(
                title: "Hide",
                help: "Linux only. tmpfs bind-mount over dirs, /dev/null over files.",
                placeholder: "/etc/shadow",
                values: bind(\.filesystem.hide))

            FileRulesEditor()
            RewireEditor()
        }
    }

    private func bind<V>(_ key: WritableKeyPath<Profile, V>, fallback: V? = nil) -> Binding<V> {
        Binding(
            get: { store.profile[keyPath: key] },
            set: { store.profile[keyPath: key] = $0; store.reserializeFromForm() }
        )
    }
}

private struct FileRulesEditor: View {
    @EnvironmentObject var store: ProfileStore
    private let knownOps = ["read", "write", "create", "delete", "rename",
                            "chmod", "chown", "xattr", "ioctl", "exec"]

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("Fine-grained rules")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.secondary)
                Spacer()
                Button {
                    store.profile.filesystem.rules.append(FileRule())
                    store.reserializeFromForm()
                } label: {
                    Label("Add", systemImage: "plus")
                        .labelStyle(.iconOnly)
                }
                .buttonStyle(.borderless)
                .help("Add a per-path rule")
            }
            if store.profile.filesystem.rules.isEmpty {
                Text("No fine-grained rules.")
                    .font(.caption)
                    .foregroundStyle(.tertiary)
            }
            ForEach(store.profile.filesystem.rules.indices, id: \.self) { idx in
                FileRuleRow(idx: idx, knownOps: knownOps)
            }
        }
        .padding(.top, 6)
    }
}

private struct FileRuleRow: View {
    let idx: Int
    let knownOps: [String]
    @EnvironmentObject var store: ProfileStore

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 10) {
                TextField("/path/to/file", text: Binding(
                    get: { store.profile.filesystem.rules[idx].path },
                    set: { store.profile.filesystem.rules[idx].path = $0
                           store.reserializeFromForm() }
                ))
                .textFieldStyle(.roundedBorder)
                .font(.system(.callout, design: .monospaced))

                Toggle("Literal", isOn: Binding(
                    get: { store.profile.filesystem.rules[idx].literal },
                    set: { store.profile.filesystem.rules[idx].literal = $0
                           store.reserializeFromForm() }
                ))
                .toggleStyle(.checkbox)
                .help("Match the exact file only, not a subtree")

                Button(role: .destructive) {
                    store.profile.filesystem.rules.remove(at: idx)
                    store.reserializeFromForm()
                } label: {
                    Image(systemName: "xmark.circle.fill")
                        .foregroundStyle(.secondary)
                }
                .buttonStyle(.borderless)
            }

            HStack(alignment: .top, spacing: 24) {
                opChipSet(title: "Allow", tint: .green,
                          values: Binding(
                            get: { store.profile.filesystem.rules[idx].allow },
                            set: { store.profile.filesystem.rules[idx].allow = $0
                                   store.reserializeFromForm() }))
                opChipSet(title: "Deny", tint: .red,
                          values: Binding(
                            get: { store.profile.filesystem.rules[idx].deny },
                            set: { store.profile.filesystem.rules[idx].deny = $0
                                   store.reserializeFromForm() }))
            }
        }
        .padding(12)
        .background(
            RoundedRectangle(cornerRadius: 8, style: .continuous)
                .fill(Color(nsColor: .controlBackgroundColor))
        )
    }

    private func opChipSet(title: String, tint: Color, values: Binding<[String]>) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title.uppercased())
                .font(.caption2.weight(.semibold))
                .foregroundStyle(.secondary)
                .tracking(0.8)
            FlowLayout(spacing: 6) {
                ForEach(knownOps, id: \.self) { op in
                    let on = values.wrappedValue.contains(op)
                    Button {
                        var v = values.wrappedValue
                        if on { v.removeAll { $0 == op } }
                        else   { v.append(op) }
                        values.wrappedValue = v
                    } label: {
                        Text(op)
                            .font(.caption.weight(.medium))
                            .padding(.horizontal, 9)
                            .padding(.vertical, 3)
                            .foregroundStyle(on ? .white : Color(nsColor: .labelColor))
                            .background(
                                Capsule()
                                    .fill(on ? tint.opacity(0.85) : Color.secondary.opacity(0.12))
                            )
                            .overlay(
                                Capsule()
                                    .strokeBorder(on ? tint.opacity(0.95) : Color.secondary.opacity(0.25),
                                                  lineWidth: 0.5)
                            )
                    }
                    .buttonStyle(.plain)
                }
            }
        }
    }
}

private struct RewireEditor: View {
    @EnvironmentObject var store: ProfileStore

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("Path rewires (Linux bind-mount)")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.secondary)
                Spacer()
                Button {
                    store.profile.filesystem.rewire.append(Rewire())
                    store.reserializeFromForm()
                } label: { Label("Add", systemImage: "plus").labelStyle(.iconOnly) }
                .buttonStyle(.borderless)
            }
            if store.profile.filesystem.rewire.isEmpty {
                Text("Inside the sandbox, A actually points to B.")
                    .font(.caption)
                    .foregroundStyle(.tertiary)
            }
            ForEach(store.profile.filesystem.rewire.indices, id: \.self) { idx in
                HStack(spacing: 8) {
                    TextField("from", text: Binding(
                        get: { store.profile.filesystem.rewire[idx].from },
                        set: { store.profile.filesystem.rewire[idx].from = $0
                               store.reserializeFromForm() }))
                    .textFieldStyle(.roundedBorder)
                    Image(systemName: "arrow.right")
                        .foregroundStyle(.secondary)
                    TextField("to", text: Binding(
                        get: { store.profile.filesystem.rewire[idx].to },
                        set: { store.profile.filesystem.rewire[idx].to = $0
                               store.reserializeFromForm() }))
                    .textFieldStyle(.roundedBorder)
                    Button {
                        store.profile.filesystem.rewire.remove(at: idx)
                        store.reserializeFromForm()
                    } label: { Image(systemName: "xmark.circle.fill") }
                    .buttonStyle(.borderless)
                    .foregroundStyle(.secondary)
                }
                .font(.system(.callout, design: .monospaced))
            }
        }
        .padding(.top, 6)
    }
}

// ─── Network ──────────────────────────────────────────────────────────

private struct NetworkSection: View {
    @EnvironmentObject var store: ProfileStore
    private let allPresets: [String] = [
        "http", "https", "quic", "web",
        "rtp", "sip", "stun", "webrtc",
        "ssh", "rdp", "vnc",
        "smtp", "smtps", "imap", "imaps", "pop3", "pop3s",
        "ftp", "ftps", "sftp", "git",
        "ldap", "ldaps", "kerberos",
        "mysql", "postgres", "redis", "memcached", "mongodb",
        "irc", "ircs", "xmpp", "matrix", "mqtt", "mqtts",
        "ntp", "mdns", "dhcp", "dns", "ping",
        "wireguard", "openvpn", "tailscale", "ipsec",
        "minecraft", "minecraft-bedrock", "steam", "source-engine",
        "discord-voice", "teamspeak",
        "tcpdump", "pcap", "nmap",
    ]

    var body: some View {
        SectionCard(title: "Network", symbol: "network") {
            LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())],
                      alignment: .leading, spacing: 6) {
                toggle("Localhost",       \.network.allow_localhost, help: "127.0.0.1, ::1")
                toggle("DNS",             \.network.allow_dns, help: "UDP/TCP :53")
                toggle("Inbound",         \.network.allow_inbound)
                toggle("UNIX sockets",    \.network.allow_unix_sockets)
                toggle("ICMP",            \.network.allow_icmp, help: "ping, traceroute")
                toggle("ICMPv6",          \.network.allow_icmpv6)
                toggle("SCTP",            \.network.allow_sctp)
                toggle("DCCP",            \.network.allow_dccp)
                toggle("UDP-Lite",        \.network.allow_udplite)
                toggle("Raw sockets",     \.network.allow_raw_sockets, help: "privileged — packet crafting")
            }

            StringListEditor(
                title: "Outbound TCP",
                help: "host:port, *:443, 192.168.1.0/24:*",
                placeholder: "*:443",
                values: bind(\.network.outbound_tcp))

            StringListEditor(title: "Outbound UDP", placeholder: "*:53",
                             values: bind(\.network.outbound_udp))

            StringListEditor(title: "Inbound TCP",
                             values: bind(\.network.inbound_tcp))

            StringListEditor(title: "Inbound UDP",
                             values: bind(\.network.inbound_udp))

            StringListEditor(title: "Extra protocols (Linux)",
                             placeholder: "sctp",
                             values: bind(\.network.extra_protocols))

            PresetPicker(title: "Presets",
                         all: allPresets,
                         selected: bind(\.network.presets))

            // DNS + hosts + proxy sub-editors
            SubGroup("DNS override") {
                StringListEditor(title: "Servers",
                                 placeholder: "1.1.1.1",
                                 values: bind(\.network.dns.servers))
                StringListEditor(title: "Search domains",
                                 placeholder: "corp.internal",
                                 values: bind(\.network.dns.search))
                StringListEditor(title: "Options",
                                 placeholder: "edns0",
                                 values: bind(\.network.dns.options))
            }

            SubGroup("/etc/hosts entries") {
                KVPairsEditor(keyLabel: "hostname",
                              valueLabel: "IP",
                              pairs: bind(\.network.hosts_entries))
            }

            SubGroup("Proxy") {
                LabeledTextField(
                    label: "URL",
                    placeholder: "http://127.0.0.1:8080",
                    text: Binding(
                        get: { store.profile.network.proxy.url ?? "" },
                        set: { store.profile.network.proxy.url = $0.isEmpty ? nil : $0
                               store.reserializeFromForm() }))
                StringListEditor(title: "Bypass",
                                 placeholder: "127.0.0.1",
                                 values: bind(\.network.proxy.bypass))
                Toggle("Restrict outbound to proxy", isOn: bind(\.network.proxy.restrict_outbound))
                    .toggleStyle(.switch)
                    .help("Narrow outbound_tcp to just the proxy host:port")
            }

            SubGroup("External (Linux)") {
                LabeledTextField(
                    label: "external",
                    placeholder: "host / none / pasta",
                    text: Binding(
                        get: { store.profile.network.external ?? "" },
                        set: { store.profile.network.external = $0.isEmpty ? nil : $0
                               store.reserializeFromForm() }))
                LabeledTextField(
                    label: "netns_path",
                    placeholder: "/run/netns/vpn",
                    text: Binding(
                        get: { store.profile.network.netns_path ?? "" },
                        set: { store.profile.network.netns_path = $0.isEmpty ? nil : $0
                               store.reserializeFromForm() }))
            }
        }
    }

    private func toggle(_ label: String, _ keyPath: WritableKeyPath<Profile, Bool>, help: String? = nil) -> some View {
        Toggle(label, isOn: bind(keyPath))
            .toggleStyle(.switch)
            .help(help ?? "")
    }

    private func bind<V>(_ key: WritableKeyPath<Profile, V>) -> Binding<V> {
        Binding(
            get: { store.profile[keyPath: key] },
            set: { store.profile[keyPath: key] = $0; store.reserializeFromForm() }
        )
    }
}

// ─── Process / System / Env ────────────────────────────────────────────

private struct ProcessSystemEnvSection: View {
    @EnvironmentObject var store: ProfileStore

    var body: some View {
        SectionCard(title: "Process / System / Env", symbol: "cpu") {
            VStack(alignment: .leading, spacing: 14) {
                SubGroup("Process") {
                    Toggle("Allow fork", isOn: bind(\.process.allow_fork)).toggleStyle(.switch)
                    Toggle("Allow exec", isOn: bind(\.process.allow_exec)).toggleStyle(.switch)
                    Toggle("Allow signal self", isOn: bind(\.process.allow_signal_self)).toggleStyle(.switch)
                }
                SubGroup("System") {
                    Toggle("Allow sysctl read", isOn: bind(\.system.allow_sysctl_read)).toggleStyle(.switch)
                    Toggle("Allow IOKit", isOn: bind(\.system.allow_iokit)).toggleStyle(.switch)
                    Toggle("Allow POSIX IPC", isOn: bind(\.system.allow_ipc)).toggleStyle(.switch)
                    Toggle("Allow ALL Mach services (macOS)", isOn: bind(\.system.allow_mach_all))
                        .toggleStyle(.switch)
                        .help("Broad — needed by Chromium/Electron apps")
                    StringListEditor(title: "Explicit Mach services",
                                     placeholder: "com.apple.system.logger",
                                     values: bind(\.system.mach_services))
                }
                SubGroup("Environment") {
                    Toggle("Pass all env vars", isOn: bind(\.env.pass_all)).toggleStyle(.switch)
                    StringListEditor(title: "Forward specific",
                                     placeholder: "PATH",
                                     values: bind(\.env.pass))
                    KVPairsEditor(keyLabel: "name",
                                  valueLabel: "value",
                                  pairs: bind(\.env.set))
                }
            }
        }
    }

    private func bind<V>(_ key: WritableKeyPath<Profile, V>) -> Binding<V> {
        Binding(
            get: { store.profile[keyPath: key] },
            set: { store.profile[keyPath: key] = $0; store.reserializeFromForm() }
        )
    }
}

// ─── Limits ───────────────────────────────────────────────────────────

private struct LimitsSection: View {
    @EnvironmentObject var store: ProfileStore

    var body: some View {
        SectionCard(title: "Resource limits", symbol: "gauge.with.dots.needle.67percent") {
            LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())],
                      alignment: .leading, spacing: 12) {
                NumberField("CPU seconds",  bind(\.limits.cpu_seconds))
                NumberField("Memory (MB)",  bind(\.limits.memory_mb))
                NumberField("File size (MB)", bind(\.limits.file_size_mb))
                NumberField("Open FDs",     bind(\.limits.open_files))
                NumberField("Max processes", bind(\.limits.processes))
                NumberField("Stack (MB)",   bind(\.limits.stack_mb))
                NumberField("Wall timeout (s)", bind(\.limits.wall_timeout_seconds))
            }
            Toggle("Allow core dumps", isOn: bind(\.limits.core_dumps))
                .toggleStyle(.switch)
                .help("Off (default) — RLIMIT_CORE = 0 so crashes can't spill memory to disk")
        }
    }

    private func bind<V>(_ key: WritableKeyPath<Profile, V>) -> Binding<V> {
        Binding(
            get: { store.profile[keyPath: key] },
            set: { store.profile[keyPath: key] = $0; store.reserializeFromForm() }
        )
    }
}

// ─── Hardware ─────────────────────────────────────────────────────────

private struct HardwareSection: View {
    @EnvironmentObject var store: ProfileStore

    var body: some View {
        SectionCard(title: "Hardware access", symbol: "wrench.and.screwdriver.fill") {
            LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())],
                      alignment: .leading, spacing: 6) {
                Toggle("USB / libusb",          isOn: bind(\.hardware.usb)).toggleStyle(.switch)
                Toggle("Serial (/dev/tty*)",    isOn: bind(\.hardware.serial)).toggleStyle(.switch)
                Toggle("Audio (ALSA/Pulse/PW)", isOn: bind(\.hardware.audio)).toggleStyle(.switch)
                Toggle("GPU / Metal",           isOn: bind(\.hardware.gpu)).toggleStyle(.switch)
                Toggle("Camera / V4L2",         isOn: bind(\.hardware.camera)).toggleStyle(.switch)
                Toggle("Screen capture",        isOn: bind(\.hardware.screen_capture)).toggleStyle(.switch)
            }
            SubGroup("Video devices") {
                StringListEditor(title: "Allow list",
                                 placeholder: "/dev/video0",
                                 values: bind(\.hardware.video.devices))
                KVPairsEditor(keyLabel: "in-sandbox",
                              valueLabel: "host",
                              pairs: bind(\.hardware.video.redirect))
            }
        }
    }

    private func bind<V>(_ key: WritableKeyPath<Profile, V>) -> Binding<V> {
        Binding(
            get: { store.profile[keyPath: key] },
            set: { store.profile[keyPath: key] = $0; store.reserializeFromForm() }
        )
    }
}

// ─── Spoof ────────────────────────────────────────────────────────────

private struct SpoofSection: View {
    @EnvironmentObject var store: ProfileStore

    var body: some View {
        SectionCard(title: "Identity spoofing", symbol: "theatermasks.fill") {
            LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())],
                      alignment: .leading, spacing: 10) {
                NumberField("CPU count", bind(\.spoof.cpu_count))
                Toggle("Synth /proc/cpuinfo", isOn: bind(\.spoof.cpuinfo_synth)).toggleStyle(.switch)
                LabeledTextField(label: "cpuinfo model",
                                 placeholder: "CustomCPU 2.0",
                                 text: optBind(\.spoof.cpuinfo_model))
                NumberField("cpuinfo MHz", bind(\.spoof.cpuinfo_mhz))
                LabeledTextField(label: "hostname",
                                 placeholder: "rig-42",
                                 text: optBind(\.spoof.hostname))
                LabeledTextField(label: "machine-id",
                                 placeholder: "deadbeef…",
                                 text: optBind(\.spoof.machine_id))
                LabeledTextField(label: "kernel_release",
                                 placeholder: "6.12.0-stable",
                                 text: optBind(\.spoof.kernel_release))
                LabeledTextField(label: "kernel_version",
                                 placeholder: "Linux version 6.12.0 …",
                                 text: optBind(\.spoof.kernel_version))
                LabeledTextField(label: "timezone",
                                 placeholder: "Etc/UTC",
                                 text: optBind(\.spoof.timezone))
                LabeledTextField(label: "hostid (hex)",
                                 placeholder: "deadbeef",
                                 text: optBind(\.spoof.hostid_hex))
                NumberField("EFI platform size", bind(\.spoof.efi_platform_size))
                NumberField("Temperature (°C)", bind(\.spoof.temperature_c))
            }

            SubGroup("DMI overrides") {
                KVPairsEditor(keyLabel: "field",
                              valueLabel: "value",
                              pairs: bind(\.spoof.dmi))
            }
            SubGroup("Arbitrary synth files") {
                if store.profile.spoof.files.isEmpty {
                    Text("No synth files.")
                        .font(.caption)
                        .foregroundStyle(.tertiary)
                }
                ForEach(store.profile.spoof.files.indices, id: \.self) { idx in
                    VStack(alignment: .leading, spacing: 6) {
                        HStack(spacing: 8) {
                            TextField("absolute path", text: Binding(
                                get: { store.profile.spoof.files[idx].path },
                                set: { store.profile.spoof.files[idx].path = $0
                                       store.reserializeFromForm() }))
                            .textFieldStyle(.roundedBorder)
                            .font(.system(.callout, design: .monospaced))
                            Button(role: .destructive) {
                                store.profile.spoof.files.remove(at: idx)
                                store.reserializeFromForm()
                            } label: { Image(systemName: "xmark.circle.fill") }
                            .buttonStyle(.borderless)
                            .foregroundStyle(.secondary)
                        }
                        TextEditor(text: Binding(
                            get: { store.profile.spoof.files[idx].content },
                            set: { store.profile.spoof.files[idx].content = $0
                                   store.reserializeFromForm() }))
                        .font(.system(.caption, design: .monospaced))
                        .frame(minHeight: 60, maxHeight: 120)
                        .overlay(
                            RoundedRectangle(cornerRadius: 6)
                                .strokeBorder(Color.secondary.opacity(0.25), lineWidth: 1)
                        )
                    }
                    .padding(8)
                    .background(
                        RoundedRectangle(cornerRadius: 8, style: .continuous)
                            .fill(Color(nsColor: .controlBackgroundColor))
                    )
                }
                Button {
                    store.profile.spoof.files.append(SpoofFile())
                    store.reserializeFromForm()
                } label: { Label("Add synth file", systemImage: "plus") }
                .buttonStyle(.bordered)
            }
        }
    }

    private func bind<V>(_ key: WritableKeyPath<Profile, V>) -> Binding<V> {
        Binding(
            get: { store.profile[keyPath: key] },
            set: { store.profile[keyPath: key] = $0; store.reserializeFromForm() }
        )
    }

    private func optBind(_ key: WritableKeyPath<Profile, String?>) -> Binding<String> {
        Binding(
            get: { store.profile[keyPath: key] ?? "" },
            set: { store.profile[keyPath: key] = $0.isEmpty ? nil : $0
                   store.reserializeFromForm() }
        )
    }
}

// ─── Workspace / Overlay / Mocks ──────────────────────────────────────

private struct WorkspaceOverlayMocksSection: View {
    @EnvironmentObject var store: ProfileStore

    var body: some View {
        SectionCard(title: "Workspace · Overlay · Mocks", symbol: "archivebox.fill") {
            SubGroup("Workspace") {
                LabeledTextField(label: "Path",
                                 placeholder: "~/.sandkasten/work/my-app",
                                 text: optBind(\.workspace.path))
                Toggle("chdir into workspace on start",
                       isOn: bind(\.workspace.chdir))
                    .toggleStyle(.switch)
            }

            SubGroup("Overlay (Linux)") {
                LabeledTextField(label: "Lower",
                                 placeholder: "/opt/myapp",
                                 text: optBind(\.overlay.lower))
                LabeledTextField(label: "Upper",
                                 placeholder: "~/.sandkasten/overlay/myapp",
                                 text: optBind(\.overlay.upper))
                LabeledTextField(label: "Mount",
                                 placeholder: "(defaults to lower)",
                                 text: optBind(\.overlay.mount))
            }

            SubGroup("Mocks") {
                KVPairsEditor(keyLabel: "filename",
                              valueLabel: "content",
                              pairs: bind(\.mocks.files),
                              valueMonospaced: true)
            }
        }
    }

    private func bind<V>(_ key: WritableKeyPath<Profile, V>) -> Binding<V> {
        Binding(
            get: { store.profile[keyPath: key] },
            set: { store.profile[keyPath: key] = $0; store.reserializeFromForm() }
        )
    }

    private func optBind(_ key: WritableKeyPath<Profile, String?>) -> Binding<String> {
        Binding(
            get: { store.profile[keyPath: key] ?? "" },
            set: { store.profile[keyPath: key] = $0.isEmpty ? nil : $0
                   store.reserializeFromForm() }
        )
    }
}

// ──────────────────────────────────────────────────────────────────────
// Reusable widgets
// ──────────────────────────────────────────────────────────────────────

struct SectionCard<Content: View>: View {
    let title: String
    let symbol: String
    let content: Content
    @State private var expanded: Bool = true

    init(title: String, symbol: String, @ViewBuilder content: () -> Content) {
        self.title = title
        self.symbol = symbol
        self.content = content()
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Button {
                withAnimation(.easeInOut(duration: 0.15)) { expanded.toggle() }
            } label: {
                HStack(spacing: 10) {
                    Image(systemName: symbol)
                        .font(.callout.weight(.semibold))
                        .foregroundStyle(Color.accentColor)
                        .frame(width: 20)
                    Text(title)
                        .font(.headline)
                    Spacer()
                    Image(systemName: "chevron.down")
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(.secondary)
                        .rotationEffect(.degrees(expanded ? 0 : -90))
                }
                .padding(.horizontal, 16)
                .padding(.vertical, 12)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)

            if expanded {
                Divider()
                VStack(alignment: .leading, spacing: 12) {
                    content
                }
                .padding(.horizontal, 16)
                .padding(.vertical, 14)
            }
        }
        .background(
            RoundedRectangle(cornerRadius: 10, style: .continuous)
                .fill(Color(nsColor: .controlBackgroundColor).opacity(0.55))
        )
        .overlay(
            RoundedRectangle(cornerRadius: 10, style: .continuous)
                .strokeBorder(Color.secondary.opacity(0.15), lineWidth: 1)
        )
    }
}

struct SubGroup<Content: View>: View {
    let title: String
    let content: Content

    init(_ title: String, @ViewBuilder content: () -> Content) {
        self.title = title
        self.content = content()
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(title.uppercased())
                .font(.caption2.weight(.semibold))
                .foregroundStyle(.secondary)
                .tracking(0.8)
            content
        }
        .padding(.top, 4)
    }
}

struct LabeledTextField: View {
    let label: String
    let placeholder: String
    let text: Binding<String>

    var body: some View {
        HStack(spacing: 10) {
            Text(label)
                .font(.caption)
                .foregroundStyle(.secondary)
                .frame(width: 120, alignment: .trailing)
            TextField(placeholder, text: text)
                .textFieldStyle(.roundedBorder)
        }
    }
}

struct NumberField: View {
    let label: String
    let binding: Binding<Int?>

    init(_ label: String, _ binding: Binding<Int?>) {
        self.label = label
        self.binding = binding
    }

    var body: some View {
        HStack(spacing: 8) {
            Text(label)
                .font(.caption)
                .foregroundStyle(.secondary)
                .frame(maxWidth: 140, alignment: .leading)
            TextField("—", text: Binding(
                get: { binding.wrappedValue.map(String.init) ?? "" },
                set: { raw in
                    let trimmed = raw.trimmingCharacters(in: .whitespaces)
                    if trimmed.isEmpty {
                        binding.wrappedValue = nil
                    } else if let i = Int(trimmed), i >= 0 {
                        binding.wrappedValue = i
                    }
                }
            ))
            .textFieldStyle(.roundedBorder)
            .frame(maxWidth: 100)
            .monospacedDigit()
        }
    }
}

struct StringListEditor: View {
    let title: String
    var help: String? = nil
    let placeholder: String
    let values: Binding<[String]>
    var accent: Color = .accentColor

    init(title: String, help: String? = nil, placeholder: String = "", values: Binding<[String]>, accent: Color = .accentColor) {
        self.title = title
        self.help = help
        self.placeholder = placeholder
        self.values = values
        self.accent = accent
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 6) {
                Text(title)
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.secondary)
                if let h = help {
                    Image(systemName: "info.circle")
                        .font(.caption2)
                        .foregroundStyle(.tertiary)
                        .help(h)
                }
                Spacer()
                Text("\(values.wrappedValue.count)")
                    .font(.caption2.monospacedDigit())
                    .foregroundStyle(.secondary)
                    .padding(.horizontal, 6)
                    .padding(.vertical, 1)
                    .background(Capsule().fill(Color.secondary.opacity(0.12)))
                Button {
                    var v = values.wrappedValue
                    v.append("")
                    values.wrappedValue = v
                } label: { Image(systemName: "plus.circle.fill") }
                .buttonStyle(.borderless)
                .foregroundStyle(accent)
            }
            if values.wrappedValue.isEmpty {
                Text("Empty.")
                    .font(.caption)
                    .foregroundStyle(.tertiary)
            }
            ForEach(values.wrappedValue.indices, id: \.self) { idx in
                HStack(spacing: 6) {
                    TextField(placeholder, text: Binding(
                        get: { values.wrappedValue[idx] },
                        set: { var v = values.wrappedValue
                               v[idx] = $0
                               values.wrappedValue = v }))
                    .textFieldStyle(.roundedBorder)
                    .font(.system(.callout, design: .monospaced))
                    Button(role: .destructive) {
                        var v = values.wrappedValue
                        v.remove(at: idx)
                        values.wrappedValue = v
                    } label: { Image(systemName: "minus.circle") }
                    .buttonStyle(.borderless)
                    .foregroundStyle(.secondary)
                }
            }
        }
    }
}

struct KVPairsEditor: View {
    let keyLabel: String
    let valueLabel: String
    let pairs: Binding<[String: String]>
    var valueMonospaced: Bool = false

    init(keyLabel: String, valueLabel: String, pairs: Binding<[String: String]>, valueMonospaced: Bool = false) {
        self.keyLabel = keyLabel
        self.valueLabel = valueLabel
        self.pairs = pairs
        self.valueMonospaced = valueMonospaced
    }

    var body: some View {
        let keys = pairs.wrappedValue.keys.sorted()
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text("\(keyLabel) → \(valueLabel)")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.secondary)
                Spacer()
                Button {
                    var p = pairs.wrappedValue
                    var newKey = "key"
                    var n = 1
                    while p[newKey] != nil { n += 1; newKey = "key\(n)" }
                    p[newKey] = ""
                    pairs.wrappedValue = p
                } label: { Image(systemName: "plus.circle.fill") }
                .buttonStyle(.borderless)
                .foregroundStyle(Color.accentColor)
            }
            if keys.isEmpty {
                Text("Empty.").font(.caption).foregroundStyle(.tertiary)
            }
            ForEach(keys, id: \.self) { key in
                HStack(spacing: 8) {
                    TextField(keyLabel, text: Binding(
                        get: { key },
                        set: { newKey in
                            var p = pairs.wrappedValue
                            if newKey != key, p[newKey] == nil {
                                let v = p.removeValue(forKey: key) ?? ""
                                p[newKey] = v
                                pairs.wrappedValue = p
                            }
                        }))
                    .textFieldStyle(.roundedBorder)
                    .font(.system(.callout, design: .monospaced))
                    Image(systemName: "arrow.right").font(.caption2).foregroundStyle(.secondary)
                    TextField(valueLabel, text: Binding(
                        get: { pairs.wrappedValue[key] ?? "" },
                        set: { var p = pairs.wrappedValue
                               p[key] = $0
                               pairs.wrappedValue = p }))
                    .textFieldStyle(.roundedBorder)
                    .font(valueMonospaced ? .system(.callout, design: .monospaced) : .callout)
                    Button(role: .destructive) {
                        var p = pairs.wrappedValue
                        p.removeValue(forKey: key)
                        pairs.wrappedValue = p
                    } label: { Image(systemName: "minus.circle") }
                    .buttonStyle(.borderless)
                    .foregroundStyle(.secondary)
                }
            }
        }
    }
}

struct PresetPicker: View {
    let title: String
    let all: [String]
    let selected: Binding<[String]>

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text(title)
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.secondary)
                Spacer()
                Text("\(selected.wrappedValue.count) selected")
                    .font(.caption2.monospacedDigit())
                    .foregroundStyle(.tertiary)
            }
            FlowLayout(spacing: 6) {
                ForEach(all, id: \.self) { p in
                    let on = selected.wrappedValue.contains(p)
                    Button {
                        var v = selected.wrappedValue
                        if on { v.removeAll { $0 == p } }
                        else   { v.append(p) }
                        selected.wrappedValue = v
                    } label: {
                        Text(p)
                            .font(.caption.weight(.medium))
                            .padding(.horizontal, 9)
                            .padding(.vertical, 3)
                            .foregroundStyle(on ? .white : Color(nsColor: .labelColor))
                            .background(
                                Capsule()
                                    .fill(on ? Color.accentColor : Color.secondary.opacity(0.12))
                            )
                    }
                    .buttonStyle(.plain)
                }
            }
        }
    }
}

/// Simple flow layout that wraps children across rows.
struct FlowLayout: Layout {
    var spacing: CGFloat = 6

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        let maxWidth = proposal.width ?? .infinity
        var x: CGFloat = 0
        var y: CGFloat = 0
        var rowH: CGFloat = 0
        for sub in subviews {
            let s = sub.sizeThatFits(.unspecified)
            if x + s.width > maxWidth {
                x = 0
                y += rowH + spacing
                rowH = 0
            }
            x += s.width + spacing
            rowH = max(rowH, s.height)
        }
        return CGSize(width: maxWidth, height: y + rowH)
    }

    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
        var x = bounds.minX
        var y = bounds.minY
        var rowH: CGFloat = 0
        for sub in subviews {
            let s = sub.sizeThatFits(.unspecified)
            if x + s.width > bounds.maxX {
                x = bounds.minX
                y += rowH + spacing
                rowH = 0
            }
            sub.place(at: CGPoint(x: x, y: y), proposal: ProposedViewSize(s))
            x += s.width + spacing
            rowH = max(rowH, s.height)
        }
    }
}
