import Foundation
import TOMLKit

// Container helper that falls back to a default when a key is missing OR
// when decoding the value threw (e.g. TOMLKit's Codable adapter doesn't
// always honour Swift's synthesised-default shortcut for [Filesystem]
// etc. → sections without every declared key would otherwise fail with
// "The data couldn't be read because it is missing.").
extension KeyedDecodingContainer {
    func decodeOrDefault<T: Decodable>(_ type: T.Type, forKey key: Key, default dflt: T) -> T {
        if let v = try? decodeIfPresent(T.self, forKey: key) {
            return v
        }
        return dflt
    }
}

// Swift mirror of the Rust `config::Profile`. Every field is optional /
// defaulted so round-tripping an empty profile produces `{}` not errors.
// We keep field order matching the Rust source so the generated TOML is
// readable.

struct Profile: Codable, Equatable {
    var name: String?
    var description: String?
    var `extends`: String?

    var filesystem = Filesystem()
    var network = Network()
    var process = ProcessSection()
    var system = SystemSection()
    var env = Env()
    var limits = Limits()
    var mocks = Mocks()
    var workspace = Workspace()
    var overlay = Overlay()
    var hardware = Hardware()
    var spoof = Spoof()

    /// Diagnostics collected during parse. Empty on clean parse. We include
    /// section-level messages so the UI can point at where the problem is
    /// without losing the rest of the profile.
    var parseWarnings: [String] = []

    enum CodingKeys: String, CodingKey {
        case name, description, `extends`
        case filesystem, network, process, system, env
        case limits, mocks, workspace, overlay, hardware, spoof
    }

    init() {}

    /// Resilient decode: one bad section doesn't void the whole profile.
    /// Each section is tried independently; failures are collected into
    /// `parseWarnings` so the UI can surface exactly what went wrong
    /// without blanking out the form.
    init(from decoder: Decoder) throws {
        self.init()
        let c = try decoder.container(keyedBy: CodingKeys.self)

        // top-level strings — these are safe to decode directly.
        name        = try c.decodeIfPresent(String.self, forKey: .name)
        description = try c.decodeIfPresent(String.self, forKey: .description)
        extends     = try c.decodeIfPresent(String.self, forKey: .extends)

        // Collect warnings into a local, then assign to self once at the
        // end — avoids an exclusive-access conflict with the inout refs.
        var warns: [String] = []
        filesystem = Self.section(c, .filesystem, "filesystem", fallback: Filesystem(), warns: &warns)
        network    = Self.section(c, .network,    "network",    fallback: Network(),    warns: &warns)
        process    = Self.section(c, .process,    "process",    fallback: ProcessSection(), warns: &warns)
        system     = Self.section(c, .system,     "system",     fallback: SystemSection(),  warns: &warns)
        env        = Self.section(c, .env,        "env",        fallback: Env(),        warns: &warns)
        limits     = Self.section(c, .limits,     "limits",     fallback: Limits(),     warns: &warns)
        mocks      = Self.section(c, .mocks,      "mocks",      fallback: Mocks(),      warns: &warns)
        workspace  = Self.section(c, .workspace,  "workspace",  fallback: Workspace(),  warns: &warns)
        overlay    = Self.section(c, .overlay,    "overlay",    fallback: Overlay(),    warns: &warns)
        hardware   = Self.section(c, .hardware,   "hardware",   fallback: Hardware(),   warns: &warns)
        spoof      = Self.section(c, .spoof,      "spoof",      fallback: Spoof(),      warns: &warns)
        self.parseWarnings = warns
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encodeIfPresent(name,        forKey: .name)
        try c.encodeIfPresent(description, forKey: .description)
        try c.encodeIfPresent(`extends`,   forKey: .extends)

        // Only write sections that differ from their defaults, so the
        // emitted TOML looks like what a human would hand-write.
        if filesystem != Filesystem() { try c.encode(filesystem, forKey: .filesystem) }
        if network    != Network()    { try c.encode(network,    forKey: .network) }
        if process    != ProcessSection() { try c.encode(process, forKey: .process) }
        if system     != SystemSection()  { try c.encode(system,  forKey: .system) }
        if env        != Env()        { try c.encode(env,        forKey: .env) }
        if limits     != Limits()     { try c.encode(limits,     forKey: .limits) }
        if mocks      != Mocks()      { try c.encode(mocks,      forKey: .mocks) }
        if workspace  != Workspace()  { try c.encode(workspace,  forKey: .workspace) }
        if overlay    != Overlay()    { try c.encode(overlay,    forKey: .overlay) }
        if hardware   != Hardware()   { try c.encode(hardware,   forKey: .hardware) }
        if spoof      != Spoof()      { try c.encode(spoof,      forKey: .spoof) }
    }

    private static func section<T: Codable>(
        _ c: KeyedDecodingContainer<CodingKeys>,
        _ key: CodingKeys,
        _ name: String,
        fallback: T,
        warns: inout [String]
    ) -> T {
        do {
            if let v = try c.decodeIfPresent(T.self, forKey: key) {
                return v
            }
            return fallback
        } catch {
            warns.append("[\(name)]: \(error.localizedDescription)")
            return fallback
        }
    }

    // ── serialize ────────────────────────────────────────────────────
    func toTOML() throws -> String {
        try TOMLEncoder().encode(self)
    }

    static func parse(_ text: String) throws -> Profile {
        try TOMLDecoder().decode(Profile.self, from: text)
    }
}

// MARK: filesystem ─────────────────────────────────────────────────────

struct Filesystem: Codable, Equatable {
    var allow_metadata_read: Bool = true
    var read: [String] = []
    var read_write: [String] = []
    var deny: [String] = []
    var read_files: [String] = []
    var read_write_files: [String] = []
    var rules: [FileRule] = []
    var rewire: [Rewire] = []
    var hide: [String] = []

    init() {}

    enum CodingKeys: String, CodingKey {
        case allow_metadata_read, read, read_write, deny
        case read_files, read_write_files, rules, rewire, hide
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        allow_metadata_read = c.decodeOrDefault(Bool.self, forKey: .allow_metadata_read, default: true)
        read             = c.decodeOrDefault([String].self, forKey: .read, default: [])
        read_write       = c.decodeOrDefault([String].self, forKey: .read_write, default: [])
        deny             = c.decodeOrDefault([String].self, forKey: .deny, default: [])
        read_files       = c.decodeOrDefault([String].self, forKey: .read_files, default: [])
        read_write_files = c.decodeOrDefault([String].self, forKey: .read_write_files, default: [])
        rules            = c.decodeOrDefault([FileRule].self, forKey: .rules, default: [])
        rewire           = c.decodeOrDefault([Rewire].self, forKey: .rewire, default: [])
        hide             = c.decodeOrDefault([String].self, forKey: .hide, default: [])
    }
}

struct FileRule: Codable, Equatable, Identifiable {
    var id: UUID { UUID() }
    var path: String = ""
    var literal: Bool = false
    var allow: [String] = []
    var deny: [String] = []

    enum CodingKeys: String, CodingKey { case path, literal, allow, deny }
}

struct Rewire: Codable, Equatable, Identifiable {
    var id: UUID { UUID() }
    var from: String = ""
    var to: String = ""

    enum CodingKeys: String, CodingKey { case from, to }
}

// MARK: network ────────────────────────────────────────────────────────

struct Network: Codable, Equatable {
    var allow_localhost: Bool = false
    var allow_inbound: Bool = false
    var allow_dns: Bool = false
    var outbound_tcp: [String] = []
    var outbound_udp: [String] = []
    var inbound_tcp: [String] = []
    var inbound_udp: [String] = []
    var allow_icmp: Bool = false
    var allow_icmpv6: Bool = false
    var allow_sctp: Bool = false
    var allow_dccp: Bool = false
    var allow_udplite: Bool = false
    var allow_raw_sockets: Bool = false
    var allow_unix_sockets: Bool = false
    var extra_protocols: [String] = []
    var presets: [String] = []
    var dns: Dns = Dns()
    var hosts_entries: [String: String] = [:]
    var redirects: [NetRedirect] = []
    var blocks: [NetBlock] = []
    var proxy: Proxy = Proxy()
    var external: String?
    var netns_path: String?

    init() {}

    enum CodingKeys: String, CodingKey {
        case allow_localhost, allow_inbound, allow_dns
        case outbound_tcp, outbound_udp, inbound_tcp, inbound_udp
        case allow_icmp, allow_icmpv6, allow_sctp, allow_dccp, allow_udplite
        case allow_raw_sockets, allow_unix_sockets
        case extra_protocols, presets
        case dns, hosts_entries, redirects, blocks
        case proxy, external, netns_path
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        allow_localhost    = c.decodeOrDefault(Bool.self, forKey: .allow_localhost, default: false)
        allow_inbound      = c.decodeOrDefault(Bool.self, forKey: .allow_inbound, default: false)
        allow_dns          = c.decodeOrDefault(Bool.self, forKey: .allow_dns, default: false)
        outbound_tcp       = c.decodeOrDefault([String].self, forKey: .outbound_tcp, default: [])
        outbound_udp       = c.decodeOrDefault([String].self, forKey: .outbound_udp, default: [])
        inbound_tcp        = c.decodeOrDefault([String].self, forKey: .inbound_tcp, default: [])
        inbound_udp        = c.decodeOrDefault([String].self, forKey: .inbound_udp, default: [])
        allow_icmp         = c.decodeOrDefault(Bool.self, forKey: .allow_icmp, default: false)
        allow_icmpv6       = c.decodeOrDefault(Bool.self, forKey: .allow_icmpv6, default: false)
        allow_sctp         = c.decodeOrDefault(Bool.self, forKey: .allow_sctp, default: false)
        allow_dccp         = c.decodeOrDefault(Bool.self, forKey: .allow_dccp, default: false)
        allow_udplite      = c.decodeOrDefault(Bool.self, forKey: .allow_udplite, default: false)
        allow_raw_sockets  = c.decodeOrDefault(Bool.self, forKey: .allow_raw_sockets, default: false)
        allow_unix_sockets = c.decodeOrDefault(Bool.self, forKey: .allow_unix_sockets, default: false)
        extra_protocols    = c.decodeOrDefault([String].self, forKey: .extra_protocols, default: [])
        presets            = c.decodeOrDefault([String].self, forKey: .presets, default: [])
        dns                = c.decodeOrDefault(Dns.self, forKey: .dns, default: Dns())
        hosts_entries      = c.decodeOrDefault([String: String].self, forKey: .hosts_entries, default: [:])
        redirects          = c.decodeOrDefault([NetRedirect].self, forKey: .redirects, default: [])
        blocks             = c.decodeOrDefault([NetBlock].self, forKey: .blocks, default: [])
        proxy              = c.decodeOrDefault(Proxy.self, forKey: .proxy, default: Proxy())
        external           = try c.decodeIfPresent(String.self, forKey: .external)
        netns_path         = try c.decodeIfPresent(String.self, forKey: .netns_path)
    }
}

struct Dns: Codable, Equatable {
    var servers: [String] = []
    var search: [String] = []
    var options: [String] = []

    init() {}

    enum CodingKeys: String, CodingKey { case servers, search, options }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        servers = c.decodeOrDefault([String].self, forKey: .servers, default: [])
        search  = c.decodeOrDefault([String].self, forKey: .search, default: [])
        options = c.decodeOrDefault([String].self, forKey: .options, default: [])
    }
}

struct NetRedirect: Codable, Equatable, Identifiable {
    var id: UUID { UUID() }
    var from: String = ""
    var to: String = ""
    var `protocol`: String?

    enum CodingKeys: String, CodingKey { case from, to, `protocol` }
}

struct NetBlock: Codable, Equatable, Identifiable {
    var id: UUID { UUID() }
    var host: String = ""
    var port: String?
    var `protocol`: String?

    enum CodingKeys: String, CodingKey { case host, port, `protocol` }
}

struct Proxy: Codable, Equatable {
    var url: String?
    var bypass: [String] = []
    var restrict_outbound: Bool = true

    init() {}

    enum CodingKeys: String, CodingKey { case url, bypass, restrict_outbound }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        url               = try c.decodeIfPresent(String.self, forKey: .url)
        bypass            = c.decodeOrDefault([String].self, forKey: .bypass, default: [])
        restrict_outbound = c.decodeOrDefault(Bool.self, forKey: .restrict_outbound, default: true)
    }
}

// MARK: process / system / env ─────────────────────────────────────────

struct ProcessSection: Codable, Equatable {
    var allow_fork: Bool = false
    var allow_exec: Bool = false
    var allow_signal_self: Bool = true

    init() {}

    enum CodingKeys: String, CodingKey { case allow_fork, allow_exec, allow_signal_self }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        allow_fork        = c.decodeOrDefault(Bool.self, forKey: .allow_fork, default: false)
        allow_exec        = c.decodeOrDefault(Bool.self, forKey: .allow_exec, default: false)
        allow_signal_self = c.decodeOrDefault(Bool.self, forKey: .allow_signal_self, default: true)
    }
}

struct SystemSection: Codable, Equatable {
    var allow_sysctl_read: Bool = true
    var mach_services: [String] = []
    var allow_mach_all: Bool = false
    var allow_iokit: Bool = false
    var allow_ipc: Bool = false

    init() {}

    enum CodingKeys: String, CodingKey {
        case allow_sysctl_read, mach_services, allow_mach_all, allow_iokit, allow_ipc
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        allow_sysctl_read = c.decodeOrDefault(Bool.self, forKey: .allow_sysctl_read, default: true)
        mach_services     = c.decodeOrDefault([String].self, forKey: .mach_services, default: [])
        allow_mach_all    = c.decodeOrDefault(Bool.self, forKey: .allow_mach_all, default: false)
        allow_iokit       = c.decodeOrDefault(Bool.self, forKey: .allow_iokit, default: false)
        allow_ipc         = c.decodeOrDefault(Bool.self, forKey: .allow_ipc, default: false)
    }
}

struct Env: Codable, Equatable {
    var pass_all: Bool = false
    var pass: [String] = []
    var set: [String: String] = [:]

    init() {}

    enum CodingKeys: String, CodingKey { case pass_all, pass, set }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        pass_all = c.decodeOrDefault(Bool.self, forKey: .pass_all, default: false)
        pass     = c.decodeOrDefault([String].self, forKey: .pass, default: [])
        set      = c.decodeOrDefault([String: String].self, forKey: .set, default: [:])
    }
}

// MARK: limits / mocks / workspace / overlay ───────────────────────────

struct Limits: Codable, Equatable {
    var cpu_seconds: Int?
    var memory_mb: Int?
    var file_size_mb: Int?
    var open_files: Int?
    var processes: Int?
    var stack_mb: Int?
    var core_dumps: Bool = false
    var wall_timeout_seconds: Int?

    init() {}

    enum CodingKeys: String, CodingKey {
        case cpu_seconds, memory_mb, file_size_mb, open_files, processes, stack_mb
        case core_dumps, wall_timeout_seconds
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        cpu_seconds         = try c.decodeIfPresent(Int.self, forKey: .cpu_seconds)
        memory_mb           = try c.decodeIfPresent(Int.self, forKey: .memory_mb)
        file_size_mb        = try c.decodeIfPresent(Int.self, forKey: .file_size_mb)
        open_files          = try c.decodeIfPresent(Int.self, forKey: .open_files)
        processes           = try c.decodeIfPresent(Int.self, forKey: .processes)
        stack_mb            = try c.decodeIfPresent(Int.self, forKey: .stack_mb)
        core_dumps          = c.decodeOrDefault(Bool.self, forKey: .core_dumps, default: false)
        wall_timeout_seconds = try c.decodeIfPresent(Int.self, forKey: .wall_timeout_seconds)
    }
}

struct Mocks: Codable, Equatable {
    var files: [String: String] = [:]

    init() {}

    enum CodingKeys: String, CodingKey { case files }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        files = c.decodeOrDefault([String: String].self, forKey: .files, default: [:])
    }
}

struct Workspace: Codable, Equatable {
    var path: String?
    var chdir: Bool = false

    init() {}

    enum CodingKeys: String, CodingKey { case path, chdir }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        path  = try c.decodeIfPresent(String.self, forKey: .path)
        chdir = c.decodeOrDefault(Bool.self, forKey: .chdir, default: false)
    }
}

struct Overlay: Codable, Equatable {
    var lower: String?
    var upper: String?
    var mount: String?

    init() {}

    enum CodingKeys: String, CodingKey { case lower, upper, mount }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        lower = try c.decodeIfPresent(String.self, forKey: .lower)
        upper = try c.decodeIfPresent(String.self, forKey: .upper)
        mount = try c.decodeIfPresent(String.self, forKey: .mount)
    }
}

// MARK: hardware / spoof ───────────────────────────────────────────────

struct Hardware: Codable, Equatable {
    var usb: Bool = false
    var serial: Bool = false
    var audio: Bool = false
    var gpu: Bool = false
    var camera: Bool = false
    var screen_capture: Bool = false
    var video: Video = Video()

    init() {}

    enum CodingKeys: String, CodingKey {
        case usb, serial, audio, gpu, camera, screen_capture, video
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        usb            = c.decodeOrDefault(Bool.self, forKey: .usb, default: false)
        serial         = c.decodeOrDefault(Bool.self, forKey: .serial, default: false)
        audio          = c.decodeOrDefault(Bool.self, forKey: .audio, default: false)
        gpu            = c.decodeOrDefault(Bool.self, forKey: .gpu, default: false)
        camera         = c.decodeOrDefault(Bool.self, forKey: .camera, default: false)
        screen_capture = c.decodeOrDefault(Bool.self, forKey: .screen_capture, default: false)
        video          = c.decodeOrDefault(Video.self, forKey: .video, default: Video())
    }
}

struct Video: Codable, Equatable {
    var devices: [String] = []
    var redirect: [String: String] = [:]

    init() {}

    enum CodingKeys: String, CodingKey { case devices, redirect }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        devices  = c.decodeOrDefault([String].self, forKey: .devices, default: [])
        redirect = c.decodeOrDefault([String: String].self, forKey: .redirect, default: [:])
    }
}

struct Spoof: Codable, Equatable {
    var cpu_count: Int?
    var cpuinfo_synth: Bool = false
    var cpuinfo_model: String?
    var cpuinfo_mhz: Int?
    var hostname: String?
    var machine_id: String?
    var dmi: [String: String] = [:]
    var files: [SpoofFile] = []
    var temperature_c: Int?
    var efi_platform_size: Int?
    var efi_enabled: Bool?
    var kernel_version: String?
    var kernel_release: String?
    var os_release: String?
    var issue: String?
    var hostid_hex: String?
    var timezone: String?

    init() {}

    enum CodingKeys: String, CodingKey {
        case cpu_count, cpuinfo_synth, cpuinfo_model, cpuinfo_mhz
        case hostname, machine_id, dmi, files
        case temperature_c, efi_platform_size, efi_enabled
        case kernel_version, kernel_release, os_release, issue
        case hostid_hex, timezone
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        cpu_count         = try c.decodeIfPresent(Int.self, forKey: .cpu_count)
        cpuinfo_synth     = c.decodeOrDefault(Bool.self, forKey: .cpuinfo_synth, default: false)
        cpuinfo_model     = try c.decodeIfPresent(String.self, forKey: .cpuinfo_model)
        cpuinfo_mhz       = try c.decodeIfPresent(Int.self, forKey: .cpuinfo_mhz)
        hostname          = try c.decodeIfPresent(String.self, forKey: .hostname)
        machine_id        = try c.decodeIfPresent(String.self, forKey: .machine_id)
        dmi               = c.decodeOrDefault([String: String].self, forKey: .dmi, default: [:])
        files             = c.decodeOrDefault([SpoofFile].self, forKey: .files, default: [])
        temperature_c     = try c.decodeIfPresent(Int.self, forKey: .temperature_c)
        efi_platform_size = try c.decodeIfPresent(Int.self, forKey: .efi_platform_size)
        efi_enabled       = try c.decodeIfPresent(Bool.self, forKey: .efi_enabled)
        kernel_version    = try c.decodeIfPresent(String.self, forKey: .kernel_version)
        kernel_release    = try c.decodeIfPresent(String.self, forKey: .kernel_release)
        os_release        = try c.decodeIfPresent(String.self, forKey: .os_release)
        issue             = try c.decodeIfPresent(String.self, forKey: .issue)
        hostid_hex        = try c.decodeIfPresent(String.self, forKey: .hostid_hex)
        timezone          = try c.decodeIfPresent(String.self, forKey: .timezone)
    }
}

struct SpoofFile: Codable, Equatable, Identifiable {
    var id: UUID { UUID() }
    var path: String = ""
    var content: String = ""

    enum CodingKeys: String, CodingKey { case path, content }
}
