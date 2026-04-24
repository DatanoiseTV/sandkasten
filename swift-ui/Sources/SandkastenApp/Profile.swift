import Foundation
import TOMLKit

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
}

struct Dns: Codable, Equatable {
    var servers: [String] = []
    var search: [String] = []
    var options: [String] = []
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
}

// MARK: process / system / env ─────────────────────────────────────────

struct ProcessSection: Codable, Equatable {
    var allow_fork: Bool = false
    var allow_exec: Bool = false
    var allow_signal_self: Bool = true

    enum CodingKeys: String, CodingKey { case allow_fork, allow_exec, allow_signal_self }
}

struct SystemSection: Codable, Equatable {
    var allow_sysctl_read: Bool = true
    var mach_services: [String] = []
    var allow_mach_all: Bool = false
    var allow_iokit: Bool = false
    var allow_ipc: Bool = false
}

struct Env: Codable, Equatable {
    var pass_all: Bool = false
    var pass: [String] = []
    var set: [String: String] = [:]
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
}

struct Mocks: Codable, Equatable {
    var files: [String: String] = [:]
}

struct Workspace: Codable, Equatable {
    var path: String?
    var chdir: Bool = false
}

struct Overlay: Codable, Equatable {
    var lower: String?
    var upper: String?
    var mount: String?
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
}

struct Video: Codable, Equatable {
    var devices: [String] = []
    var redirect: [String: String] = [:]
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
}

struct SpoofFile: Codable, Equatable, Identifiable {
    var id: UUID { UUID() }
    var path: String = ""
    var content: String = ""

    enum CodingKeys: String, CodingKey { case path, content }
}
