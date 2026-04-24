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
