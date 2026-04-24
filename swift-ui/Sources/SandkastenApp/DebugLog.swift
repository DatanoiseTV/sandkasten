import Foundation

/// Append-only diagnostic log. Every interesting event goes here with a
/// timestamp so external tooling (and the dev chatting with the user over
/// iMessage) can `cat /tmp/sandkasten-ui.log` and see exactly what the UI
/// just tried to do — what TOML it loaded, what TOMLKit complained about,
/// which section fell back to defaults.
///
/// Two destinations: `/tmp/sandkasten-ui.log` (stable, easy to `cat`) and
/// `~/Library/Logs/sandkasten/ui.log` (survives /tmp wipes across reboots
/// on some macOS versions; shown in Console.app).
enum DebugLog {
    private static let queue = DispatchQueue(label: "sandkasten.debuglog", qos: .utility)

    private static let paths: [URL] = {
        let tmp = URL(fileURLWithPath: "/tmp/sandkasten-ui.log")
        let logs = FileManager.default
            .urls(for: .libraryDirectory, in: .userDomainMask).first?
            .appendingPathComponent("Logs/sandkasten", isDirectory: true)
        if let dir = logs {
            try? FileManager.default.createDirectory(at: dir,
                                                     withIntermediateDirectories: true)
            return [tmp, dir.appendingPathComponent("ui.log")]
        }
        return [tmp]
    }()

    private static let dateFmt: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "HH:mm:ss.SSS"
        return f
    }()

    /// Emit a one-line event.
    static func line(_ kind: String, _ message: String) {
        let ts = dateFmt.string(from: Date())
        let row = "\(ts) [\(kind)] \(message)\n"
        write(row)
    }

    /// Emit a multi-line block — useful for dumping TOML on failure.
    static func block(_ kind: String, _ title: String, _ body: String) {
        let ts = dateFmt.string(from: Date())
        var s = "\(ts) [\(kind)] ── \(title) ──\n"
        for l in body.split(separator: "\n", omittingEmptySubsequences: false) {
            s += "                \(l)\n"
        }
        s += "                ── end ──\n"
        write(s)
    }

    /// Startup banner — written once per app launch.
    static func boot() {
        line("boot", "sandkasten UI v\(Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "?") on macOS \(ProcessInfo.processInfo.operatingSystemVersionString)")
        line("boot", "executable: \(Bundle.main.bundlePath)")
        for p in paths {
            line("boot", "log sink: \(p.path)")
        }
    }

    // ── private ─────────────────────────────────────────────────────

    private static func write(_ row: String) {
        queue.async {
            guard let data = row.data(using: .utf8) else { return }
            for path in paths {
                append(data, to: path)
            }
        }
    }

    private static func append(_ data: Data, to url: URL) {
        let fm = FileManager.default
        if !fm.fileExists(atPath: url.path) {
            try? data.write(to: url, options: .atomic)
            return
        }
        if let h = try? FileHandle(forWritingTo: url) {
            defer { try? h.close() }
            _ = try? h.seekToEnd()
            try? h.write(contentsOf: data)
        }
    }
}
