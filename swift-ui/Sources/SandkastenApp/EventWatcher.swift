import Foundation
import Combine
import AppKit
import UserNotifications

/// One denial event we got from the CLI. Identity is `(profile, op,
/// target)` so repeated emissions of the same denial across multiple
/// runs collapse into a single review row.
struct DenialItem: Identifiable, Hashable {
    let id: String          // profile|op|target
    let profile: String
    let op: String
    let target: String
    var count: Int          // accumulated across runs
    var firstSeen: Date
    var lastSeen: Date
    /// User has clicked allow/deny/once on this row → hide it.
    var resolved: Bool = false
}

/// One completed sandkasten run, surfaced in the menu / activity log.
struct RecentRun: Identifiable, Hashable {
    let id: UUID = UUID()
    let profile: String
    let target: String
    let argv: [String]
    let exitCode: Int
    let wallMs: UInt64
    let startedAt: Date
    let endedAt: Date
}

/// Watches `~/Library/Application Support/sandkasten/events/` for
/// new NDJSON files emitted by `sandkasten run` invocations under
/// `SANDKASTEN_EVENTS_DIR`. Parses lines as they arrive, deduplicates
/// denials, and publishes them for the menu / denial-review UIs.
///
/// Soft-fails everywhere: if the directory doesn't exist, we just
/// don't see events; if a file is corrupt, we skip the bad lines.
/// The CLI never depends on this side existing — server / headless
/// users never set the env var and never write any files.
@MainActor
final class EventWatcher: ObservableObject {
    @Published private(set) var denials: [DenialItem] = []
    @Published private(set) var recent: [RecentRun] = []
    @Published var watchEnabled: Bool {
        didSet {
            UserDefaults.standard.set(watchEnabled, forKey: "watchEnabled")
            if watchEnabled {
                start()
                installShellSnippetIfMissing()
            } else {
                stop()
            }
        }
    }

    /// Denials the user hasn't dismissed yet — drives the menu badge.
    var unreviewedDenialCount: Int {
        denials.filter { !$0.resolved }.count
    }

    var recentRunCount: Int { recent.count }

    private var fileOffsets: [URL: UInt64] = [:]
    private var dirSource: DispatchSourceFileSystemObject?
    private var dirFD: Int32 = -1
    private var pollTimer: Timer?

    init() {
        // Default to off so a fresh install never starts watching the
        // user's runs without explicit opt-in.
        let defaults = UserDefaults.standard
        if defaults.object(forKey: "watchEnabled") == nil {
            defaults.set(false, forKey: "watchEnabled")
        }
        self.watchEnabled = defaults.bool(forKey: "watchEnabled")
        if self.watchEnabled {
            start()
        }
        // Notification permission is requested lazily so users who
        // never enable watching never see the prompt.
    }

    // ─── public API ───────────────────────────────────────────

    static func eventsDir() -> URL {
        let base = FileManager.default.urls(
            for: .applicationSupportDirectory,
            in: .userDomainMask
        ).first ?? URL(fileURLWithPath: NSHomeDirectory())
            .appendingPathComponent("Library/Application Support")
        return base.appendingPathComponent("sandkasten/events", isDirectory: true)
    }

    func resolveDenial(_ id: String) {
        if let idx = denials.firstIndex(where: { $0.id == id }) {
            denials[idx].resolved = true
        }
    }

    func clearResolved() {
        denials.removeAll { $0.resolved }
    }

    // ─── lifecycle ────────────────────────────────────────────

    private func start() {
        let dir = Self.eventsDir()
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        scanDirectory()
        watchDirectory(dir)
        if pollTimer == nil {
            // Backup poll — FSEvents at the dir level fires on
            // create/delete, but not on every append-write to a file
            // already in the dir. The poll catches those.
            pollTimer = Timer.scheduledTimer(withTimeInterval: 1.0, repeats: true) { [weak self] _ in
                Task { @MainActor in self?.scanDirectory() }
            }
        }
    }

    private func stop() {
        dirSource?.cancel()
        dirSource = nil
        if dirFD >= 0 {
            close(dirFD)
            dirFD = -1
        }
        pollTimer?.invalidate()
        pollTimer = nil
    }

    private func watchDirectory(_ dir: URL) {
        dirSource?.cancel()
        if dirFD >= 0 { close(dirFD) }
        dirFD = open(dir.path, O_EVTONLY)
        guard dirFD >= 0 else { return }
        let src = DispatchSource.makeFileSystemObjectSource(
            fileDescriptor: dirFD,
            eventMask: [.write, .extend],
            queue: .main
        )
        src.setEventHandler { [weak self] in
            Task { @MainActor in self?.scanDirectory() }
        }
        src.setCancelHandler { [weak self] in
            if let fd = self?.dirFD, fd >= 0 { close(fd) }
            self?.dirFD = -1
        }
        src.resume()
        dirSource = src
    }

    /// Find any NDJSON files in the dir, append-read them past where
    /// we last left off. Idempotent — safe to call repeatedly.
    private func scanDirectory() {
        let dir = Self.eventsDir()
        guard let entries = try? FileManager.default.contentsOfDirectory(
            at: dir,
            includingPropertiesForKeys: [.fileSizeKey],
            options: [.skipsHiddenFiles]
        ) else { return }

        for url in entries where url.pathExtension == "ndjson" {
            ingest(file: url)
        }
        // Drop offsets for files that no longer exist (run finished
        // and cleaned up, or user deleted them).
        let alive = Set(entries.map { $0 })
        fileOffsets = fileOffsets.filter { alive.contains($0.key) }

        // Keep the recent-runs list bounded so a long-running session
        // doesn't bloat memory.
        if recent.count > 200 {
            recent.removeFirst(recent.count - 200)
        }
    }

    private func ingest(file: URL) {
        guard let fh = try? FileHandle(forReadingFrom: file) else { return }
        defer { try? fh.close() }
        let prevOffset = fileOffsets[file] ?? 0
        do {
            try fh.seek(toOffset: prevOffset)
        } catch {
            return
        }
        let data = (try? fh.readToEnd()) ?? Data()
        if data.isEmpty { return }
        let newOffset = prevOffset + UInt64(data.count)
        fileOffsets[file] = newOffset

        // Split on newline; ignore any trailing partial line (it'll
        // come back next poll once the writer flushes).
        let chunks = data.split(separator: 0x0a)  // '\n'
        let endsWithNewline = data.last == 0x0a
        let usable = endsWithNewline ? chunks : chunks.dropLast()
        // If the last line was partial, rewind the offset so we
        // re-read it next time.
        if !endsWithNewline, let last = chunks.last {
            fileOffsets[file] = newOffset - UInt64(last.count)
        }

        for raw in usable {
            guard let line = String(data: Data(raw), encoding: .utf8),
                  !line.isEmpty else { continue }
            handleLine(line)
        }
    }

    private func handleLine(_ line: String) {
        guard let data = line.data(using: .utf8),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let kind = obj["event"] as? String
        else { return }
        switch kind {
        case "denial":   absorbDenial(obj)
        case "run_end":  absorbRunEnd(obj)
        case "run_start": break  // we accumulate enough on run_end
        default: break
        }
    }

    private func absorbDenial(_ obj: [String: Any]) {
        let profile = (obj["profile"] as? String) ?? "<inline>"
        let op      = (obj["op"]      as? String) ?? "?"
        let target  = (obj["target"]  as? String) ?? ""
        let count   = (obj["count"]   as? Int) ?? 1
        let id = "\(profile)|\(op)|\(target)"
        let now = Date()
        if let idx = denials.firstIndex(where: { $0.id == id }) {
            denials[idx].count += count
            denials[idx].lastSeen = now
            denials[idx].resolved = false
        } else {
            denials.append(DenialItem(
                id: id, profile: profile, op: op, target: target,
                count: count, firstSeen: now, lastSeen: now
            ))
            postNotification(profile: profile, op: op, target: target)
        }
    }

    private func absorbRunEnd(_ obj: [String: Any]) {
        // We could correlate with a previous run_start by pid, but for
        // v1 the run_end has enough to render the activity row.
        let profile = (obj["profile"] as? String) ?? "<inline>"
        let target  = (obj["target"]  as? String) ?? ""
        let argv    = (obj["argv"]    as? [String]) ?? []
        let exit    = (obj["exit_code"] as? Int) ?? 0
        let wall    = (obj["wall_ms"] as? UInt64) ?? 0
        recent.append(RecentRun(
            profile: profile, target: target, argv: argv,
            exitCode: exit, wallMs: wall,
            startedAt: Date().addingTimeInterval(-Double(wall) / 1000.0),
            endedAt: Date()
        ))
    }

    // ─── notifications ────────────────────────────────────────

    private func postNotification(profile: String, op: String, target: String) {
        // UNUserNotificationCenter requires a real app bundle (it
        // looks up bundleProxyForCurrentProcess and crashes if it's
        // nil). We hit that path during local dev when running the
        // binary directly out of `.build/debug/`. Skip silently —
        // notifications are nice-to-have, not load-bearing.
        guard Bundle.main.bundleIdentifier != nil else { return }
        let center = UNUserNotificationCenter.current()
        center.requestAuthorization(options: [.alert, .sound]) { _, _ in }
        let content = UNMutableNotificationContent()
        content.title = "sandkasten: \(profile) denied \(op)"
        content.body = displayPath(target)
        content.sound = .default
        let req = UNNotificationRequest(
            identifier: UUID().uuidString,
            content: content,
            trigger: nil
        )
        center.add(req) { _ in }
    }

    // ─── shell snippet (opt-in event-dir env var) ─────────────

    /// One-shot: when the user enables watching for the first time,
    /// write a tiny shell snippet at
    /// `~/Library/Application Support/sandkasten/sandkasten-watch.sh`
    /// that exports `SANDKASTEN_EVENTS_DIR`, and tell the user to
    /// source it from their shell rc. Without the env var set in the
    /// CLI's environment, the watcher won't see anything.
    private func installShellSnippetIfMissing() {
        let dir = Self.eventsDir().deletingLastPathComponent()
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let snippet = dir.appendingPathComponent("sandkasten-watch.sh")
        if FileManager.default.fileExists(atPath: snippet.path) { return }
        let path = Self.eventsDir().path
        let body = """
        # sandkasten — UI event-stream opt-in.
        # Source this from ~/.zshrc / ~/.bashrc to let the macOS
        # menu-bar app see your `sandkasten run` invocations.
        # Server / headless users should NOT source this — it has no
        # effect outside a session where the UI is running, but the
        # principle is "leave it untouched on a server".
        export SANDKASTEN_EVENTS_DIR="\(path)"
        """
        try? body.write(to: snippet, atomically: true, encoding: .utf8)
    }

    private func displayPath(_ p: String) -> String {
        let home = NSHomeDirectory()
        if p.hasPrefix(home) { return "~" + p.dropFirst(home.count) }
        return p
    }
}
