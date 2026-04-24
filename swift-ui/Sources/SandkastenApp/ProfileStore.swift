import Foundation
import Combine
import AppKit

/// One entry in the sidebar.
struct ProfileEntry: Identifiable, Hashable {
    enum Kind { case builtin, user }
    let id: String          // unique across builtins + user names
    let name: String
    let kind: Kind
    var description: String
}

@MainActor
final class ProfileStore: ObservableObject {
    @Published var builtins: [ProfileEntry] = []
    @Published var userProfiles: [ProfileEntry] = []
    @Published var selectedID: String?
    @Published var rawToml: String = ""
    @Published var explanation: String = ""
    @Published var statusLine: String = "Ready"
    @Published var isDirty: Bool = false
    @Published var pendingError: String?
    @Published var newProfilePromptVisible: Bool = false

    /// Resolved path to the `sandkasten` CLI. First checks $PATH, then
    /// falls back to the repo's `target/release` sibling.
    @Published var cliPath: String = ProfileStore.resolveCLI()

    private var cancellables = Set<AnyCancellable>()

    init() {
        reload()
        // When selection changes, load that profile.
        $selectedID
            .removeDuplicates()
            .sink { [weak self] id in
                guard let self = self, let id = id else { return }
                self.openSelected(id: id)
            }
            .store(in: &cancellables)
    }

    // ─── filesystem ────────────────────────────────────────

    static func profilesDir() -> URL {
        // Matches `dirs::config_dir()/sandkasten/profiles` from the CLI.
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? URL(fileURLWithPath: NSHomeDirectory()).appendingPathComponent("Library/Application Support")
        return base.appendingPathComponent("sandkasten/profiles", isDirectory: true)
    }

    private static func resolveCLI() -> String {
        // $PATH
        if let path = ProcessInfo.processInfo.environment["PATH"] {
            for dir in path.split(separator: ":") {
                let p = "\(dir)/sandkasten"
                if FileManager.default.isExecutableFile(atPath: p) {
                    return p
                }
            }
        }
        // Development fallback: <repo>/target/release/sandkasten
        let cwd = FileManager.default.currentDirectoryPath
        let candidates = [
            "\(cwd)/target/release/sandkasten",
            "\(cwd)/../target/release/sandkasten",
            "/usr/local/bin/sandkasten",
            "/opt/homebrew/bin/sandkasten",
        ]
        for p in candidates {
            if FileManager.default.isExecutableFile(atPath: p) {
                return p
            }
        }
        return "sandkasten"   // let the user see the error when we run it
    }

    // ─── listing ───────────────────────────────────────────

    func reload() {
        builtins = Self.listBuiltins(cli: cliPath)
        userProfiles = Self.listUserProfiles()
        if selectedID == nil, let first = builtins.first {
            selectedID = first.id
        }
    }

    private static func listBuiltins(cli: String) -> [ProfileEntry] {
        let out = runCapturing(cli, ["templates"]) ?? ""
        var items: [ProfileEntry] = []
        for raw in out.split(separator: "\n") {
            let trimmed = raw.trimmingCharacters(in: .whitespaces)
            if trimmed.isEmpty { continue }
            let parts = trimmed.components(separatedBy: "  ")
                .map { $0.trimmingCharacters(in: .whitespaces) }
                .filter { !$0.isEmpty }
            guard parts.count >= 2 else { continue }
            items.append(.init(
                id: "builtin:\(parts[0])",
                name: parts[0],
                kind: .builtin,
                description: parts[1]
            ))
        }
        return items
    }

    private static func listUserProfiles() -> [ProfileEntry] {
        let dir = profilesDir()
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        guard let entries = try? FileManager.default.contentsOfDirectory(atPath: dir.path) else {
            return []
        }
        var out: [ProfileEntry] = []
        for e in entries.sorted() where e.hasSuffix(".toml") {
            let name = String(e.dropLast(5))
            let text = (try? String(contentsOf: dir.appendingPathComponent(e), encoding: .utf8)) ?? ""
            let desc = Self.extractDescription(text)
            out.append(.init(
                id: "user:\(name)",
                name: name,
                kind: .user,
                description: desc
            ))
        }
        return out
    }

    private static func extractDescription(_ toml: String) -> String {
        for line in toml.split(separator: "\n") {
            let t = line.trimmingCharacters(in: .whitespaces)
            if t.hasPrefix("description") {
                if let eq = t.firstIndex(of: "=") {
                    let raw = t[t.index(after: eq)...].trimmingCharacters(in: .whitespaces)
                    return raw.trimmingCharacters(in: CharacterSet(charactersIn: "\"'"))
                }
            }
        }
        return ""
    }

    // ─── selection ─────────────────────────────────────────

    func selectedEntry() -> ProfileEntry? {
        guard let id = selectedID else { return nil }
        return (builtins + userProfiles).first { $0.id == id }
    }

    private func openSelected(id: String) {
        guard let entry = (builtins + userProfiles).first(where: { $0.id == id }) else { return }
        rawToml = loadRaw(for: entry) ?? "# profile not found"
        // Pass the absolute path for user profiles so we're independent of
        // the CLI's config-dir resolution. Built-ins resolve by name.
        let target: String = {
            switch entry.kind {
            case .builtin: return entry.name
            case .user:    return Self.profilesDir()
                .appendingPathComponent("\(entry.name).toml").path
            }
        }()
        let (out, err, rc) = runCapturingVerbose(cliPath, ["explain", target])
        if rc == 0, let out = out, !out.isEmpty {
            explanation = out
            statusLine = "Loaded \(entry.name)"
        } else {
            explanation = "(sandkasten explain failed; exit=\(rc))\n\n"
                + (err ?? "")
                + "\ncli path: \(cliPath)"
                + "\ntarget:   \(target)"
            statusLine = "Could not render \(entry.name)"
        }
        isDirty = false
    }

    func loadRaw(for entry: ProfileEntry) -> String? {
        switch entry.kind {
        case .user:
            return try? String(
                contentsOf: Self.profilesDir().appendingPathComponent("\(entry.name).toml"),
                encoding: .utf8
            )
        case .builtin:
            // The CLI's `render` prints generated policy, not TOML.
            // For the source TOML of a built-in we shell to `init` into a
            // tempfile, then read it back.
            let tmp = FileManager.default.temporaryDirectory
                .appendingPathComponent("sk-preview-\(entry.name).toml")
            _ = runCapturing(cliPath, ["init", "--template", entry.name, "-o", tmp.path])
            let text = (try? String(contentsOf: tmp, encoding: .utf8))
            try? FileManager.default.removeItem(at: tmp)
            return text
        }
    }

    // ─── mutations ─────────────────────────────────────────

    func markDirty() {
        if !isDirty {
            isDirty = true
            statusLine = "Modified"
        }
    }

    func save() {
        guard let entry = selectedEntry(), entry.kind == .user else {
            statusLine = "Built-in templates are read-only. Duplicate first."
            return
        }
        let path = Self.profilesDir().appendingPathComponent("\(entry.name).toml")
        do {
            try rawToml.write(to: path, atomically: true, encoding: .utf8)
            // Validate via the CLI.
            if let out = runCapturing(cliPath, ["check", entry.name]), out.contains("ok") {
                isDirty = false
                statusLine = "Saved — \(entry.name) validated"
                reload()
            } else {
                statusLine = "Saved, but validation reported a problem"
            }
        } catch {
            pendingError = "Save failed: \(error.localizedDescription)"
        }
    }

    func duplicate(as newName: String) {
        let sanitized = newName.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !sanitized.isEmpty,
              sanitized.range(of: "^[A-Za-z0-9_-]+$", options: .regularExpression) != nil
        else {
            pendingError = "Name must match [A-Za-z0-9_-]+"
            return
        }
        let dst = Self.profilesDir().appendingPathComponent("\(sanitized).toml")
        if FileManager.default.fileExists(atPath: dst.path) {
            pendingError = "\(sanitized) already exists"
            return
        }
        do {
            try rawToml.write(to: dst, atomically: true, encoding: .utf8)
            reload()
            selectedID = "user:\(sanitized)"
            statusLine = "Duplicated as \(sanitized)"
        } catch {
            pendingError = "Duplicate failed: \(error.localizedDescription)"
        }
    }

    func delete() {
        guard let entry = selectedEntry(), entry.kind == .user else { return }
        let path = Self.profilesDir().appendingPathComponent("\(entry.name).toml")
        do {
            try FileManager.default.removeItem(at: path)
            selectedID = builtins.first?.id
            reload()
            statusLine = "Deleted \(entry.name)"
        } catch {
            pendingError = "Delete failed: \(error.localizedDescription)"
        }
    }

    func requestNewProfile() {
        newProfilePromptVisible = true
    }

    func createNew(name: String, basedOn template: String) {
        let sanitized = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !sanitized.isEmpty,
              sanitized.range(of: "^[A-Za-z0-9_-]+$", options: .regularExpression) != nil
        else {
            pendingError = "Name must match [A-Za-z0-9_-]+"
            return
        }
        let stub = """
        name = "\(sanitized)"
        description = "New sandkasten profile."
        extends = "\(template)"

        [filesystem]
        allow_metadata_read = true

        [env]
        pass = ["PATH", "HOME", "TERM", "LANG"]
        """
        let dst = Self.profilesDir().appendingPathComponent("\(sanitized).toml")
        do {
            try stub.write(to: dst, atomically: true, encoding: .utf8)
            reload()
            selectedID = "user:\(sanitized)"
            statusLine = "Created \(sanitized)"
        } catch {
            pendingError = "Create failed: \(error.localizedDescription)"
        }
    }

    // ─── launch ────────────────────────────────────────────

    /// Opens a new Terminal window and runs `sandkasten shell <profile>` there,
    /// so the user gets an interactive sandboxed shell with the current profile.
    func launchShell() {
        guard let entry = selectedEntry() else { return }
        let cli = cliPath.replacingOccurrences(of: "\"", with: "\\\"")
        let name = entry.name.replacingOccurrences(of: "\"", with: "\\\"")
        let script = """
        tell application "Terminal"
            activate
            do script "\(cli) -v shell \(name)"
        end tell
        """
        let task = Process()
        task.launchPath = "/usr/bin/osascript"
        task.arguments = ["-e", script]
        try? task.run()
        statusLine = "Spawned interactive shell for \(entry.name)"
    }

    /// Opens the profile in the default editor (for users who prefer vim/Emacs).
    func openInEditor() {
        guard let entry = selectedEntry(), entry.kind == .user else { return }
        let path = Self.profilesDir().appendingPathComponent("\(entry.name).toml").path
        NSWorkspace.shared.open(URL(fileURLWithPath: path))
    }
}

// Shell helper — blocking. Returns stdout on success, nil on failure.
@discardableResult
func runCapturing(_ path: String, _ args: [String]) -> String? {
    runCapturingVerbose(path, args).stdout
}

/// Full-fidelity invocation: stdout, stderr, and exit code all separately.
/// Lets the UI surface which process tier failed when debugging config or
/// missing binaries.
func runCapturingVerbose(_ path: String, _ args: [String]) -> (stdout: String?, stderr: String?, rc: Int32) {
    let task = Process()
    task.launchPath = path
    task.arguments = args
    let outPipe = Pipe()
    let errPipe = Pipe()
    task.standardOutput = outPipe
    task.standardError = errPipe
    do {
        try task.run()
    } catch {
        return (nil, "spawn failed: \(error.localizedDescription)", -1)
    }
    let outData = outPipe.fileHandleForReading.readDataToEndOfFile()
    let errData = errPipe.fileHandleForReading.readDataToEndOfFile()
    task.waitUntilExit()
    return (
        String(data: outData, encoding: .utf8),
        String(data: errData, encoding: .utf8),
        task.terminationStatus
    )
}
