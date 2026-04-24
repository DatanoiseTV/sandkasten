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
    @Published var profile: Profile = Profile()      // parsed model
    @Published var parseError: String?                // TOML parse issue
    @Published var explanation: String = ""
    @Published var statusLine: String = "Ready"
    @Published var isDirty: Bool = false
    @Published var pendingError: String?
    @Published var newProfilePromptVisible: Bool = false
    /// When true, profile edits in the form aren't mirrored back to rawToml.
    /// Prevents feedback loops when we programmatically reload.
    var suppressRoundTrip: Bool = false

    /// Resolved path to the `sandkasten` CLI. Falls back through bundled
    /// binary, $PATH, Homebrew, and repo checkout — see `resolveCLI`.
    @Published var cliPath: String = ProfileStore.resolveCLI()

    private var cancellables = Set<AnyCancellable>()

    init() {
        reload()
        $selectedID
            .removeDuplicates()
            .sink { [weak self] id in
                guard let self = self, let id = id else { return }
                self.openSelected(id: id)
            }
            .store(in: &cancellables)

        // Persist cli-path edits so the user only has to set it once.
        $cliPath
            .removeDuplicates()
            .dropFirst()
            .sink { value in
                UserDefaults.standard.set(value, forKey: "cliPath")
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
        let fm = FileManager.default

        // 1. User override persisted in UserDefaults.
        if let override = UserDefaults.standard.string(forKey: "cliPath"),
           !override.isEmpty,
           fm.isExecutableFile(atPath: override)
        {
            return override
        }

        // 2. Bundled CLI inside this .app's Resources/. build-app.sh
        //    installs it there — we can't use Contents/MacOS/ because the
        //    UI's own binary `Sandkasten` case-collides with `sandkasten`
        //    on case-insensitive macOS filesystems.
        if let bundled = Bundle.main.url(forResource: "sandkasten", withExtension: nil),
           fm.isExecutableFile(atPath: bundled.path)
        {
            return bundled.path
        }

        // 3. $PATH. When the app is launched from Finder via `open`, PATH
        //    is typically `/usr/bin:/bin:/usr/sbin:/sbin` and misses
        //    Homebrew. We also probe the canonical Homebrew locations
        //    directly as a fallback.
        let pathEnv = ProcessInfo.processInfo.environment["PATH"] ?? ""
        var dirs = pathEnv.split(separator: ":").map(String.init)
        dirs.append(contentsOf: [
            "/opt/homebrew/bin",
            "/usr/local/bin",
            "/usr/local/sbin",
            "/opt/local/bin",
        ])
        for dir in dirs {
            let p = "\(dir)/sandkasten"
            if fm.isExecutableFile(atPath: p) { return p }
        }

        // 4. Development fallback — sibling of the repo checkout.
        let cwd = fm.currentDirectoryPath
        for p in [
            "\(cwd)/target/release/sandkasten",
            "\(cwd)/../target/release/sandkasten",
            NSHomeDirectory() + "/dev/priv/sandkasten/target/release/sandkasten",
        ] {
            if fm.isExecutableFile(atPath: p) { return p }
        }

        // Nothing found — return the bare name so the error surfaces
        // once the user tries an operation.
        return "sandkasten"
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
        suppressRoundTrip = true
        defer { suppressRoundTrip = false }

        let raw = loadRaw(for: entry) ?? "# profile not found"
        rawToml = raw
        DebugLog.line("open", "\(entry.kind == .user ? "user" : "builtin"):\(entry.name) (\(raw.count) bytes)")
        reparseFromRaw(context: entry.name)
        refreshExplanation(for: entry)
        isDirty = false
        statusLine = "Loaded \(entry.name)"
    }

    func reparseFromRaw(context: String = "<unknown>") {
        do {
            profile = try Profile.parse(rawToml)
            parseError = nil
            if profile.parseWarnings.isEmpty {
                DebugLog.line("parse", "\(context): ok")
            } else {
                DebugLog.line("parse", "\(context): ok with \(profile.parseWarnings.count) section warning(s)")
                for w in profile.parseWarnings {
                    DebugLog.line("parse-warn", "  \(w)")
                }
                DebugLog.block("parse-warn", "raw TOML that produced the warnings (\(context))", rawToml)
            }
        } catch {
            parseError = "TOML parse: \(error.localizedDescription)"
            DebugLog.line("parse", "\(context): FAILED — \(error.localizedDescription)")
            DebugLog.block("parse-fail", "raw TOML that failed to parse (\(context))", rawToml)
            // leave `profile` as it was; form stays editable with the last good value
        }
    }

    func refreshExplanation(for entry: ProfileEntry? = nil) {
        let use = entry ?? selectedEntry()
        guard let e = use else { return }
        let target: String = {
            switch e.kind {
            case .builtin: return e.name
            case .user:    return Self.profilesDir()
                .appendingPathComponent("\(e.name).toml").path
            }
        }()
        let (out, err, rc) = runCapturingVerbose(cliPath, ["explain", target])
        if rc == 0, let out = out, !out.isEmpty {
            explanation = out
        } else {
            explanation = "(sandkasten explain failed; exit=\(rc))\n\n"
                + (err ?? "")
                + "\ncli path: \(cliPath)"
                + "\ntarget:   \(target)"
        }
    }

    /// Re-serialize the in-memory `profile` back to `rawToml`. Called
    /// from form-editor bindings.
    func reserializeFromForm() {
        guard !suppressRoundTrip else { return }
        do {
            let toml = try profile.toTOML()
            if toml != rawToml {
                rawToml = toml
                markDirty()
            }
            parseError = nil
        } catch {
            parseError = "TOML encode: \(error.localizedDescription)"
            DebugLog.line("encode-fail", "\(error.localizedDescription)")
        }
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
