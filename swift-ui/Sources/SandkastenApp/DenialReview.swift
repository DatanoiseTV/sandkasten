import SwiftUI
import AppKit

/// Smart denial review. Groups incoming denials by common
/// (profile, op, path-prefix) and offers Always Allow / Once /
/// Always Deny / Customize for each cluster.
///
/// "Smart" here is deliberately small: prefix-collapse sibling reads
/// (e.g. `~/.config/foo/file1`, `~/.config/foo/file2` → "Allow
/// `~/.config/foo/`"), flag known sensitive paths (`~/.ssh`,
/// `~/.aws`, keychains) as "high-risk — confirm again", and offer
/// the right-shape rule for the op kind (`file-read*`/`file-write*`/
/// `network-outbound`/`mach-lookup`).
struct DenialReviewView: View {
    @EnvironmentObject var store: ProfileStore
    @EnvironmentObject var events: EventWatcher
    @State private var pendingConfirm: ConfirmAction?

    var body: some View {
        let groups = clusterDenials(events.denials.filter { !$0.resolved })

        VStack(alignment: .leading, spacing: 0) {
            header
            Divider()
            if groups.isEmpty {
                ContentUnavailableView(
                    "No denials to review",
                    systemImage: "checkmark.shield.fill",
                    description: Text(
                        "Sandkasten will list denied paths and hosts here as your sandboxed processes hit them. Toggle 'Watch sandkasten runs' in the menu bar to start collecting events."
                    )
                )
                .padding(.vertical, 40)
                Spacer()
            } else {
                ScrollView(.vertical) {
                    LazyVStack(alignment: .leading, spacing: 8) {
                        ForEach(groups) { g in
                            DenialClusterRow(group: g) { action in
                                handle(action: action, group: g)
                            }
                        }
                    }
                    .padding(.horizontal, 18)
                    .padding(.vertical, 14)
                }
            }
        }
        .alert(item: $pendingConfirm) { action in
            Alert(
                title: Text(action.title),
                message: Text(action.message),
                primaryButton: .destructive(Text("Confirm")) { action.run() },
                secondaryButton: .cancel()
            )
        }
    }

    private var header: some View {
        HStack(alignment: .center, spacing: 14) {
            Image(systemName: "exclamationmark.triangle.fill")
                .font(.system(size: 22, weight: .semibold))
                .foregroundStyle(.orange)
            VStack(alignment: .leading, spacing: 2) {
                Text("Recent denials")
                    .font(.title2.weight(.semibold))
                Text("Each row is a cluster of related denied accesses. Acting on a row patches the corresponding profile.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            Button {
                events.clearResolved()
            } label: {
                Label("Clear resolved", systemImage: "tray")
            }
            .help("Hide rows you've already acted on.")
        }
        .padding(.horizontal, 24)
        .padding(.vertical, 16)
    }

    // ─── decision dispatch ────────────────────────────────────

    private func handle(action: DenialAction, group: DenialGroup) {
        switch action {
        case .once:
            for d in group.items { events.resolveDenial(d.id) }

        case .alwaysAllow:
            if isHighRisk(path: group.canonicalPath) {
                pendingConfirm = ConfirmAction(
                    title: "Allow access to a sensitive path?",
                    message: "\(group.canonicalPath) typically contains credentials. Adding it to '\(group.profile)' weakens the sandbox meaningfully.",
                    run: { applyAllow(group: group) }
                )
            } else {
                applyAllow(group: group)
            }

        case .alwaysDeny:
            applyDeny(group: group)

        case .customize:
            store.selectedID = "user:\(group.profile)"
            NSApp.activate(ignoringOtherApps: true)
            // The SwiftUI environment doesn't expose openWindow from
            // here without threading it; the user can use Cmd-Shift-E
            // from the menu bar to open the editor.
            for d in group.items { events.resolveDenial(d.id) }
        }
    }

    private func applyAllow(group: DenialGroup) {
        let key = ruleKey(for: group.opCategory)
        let path = group.canonicalPath
        let ok = store.appendArrayEntry(profile: group.profile, section: "filesystem", key: key, value: path)
        if ok {
            for d in group.items { events.resolveDenial(d.id) }
        }
    }

    private func applyDeny(group: DenialGroup) {
        let path = group.canonicalPath
        let ok = store.appendArrayEntry(profile: group.profile, section: "filesystem", key: "deny", value: path)
        if ok {
            for d in group.items { events.resolveDenial(d.id) }
        }
    }

    private func ruleKey(for category: OpCategory) -> String {
        switch category {
        case .read:    return "read"
        case .write:   return "read_write"
        case .network: return "outbound_tcp"
        case .mach:    return "mach_services"
        case .other:   return "read"  // best-guess fallback
        }
    }

    private func isHighRisk(path: String) -> Bool {
        let p = path.lowercased()
        let markers = ["/.ssh", "/.aws", "/.gnupg", "/.kube", "/.docker", "/.netrc",
                       "/keychains", "/com.apple.tcc", "/.password-store",
                       "/.bash_history", "/.zsh_history"]
        return markers.contains(where: { p.contains($0) })
    }
}

// ─── cluster types ────────────────────────────────────────────

/// One row in the review = one (op-category, profile, path-prefix)
/// cluster of denials.
struct DenialGroup: Identifiable {
    let id: String
    let profile: String
    let opCategory: OpCategory
    let opLabel: String
    let canonicalPath: String     // either the common prefix or the single path
    let items: [DenialItem]
    let totalCount: Int

    var subtitle: String {
        let n = items.count
        if n <= 1 {
            return "\(totalCount)× from \(profile)"
        }
        return "\(n) related paths · \(totalCount) total denials · \(profile)"
    }
}

enum OpCategory {
    case read, write, network, mach, other

    var label: String {
        switch self {
        case .read:    return "Read"
        case .write:   return "Write"
        case .network: return "Outbound"
        case .mach:    return "Mach service"
        case .other:   return "Access"
        }
    }
}

enum DenialAction {
    case once
    case alwaysAllow
    case alwaysDeny
    case customize
}

/// `Identifiable` wrapper around a confirmable destructive action so
/// SwiftUI's `.alert(item:)` can drive the confirm sheet.
struct ConfirmAction: Identifiable {
    let id: UUID = UUID()
    let title: String
    let message: String
    let run: () -> Void
}

// ─── clustering ───────────────────────────────────────────────

/// Group denials into actionable rows. Heuristics:
///   • same (profile, op-category, immediate parent dir) → one row
///   • single denial with no siblings → one-row cluster
///   • Mach lookups → grouped by service prefix (com.apple.*)
///   • outbound network → grouped as-is (host:port is already terse)
private func clusterDenials(_ denials: [DenialItem]) -> [DenialGroup] {
    // Bucket by (profile, op-category, parent-dir-or-host).
    var buckets: [String: [DenialItem]] = [:]
    var keyOrder: [String] = []
    for d in denials {
        let cat = categorize(op: d.op)
        let prefix = clusterKey(target: d.target, category: cat)
        let key = "\(d.profile)|\(cat)|\(prefix)"
        if buckets[key] == nil { keyOrder.append(key) }
        buckets[key, default: []].append(d)
    }
    return keyOrder.compactMap { key -> DenialGroup? in
        guard let items = buckets[key], let first = items.first else { return nil }
        let cat = categorize(op: first.op)
        let canonical = items.count > 1
            ? clusterKey(target: first.target, category: cat) + (cat == .read || cat == .write ? "/" : "")
            : first.target
        return DenialGroup(
            id: key,
            profile: first.profile,
            opCategory: cat,
            opLabel: first.op,
            canonicalPath: canonical,
            items: items,
            totalCount: items.reduce(0) { $0 + $1.count }
        )
    }
}

private func categorize(op: String) -> OpCategory {
    let o = op.lowercased()
    if o.contains("file-write") || o.contains("file-mkdir") || o.contains("file-link") || o.contains("file-rename") {
        return .write
    }
    if o.contains("file-read") || o.contains("file-ioctl") {
        return .read
    }
    if o.contains("network") || o.contains("connect") || o.contains("bind") {
        return .network
    }
    if o.contains("mach") {
        return .mach
    }
    return .other
}

private func clusterKey(target: String, category: OpCategory) -> String {
    switch category {
    case .read, .write:
        // Group by parent dir.
        if let last = target.lastIndex(of: "/"), last != target.startIndex {
            return String(target[..<last])
        }
        return target
    case .mach:
        // com.apple.foo.bar → com.apple.foo
        let parts = target.split(separator: ".")
        if parts.count >= 3 { return parts.prefix(3).joined(separator: ".") }
        return target
    case .network, .other:
        return target
    }
}

// ─── row UI ───────────────────────────────────────────────────

struct DenialClusterRow: View {
    let group: DenialGroup
    let onAction: (DenialAction) -> Void
    @State private var expanded: Bool = false

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .top, spacing: 12) {
                Image(systemName: iconName)
                    .font(.system(size: 16, weight: .semibold))
                    .foregroundStyle(iconColor)
                    .frame(width: 22)
                VStack(alignment: .leading, spacing: 2) {
                    HStack(spacing: 6) {
                        Text(group.opCategory.label)
                            .font(.headline)
                        Text(group.canonicalPath)
                            .font(.system(.body, design: .monospaced))
                            .lineLimit(1)
                            .truncationMode(.middle)
                    }
                    Text(group.subtitle)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
            }

            HStack(spacing: 8) {
                Button("Always Allow") { onAction(.alwaysAllow) }
                    .buttonStyle(.borderedProminent)
                Button("Once") { onAction(.once) }
                Button("Always Deny") { onAction(.alwaysDeny) }
                Button("Customize…") { onAction(.customize) }
                Spacer()
                if group.items.count > 1 {
                    Button(expanded ? "Hide paths" : "Show \(group.items.count) paths") {
                        expanded.toggle()
                    }
                    .buttonStyle(.borderless)
                }
            }
            .controlSize(.small)

            if expanded {
                VStack(alignment: .leading, spacing: 2) {
                    ForEach(group.items, id: \.id) { d in
                        Text("• \(d.target)  (\(d.count)×)")
                            .font(.system(.caption, design: .monospaced))
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                            .truncationMode(.middle)
                    }
                }
                .padding(.leading, 34)
            }
        }
        .padding(12)
        .background(
            RoundedRectangle(cornerRadius: 8, style: .continuous)
                .fill(Color(nsColor: .controlBackgroundColor))
        )
        .overlay(
            RoundedRectangle(cornerRadius: 8, style: .continuous)
                .stroke(Color.secondary.opacity(0.2), lineWidth: 1)
        )
    }

    private var iconName: String {
        switch group.opCategory {
        case .read:    return "doc.text"
        case .write:   return "square.and.pencil"
        case .network: return "network"
        case .mach:    return "cpu"
        case .other:   return "questionmark.circle"
        }
    }

    private var iconColor: Color {
        switch group.opCategory {
        case .read:    return .blue
        case .write:   return .orange
        case .network: return .purple
        case .mach:    return .gray
        case .other:   return .secondary
        }
    }
}
