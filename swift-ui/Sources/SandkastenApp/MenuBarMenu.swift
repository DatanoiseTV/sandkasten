import SwiftUI
import AppKit

/// Status-bar menu surface. Kept deliberately small — anything that
/// needs more than a handful of clicks goes into the editor or
/// denial-review windows.
struct MenuBarMenu: View {
    @EnvironmentObject var store: ProfileStore
    @EnvironmentObject var events: EventWatcher
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        // Header (visible label, not selectable in `.menu` style).
        Text("sandkasten")
            .font(.headline)

        Divider()

        // Quick action: open the rule editor.
        Button("Open Editor…") {
            openWindow(id: "editor")
            NSApp.activate(ignoringOtherApps: true)
        }
        .keyboardShortcut("e", modifiers: [.command, .shift])

        // Profiles submenu — left-click to start an interactive
        // sandboxed shell with that profile.
        Menu("Profiles") {
            if store.userProfiles.isEmpty {
                Text("No user profiles").foregroundStyle(.secondary)
            } else {
                Section("Yours") {
                    ForEach(store.userProfiles, id: \.id) { p in
                        Button(p.name) {
                            store.selectedID = p.id
                            store.launchShell()
                        }
                    }
                }
            }
            Section("Built-in") {
                ForEach(store.builtins, id: \.id) { p in
                    Button(p.name) {
                        store.selectedID = p.id
                        store.launchShell()
                    }
                }
            }
        }

        Divider()

        // Recent activity summary. The numbers come from the event
        // watcher; click opens the denial-review window.
        if events.unreviewedDenialCount > 0 {
            Button {
                openWindow(id: "denials")
                NSApp.activate(ignoringOtherApps: true)
            } label: {
                Label(
                    "Review \(events.unreviewedDenialCount) denial\(events.unreviewedDenialCount == 1 ? "" : "s")…",
                    systemImage: "exclamationmark.triangle.fill"
                )
            }
            .keyboardShortcut("d", modifiers: [.command, .shift])
        } else {
            Text("No new denials").foregroundStyle(.secondary)
        }

        if events.recentRunCount > 0 {
            Text("\(events.recentRunCount) recent run\(events.recentRunCount == 1 ? "" : "s")")
                .foregroundStyle(.secondary)
        }

        Divider()

        // Watch toggle — the user opts the UI in/out without quitting
        // the app. When off, the watcher stops, no notifications fire,
        // and CLI-side runs without `SANDKASTEN_EVENTS_DIR` simply
        // emit nothing (server users see exactly that already).
        Toggle("Watch sandkasten runs", isOn: $events.watchEnabled)
            .toggleStyle(.checkbox)

        Divider()

        SettingsLink {
            Text("Settings…")
        }
        .keyboardShortcut(",", modifiers: .command)

        Button("Quit sandkasten") {
            NSApp.terminate(nil)
        }
        .keyboardShortcut("q", modifiers: .command)
    }
}
