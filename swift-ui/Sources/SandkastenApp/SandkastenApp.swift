import SwiftUI
import AppKit

@main
struct SandkastenApp: App {
    @StateObject private var store = ProfileStore()
    @StateObject private var events = EventWatcher()
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate

    var body: some Scene {
        // Menu-bar status item — the primary surface. SwiftUI's
        // `MenuBarExtra` gives us a popover-style menu without the
        // Dock icon (that's the `.accessory` activation policy in
        // AppDelegate). The icon is the system "shield" symbol.
        MenuBarExtra("sandkasten", systemImage: "shield.lefthalf.filled") {
            MenuBarMenu()
                .environmentObject(store)
                .environmentObject(events)
        }
        .menuBarExtraStyle(.menu)

        // The rule-editor surface. Opened on demand from the menu /
        // from the global "Editor…" menu item, NOT shown at launch.
        // The window is a regular `Window` (single-instance) rather
        // than a `WindowGroup` so the menu's "Open Editor" idempotently
        // brings the same window to the front.
        Window("sandkasten — Profiles", id: "editor") {
            ContentView()
                .environmentObject(store)
                .frame(minWidth: 960, minHeight: 600)
        }
        .windowStyle(.titleBar)
        .windowResizability(.contentSize)
        .commands {
            CommandGroup(replacing: .newItem) {
                Button("New Profile…") { store.requestNewProfile() }
                    .keyboardShortcut("n", modifiers: .command)
            }
            CommandGroup(after: .toolbar) {
                Button("Refresh Profiles") { store.reload() }
                    .keyboardShortcut("r", modifiers: .command)
                Divider()
                Button("Open in External Editor") { store.openInEditor() }
                    .keyboardShortcut("e", modifiers: .command)
            }
            CommandGroup(replacing: .help) {
                Button("sandkasten Documentation") {
                    if let url = URL(string: "https://github.com/DatanoiseTV/sandkasten") {
                        NSWorkspace.shared.open(url)
                    }
                }
            }
        }

        // The denial-review surface. Opened automatically when new
        // denials arrive (from EventWatcher) AND the user has the
        // "show prompts" preference on. Also reachable from the menu.
        Window("sandkasten — Recent Denials", id: "denials") {
            DenialReviewView()
                .environmentObject(store)
                .environmentObject(events)
                .frame(minWidth: 620, minHeight: 420)
        }
        .windowStyle(.titleBar)
        .windowResizability(.contentSize)

        Settings {
            PreferencesView()
                .environmentObject(store)
                .environmentObject(events)
        }
    }
}

/// Handles the bits SwiftUI doesn't cover directly: activation policy
/// (no Dock icon — menu-bar primary), keep-running-on-window-close
/// (a menu-bar app shouldn't quit when you close its editor window),
/// and starting the event watcher.
final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        DebugLog.boot()
        // Menu-bar primary: hide from Dock + Cmd-Tab. The user can
        // still cmd-Q to quit from the menu.
        NSApp.setActivationPolicy(.accessory)
    }

    /// Closing the editor window should NOT quit the app — we're a
    /// menu-bar resident. The user quits via the status menu.
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        false
    }
}
