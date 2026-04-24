import SwiftUI
import AppKit

@main
struct SandkastenApp: App {
    @StateObject private var store = ProfileStore()
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate

    var body: some Scene {
        WindowGroup("sandkasten") {
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

        Settings {
            PreferencesView()
                .environmentObject(store)
        }
    }
}

/// Handles the bits SwiftUI doesn't cover directly: Dock activation policy,
/// window close → app-quits, app-terminated-on-last-window.
final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        // Show in Dock + Cmd-Tab, not as a menu-bar-only background helper.
        NSApp.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        true
    }
}
