import SwiftUI

struct ContentView: View {
    @EnvironmentObject var store: ProfileStore
    @State private var selectedTab: DetailTab = .policy
    @State private var duplicateDialog: Bool = false

    var body: some View {
        NavigationSplitView {
            SidebarView()
                .navigationSplitViewColumnWidth(min: 220, ideal: 260, max: 360)
        } detail: {
            if let entry = store.selectedEntry() {
                DetailView(entry: entry, tab: $selectedTab)
            } else {
                ContentUnavailableView(
                    "Select a profile",
                    systemImage: "shield.lefthalf.filled",
                    description: Text("Pick one on the left, or press ⌘N to create a new one.")
                )
            }
        }
        .navigationTitle("sandkasten")
        .navigationSubtitle(store.selectedEntry()?.description ?? "")
        .toolbar {
            ToolbarItem(placement: .principal) {
                // Subtle, right-aligned status indicator.
                Text(store.statusLine)
                    .font(.caption)
                    .foregroundStyle(store.isDirty ? .orange : .secondary)
                    .lineLimit(1)
                    .frame(maxWidth: 280, alignment: .trailing)
            }
            ToolbarItemGroup(placement: .primaryAction) {
                if let entry = store.selectedEntry() {
                    if entry.kind == .user {
                        Button {
                            store.save()
                        } label: {
                            Label("Save", systemImage: "checkmark.circle.fill")
                        }
                        .disabled(!store.isDirty)
                        .keyboardShortcut("s", modifiers: .command)
                        .help("Save changes (⌘S)")
                    }

                    Button {
                        store.pendingError = nil
                        duplicateDialog = true
                    } label: {
                        Label("Duplicate", systemImage: "plus.square.on.square")
                    }
                    .keyboardShortcut("d", modifiers: .command)
                    .help("Duplicate into a new user profile (⌘D)")

                    Button {
                        store.launchShell()
                    } label: {
                        Label("Open Shell", systemImage: "terminal.fill")
                    }
                    .keyboardShortcut(.return, modifiers: .command)
                    .help("Open a sandboxed shell in Terminal (⌘↩)")

                    if entry.kind == .user {
                        Menu {
                            Button(role: .destructive) { store.delete() } label: {
                                Label("Delete profile…", systemImage: "trash")
                            }
                        } label: {
                            Label("More", systemImage: "ellipsis.circle")
                        }
                    }
                }
            }
        }
        .alert("Error", isPresented: .constant(store.pendingError != nil)) {
            Button("OK") { store.pendingError = nil }
        } message: {
            Text(store.pendingError ?? "")
        }
        .sheet(isPresented: $duplicateDialog) {
            DuplicateSheet(isPresented: $duplicateDialog)
                .environmentObject(store)
        }
        .sheet(isPresented: $store.newProfilePromptVisible) {
            NewProfileSheet()
                .environmentObject(store)
        }
    }
}

// ─── sidebar ─────────────────────────────────────────────────────────────

struct SidebarView: View {
    @EnvironmentObject var store: ProfileStore

    var body: some View {
        List(selection: $store.selectedID) {
            Section {
                if store.userProfiles.isEmpty {
                    HStack(spacing: 8) {
                        Image(systemName: "plus.circle")
                            .foregroundStyle(.tertiary)
                        Text("No user profiles yet.")
                            .foregroundStyle(.secondary)
                    }
                    .font(.caption)
                    .padding(.vertical, 2)
                }
                ForEach(store.userProfiles, id: \.id) { entry in
                    ProfileRow(entry: entry)
                        .tag(entry.id)
                }
            } header: {
                SidebarSectionHeader(title: "Your profiles",
                                     action: { store.requestNewProfile() },
                                     actionSymbol: "plus",
                                     help: "New profile (⌘N)")
            }

            Section {
                ForEach(store.builtins, id: \.id) { entry in
                    ProfileRow(entry: entry)
                        .tag(entry.id)
                }
            } header: {
                SidebarSectionHeader(title: "Built-in templates")
            }
        }
        .listStyle(.sidebar)
        .listRowInsets(EdgeInsets(top: 2, leading: 0, bottom: 2, trailing: 0))
    }
}

struct SidebarSectionHeader: View {
    let title: String
    var action: (() -> Void)? = nil
    var actionSymbol: String? = nil
    var help: String? = nil

    var body: some View {
        HStack(alignment: .center, spacing: 6) {
            Text(title)
                .textCase(.uppercase)
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)
            Spacer(minLength: 0)
            if let action = action, let symbol = actionSymbol {
                Button(action: action) {
                    Image(systemName: symbol)
                        .font(.system(size: 11, weight: .semibold))
                }
                .buttonStyle(.borderless)
                .help(help ?? "")
            }
        }
        .padding(.vertical, 4)
    }
}

struct ProfileRow: View {
    let entry: ProfileEntry

    var body: some View {
        HStack(spacing: 10) {
            ZStack {
                RoundedRectangle(cornerRadius: 4, style: .continuous)
                    .fill(entry.kind == .user
                          ? Color.accentColor.opacity(0.15)
                          : Color.secondary.opacity(0.12))
                    .frame(width: 22, height: 22)
                Image(systemName: entry.kind == .user ? "doc.text.fill" : "shield.lefthalf.filled")
                    .font(.system(size: 11, weight: .semibold))
                    .foregroundStyle(entry.kind == .user ? Color.accentColor : .secondary)
            }
            VStack(alignment: .leading, spacing: 2) {
                Text(entry.name)
                    .font(.body)
                    .lineLimit(1)
                if !entry.description.isEmpty {
                    Text(entry.description)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .truncationMode(.tail)
                }
            }
            Spacer(minLength: 0)
        }
        .padding(.vertical, 3)
    }
}

// ─── detail ──────────────────────────────────────────────────────────────

enum DetailTab: String, CaseIterable, Identifiable {
    case form   = "Editor"
    case policy = "Policy"
    case toml   = "TOML"

    var id: String { rawValue }
}

struct DetailView: View {
    let entry: ProfileEntry
    @Binding var tab: DetailTab
    @EnvironmentObject var store: ProfileStore

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            Divider()
            tabBar
            Divider()
            contentArea
        }
        // Use material background for native macOS vibrancy.
        .background(.background)
    }

    private var header: some View {
        HStack(alignment: .center, spacing: 14) {
            Image(systemName: entry.kind == .user ? "doc.text.fill" : "shield.lefthalf.filled")
                .font(.system(size: 22, weight: .semibold))
                .foregroundStyle(entry.kind == .user ? Color.accentColor : .secondary)
                .frame(width: 28)
            VStack(alignment: .leading, spacing: 2) {
                Text(entry.name)
                    .font(.title2.weight(.semibold))
                Text(entry.kind == .user
                     ? "User profile"
                     : "Built-in template · read-only · Duplicate (⌘D) to edit")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 24)
        .padding(.vertical, 16)
    }

    private var tabBar: some View {
        HStack {
            Picker("View", selection: $tab) {
                ForEach(DetailTab.allCases) { t in
                    Text(t.rawValue).tag(t)
                }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .frame(maxWidth: 260)
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 24)
        .padding(.vertical, 10)
    }

    @ViewBuilder
    private var contentArea: some View {
        switch tab {
        case .form:
            FormView(readonly: entry.kind == .builtin)
        case .policy:
            ScrollView(.vertical, showsIndicators: true) {
                Text(store.explanation.isEmpty ? "(no explanation yet)" : store.explanation)
                    .font(.system(.callout, design: .monospaced))
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.horizontal, 24)
                    .padding(.vertical, 18)
            }
        case .toml:
            TomlEditor(readonly: entry.kind == .builtin)
        }
    }
}

struct TomlEditor: View {
    let readonly: Bool
    @EnvironmentObject var store: ProfileStore

    var body: some View {
        TextEditor(text: Binding(
            get: { store.rawToml },
            set: { newValue in
                guard !readonly else { return }
                if newValue != store.rawToml {
                    store.rawToml = newValue
                    store.markDirty()
                }
            }
        ))
        .font(.system(.callout, design: .monospaced))
        .autocorrectionDisabled(true)
        .textEditorStyle(.plain)
        .scrollContentBackground(.hidden)
        .padding(.horizontal, 20)
        .padding(.vertical, 16)
        .background(Color(nsColor: .textBackgroundColor))
    }
}

// ─── sheets ──────────────────────────────────────────────────────────────

struct DuplicateSheet: View {
    @Binding var isPresented: Bool
    @EnvironmentObject var store: ProfileStore
    @State private var newName: String = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            VStack(alignment: .leading, spacing: 6) {
                Text("Duplicate profile")
                    .font(.title3.weight(.semibold))
                Text("Creates a new user profile seeded with the current TOML.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }

            VStack(alignment: .leading, spacing: 6) {
                Text("Name")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                TextField("letters, digits, - and _", text: $newName)
                    .textFieldStyle(.roundedBorder)
                    .onAppear {
                        newName = (store.selectedEntry()?.name ?? "new-profile") + "-copy"
                    }
            }

            HStack(spacing: 10) {
                Spacer()
                Button("Cancel") { isPresented = false }
                    .keyboardShortcut(.cancelAction)
                Button("Duplicate") {
                    store.duplicate(as: newName)
                    if store.pendingError == nil { isPresented = false }
                }
                .keyboardShortcut(.defaultAction)
                .buttonStyle(.borderedProminent)
                .disabled(newName.isEmpty)
            }
        }
        .padding(EdgeInsets(top: 24, leading: 28, bottom: 24, trailing: 28))
        .frame(minWidth: 420)
    }
}

struct NewProfileSheet: View {
    @EnvironmentObject var store: ProfileStore
    @State private var newName: String = ""
    @State private var base: String = "self"

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            VStack(alignment: .leading, spacing: 6) {
                Text("New profile")
                    .font(.title3.weight(.semibold))
                Text("Starts from a built-in template — you can narrow or widen from there.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }

            VStack(alignment: .leading, spacing: 6) {
                Text("Name")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                TextField("letters, digits, - and _", text: $newName)
                    .textFieldStyle(.roundedBorder)
            }

            VStack(alignment: .leading, spacing: 6) {
                Text("Extend template")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Picker("Extend template", selection: $base) {
                    ForEach(store.builtins, id: \.id) { b in
                        Text(b.name).tag(b.name)
                    }
                }
                .labelsHidden()
                .pickerStyle(.menu)
            }

            HStack(spacing: 10) {
                Spacer()
                Button("Cancel") { store.newProfilePromptVisible = false }
                    .keyboardShortcut(.cancelAction)
                Button("Create") {
                    store.createNew(name: newName, basedOn: base)
                    if store.pendingError == nil {
                        store.newProfilePromptVisible = false
                    }
                }
                .keyboardShortcut(.defaultAction)
                .buttonStyle(.borderedProminent)
                .disabled(newName.isEmpty)
            }
        }
        .padding(EdgeInsets(top: 24, leading: 28, bottom: 24, trailing: 28))
        .frame(minWidth: 420)
    }
}

// ─── preferences ─────────────────────────────────────────────────────────

struct PreferencesView: View {
    @EnvironmentObject var store: ProfileStore

    var body: some View {
        Form {
            Section {
                LabeledContent("Path") {
                    TextField("", text: $store.cliPath)
                        .textFieldStyle(.roundedBorder)
                }
                LabeledContent("Discovery") {
                    Text("$PATH, then /opt/homebrew/bin, /usr/local/bin, and the repo's target/release.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            } header: {
                Text("sandkasten CLI")
                    .font(.headline)
            }

            Section {
                LabeledContent("Location") {
                    Text(ProfileStore.profilesDir().path)
                        .font(.system(.callout, design: .monospaced))
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                LabeledContent("User profiles") {
                    Text("\(store.userProfiles.count)")
                        .monospacedDigit()
                        .foregroundStyle(.secondary)
                }
            } header: {
                Text("Profiles directory")
                    .font(.headline)
            }
        }
        .formStyle(.grouped)
        .frame(width: 480, height: 280)
        .tabItem { Label("General", systemImage: "gear") }
    }
}
