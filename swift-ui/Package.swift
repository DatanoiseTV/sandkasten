// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "SandkastenApp",
    platforms: [
        // ContentUnavailableView + other SwiftUI niceties are macOS 14+.
        .macOS(.v14)
    ],
    products: [
        .executable(name: "SandkastenApp", targets: ["SandkastenApp"]),
    ],
    targets: [
        .executableTarget(
            name: "SandkastenApp",
            path: "Sources/SandkastenApp"
        ),
    ]
)
