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
    dependencies: [
        .package(url: "https://github.com/LebJe/TOMLKit.git", from: "0.6.0"),
    ],
    targets: [
        .executableTarget(
            name: "SandkastenApp",
            dependencies: [
                .product(name: "TOMLKit", package: "TOMLKit"),
            ],
            path: "Sources/SandkastenApp"
        ),
    ]
)
