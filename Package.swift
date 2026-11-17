// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "iMailSecure",
    platforms: [
        // Als String, weil `.v18`/`.v15` erst ab swift-tools-version 6.0
        // existieren; wir bleiben bei 5.9 (Sprachmodus wie im Xcode-Projekt).
        .iOS("18.0"),
        .macOS("15.0")
    ],
    products: [
        .library(name: "iMailSecure", targets: ["iMailSecure"])
    ],
    dependencies: [
        // SwiftMail – auf stabilen Commit gepinnt um API-Änderungen zu vermeiden
        .package(url: "https://github.com/Cocoanetics/SwiftMail.git", revision: "88c45cbd31b347b373f7c87e197be63eb95efbc2"),
        .package(url: "https://github.com/apple/swift-log.git", from: "1.4.0"),
    ],
    targets: [
        .target(
            name: "iMailSecure",
            dependencies: [
                .product(name: "SwiftMail", package: "SwiftMail"),
                .product(name: "Logging", package: "swift-log"),
                "imailpgp",
            ],
            path: "Sources/iMailSecure"
        ),
        .testTarget(
            name: "iMailSecureTests",
            dependencies: ["iMailSecure"],
            path: "Tests/iMailSecureTests"
        ),
        // rpgp-FFI. Muss vor `swift build` gebaut sein: Tools/build-pgp-ios.sh.
        // Bewusst kein eingechecktes Artefakt – der Quellcode liegt in Crypto/.
        .binaryTarget(
            name: "imailpgp",
            path: "Crypto/build/PGPKit.xcframework"
        )
    ]
)
