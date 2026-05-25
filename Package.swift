// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "PowerAuthForWatch",
    platforms: [
        .watchOS(.v4)
    ],
    products: [
        .library(name: "PowerAuth2ForWatch", type: .dynamic, targets: ["PowerAuth2ForWatch"])
    ],
    dependencies: [
        .package(url: "https://github.com/wultra/cc7", exact: "0.7.0-rc2")
    ],
    targets: [
        
        // --- PowerAuth2ForWatch ---
        
        .target(
            name: "PowerAuth2ForWatch",
            dependencies: [
                .product(name: "openssl", package: "cc7")
            ],
            path: "Sources",
            exclude: [
                "PowerAuth2ForWatch/Info.plist",
                "PowerAuth2ForWatch/module.modulemap"
            ],
            sources: [
                "PowerAuth2ForWatch",
                "PowerAuth2ForWatchPrivate",
            ],
            publicHeadersPath: "PowerAuth2ForWatch",
            cSettings: [
                // Required for "Header.h" style imports
                .headerSearchPath("PowerAuth2ForWatch"),
                .headerSearchPath("PowerAuth2ForWatchPrivate"),
                .define("PA2_EXTENSION_SDK", to: "1"),
                .define("PA2_WATCH_SDK", to: "1")
            ]
        ),
        
        // --- PowerAuth2ForWatchTests ---
        
        .testTarget(
            name: "PowerAuth2ForWatchTests",
            dependencies: [ "PowerAuth2ForWatch" ],
            path: "Sources",
            sources: [
                "PowerAuth2ForWatchTests"
            ],
            cSettings: [
                // Required for <FW/Header.h> style imports
                .headerSearchPath("."),
                // Required for "Header.h" style imports
                .headerSearchPath("PowerAuth2ForWatch"),
                .headerSearchPath("PowerAuth2ForWatchPrivate"),
                .define("PA2_EXTENSION_SDK", to: "1"),
                .define("PA2_WATCH_SDK", to: "1")
            ]
        )
    ],
    cLanguageStandard: .c17,
    cxxLanguageStandard: .cxx20
)
