// swift-tools-version: 6.2

import Foundation
import PackageDescription

let packageRoot = URL(fileURLWithPath: #filePath).deletingLastPathComponent().path
let workspaceRoot = URL(fileURLWithPath: packageRoot).deletingLastPathComponent().path
let environment = ProcessInfo.processInfo.environment
let deploymentTarget = environment["CWRU_OVPN_MACOS_DEPLOYMENT_TARGET"] ?? "14.0"

func firstExistingPath(_ candidates: [String], label: String) -> String {
    for candidate in candidates where FileManager.default.fileExists(atPath: candidate) {
        return candidate
    }

    fatalError(
        """
        Unable to locate \(label).
        Checked:
        \(candidates.map { "- \($0)" }.joined(separator: "\n"))

        Set the relevant environment variable before building if your checkout lives elsewhere.
        """
    )
}

func uniquePaths(_ candidates: [String]) -> [String] {
    var seen = Set<String>()
    var result: [String] = []
    for candidate in candidates where seen.insert(candidate).inserted {
        result.append(candidate)
    }
    return result
}

let homebrewPrefix = environment["HOMEBREW_PREFIX"] ?? "/opt/homebrew"
let thirdPartyPrefix = environment["CWRU_OVPN_THIRD_PARTY_PREFIX"]
let openSSLPrefix = environment["OPENSSL_PREFIX"] ?? thirdPartyPrefix ?? "\(homebrewPrefix)/opt/openssl@3"
let lz4Prefix = environment["LZ4_PREFIX"] ?? thirdPartyPrefix ?? "\(homebrewPrefix)/opt/lz4"
let fmtPrefix = environment["FMT_PREFIX"] ?? thirdPartyPrefix ?? "\(homebrewPrefix)/opt/fmt"
let openVPN3Root = firstExistingPath(
    [
        environment["OPENVPN3_DIR"],
        "\(workspaceRoot)/openvpn3",
        "\(packageRoot)/openvpn3",
    ].compactMap { $0 },
    label: "the OpenVPN 3 source tree"
)
let asioRoot = firstExistingPath(
    [
        environment["ASIO_DIR"],
        "\(workspaceRoot)/asio",
        "\(workspaceRoot)/asio/asio",
        "\(packageRoot)/asio",
        "\(packageRoot)/asio/asio",
    ].compactMap { $0 },
    label: "the Asio source tree"
)
let asioIncludeDir = firstExistingPath(
    [
        "\(asioRoot)/include",
        "\(asioRoot)/asio/include",
    ],
    label: "the Asio include directory"
)
let preferStaticThirdPartyLibraries = environment["CWRU_OVPN_STATIC_THIRD_PARTY"] == "1"
let staticThirdPartyLibraries = [
    "\(openSSLPrefix)/lib/libssl.a",
    "\(openSSLPrefix)/lib/libcrypto.a",
    "\(lz4Prefix)/lib/liblz4.a",
    "\(fmtPrefix)/lib/libfmt.a",
]
if preferStaticThirdPartyLibraries && !staticThirdPartyLibraries.allSatisfy({ FileManager.default.fileExists(atPath: $0) }) {
    fatalError(
        """
        Static third-party libraries were requested, but the required archives were not found.
        Checked:
        \(staticThirdPartyLibraries.map { "- \($0)" }.joined(separator: "\n"))

        Build target-specific dependencies with ./scripts/build-third-party-libs.sh, or clear CWRU_OVPN_STATIC_THIRD_PARTY to use Homebrew's dynamic libraries for local builds.
        """
    )
}
let useStaticThirdPartyLibraries = preferStaticThirdPartyLibraries
let thirdPartyIncludeDirs = uniquePaths(
    [
        thirdPartyPrefix.map { "\($0)/include" },
        "\(openSSLPrefix)/include",
        "\(lz4Prefix)/include",
        "\(fmtPrefix)/include",
        "\(homebrewPrefix)/include",
    ].compactMap { $0 }
)
let dynamicLibrarySearchPaths = uniquePaths([
    "\(homebrewPrefix)/lib",
    "\(openSSLPrefix)/lib",
    "\(lz4Prefix)/lib",
    "\(fmtPrefix)/lib",
])
let wrapperIncludeFlags =
    [
        "-std=c++20",
        "-I\(openVPN3Root)",
        "-I\(asioIncludeDir)",
    ]
    + thirdPartyIncludeDirs.map { "-I\($0)" }
    + [
        "-I\(openVPN3Root)/openvpn/crypto",
    ]

let wrapperLinkerSettings: [LinkerSetting] = {
    var linkerOptions: [LinkerSetting] = [
        .linkedLibrary("pthread"),
        .linkedFramework("CoreFoundation"),
        .linkedFramework("CoreServices"),
        .linkedFramework("IOKit"),
        .linkedFramework("SystemConfiguration"),
    ]

    if useStaticThirdPartyLibraries {
        linkerOptions.insert(.unsafeFlags(staticThirdPartyLibraries), at: 0)
    } else {
        linkerOptions.insert(
            .unsafeFlags(dynamicLibrarySearchPaths.map { "-L\($0)" }),
            at: 0
        )
        linkerOptions.insert(.linkedLibrary("fmt"), at: 1)
        linkerOptions.insert(.linkedLibrary("lz4"), at: 1)
        linkerOptions.insert(.linkedLibrary("ssl"), at: 1)
        linkerOptions.insert(.linkedLibrary("crypto"), at: 1)
    }

    return linkerOptions
}()

let package = Package(
    name: "cwru-ovpn",
    platforms: [
        .macOS(deploymentTarget),
    ],
    products: [
        .executable(name: "cwru-ovpn", targets: ["cwru-ovpn"]),
    ],
    targets: [
        .target(
            name: "COpenVPN3Wrapper",
            path: "Sources/COpenVPN3Wrapper",
            publicHeadersPath: "include",
            cSettings: [
                .headerSearchPath("include"),
            ],
            cxxSettings: [
                .unsafeFlags(wrapperIncludeFlags),
                .define("ASIO_STANDALONE"),
                .define("USE_ASIO"),
                .define("HAVE_LZ4"),
                .define("USE_OPENSSL"),
            ],
            linkerSettings: wrapperLinkerSettings
        ),
        .executableTarget(
            name: "cwru-ovpn",
            dependencies: ["COpenVPN3Wrapper"],
            path: "Sources/cwru-ovpn",
            swiftSettings: [
                .define("CWRU_OVPN_INCLUDE_SELF_TEST", .when(configuration: .debug)),
            ],
            linkerSettings: [
                .linkedFramework("AppKit"),
                .linkedFramework("AuthenticationServices"),
                .linkedFramework("WebKit"),
            ]
        ),
    ]
)
