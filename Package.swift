// swift-tools-version: 6.2

import Foundation
import PackageDescription

#if !arch(arm64)
#error("cwru-ovpn requires Apple Silicon.")
#endif

let packageRoot = URL(fileURLWithPath: #filePath).deletingLastPathComponent().path
let workspaceRoot = URL(fileURLWithPath: packageRoot).deletingLastPathComponent().path
let environment = ProcessInfo.processInfo.environment
let hostDeploymentTarget = "\(ProcessInfo.processInfo.operatingSystemVersion.majorVersion).0"
let deploymentTarget = environment["CWRU_OVPN_MACOS_DEPLOYMENT_TARGET"] ?? hostDeploymentTarget
let minimumSupportedMacOSMajor = 15

func appIdentityVersion() -> String {
    let sourcePath = URL(fileURLWithPath: packageRoot)
        .appendingPathComponent("Sources/cwru-ovpn/AppIdentity.swift")
    guard let source = try? String(contentsOf: sourcePath, encoding: .utf8) else {
        return "unknown"
    }
    for line in source.split(separator: "\n") where line.contains("static let version") {
        let parts = line.split(separator: "\"", omittingEmptySubsequences: false)
        if parts.count >= 3 {
            return String(parts[1])
        }
    }
    return "unknown"
}

let appVersion = appIdentityVersion()

guard let deploymentTargetMajor = Int(deploymentTarget.split(separator: ".").first ?? "") else {
    fatalError("Invalid CWRU_OVPN_MACOS_DEPLOYMENT_TARGET: \(deploymentTarget)")
}

if deploymentTargetMajor < minimumSupportedMacOSMajor {
    fatalError("cwru-ovpn \(appVersion) supports macOS \(minimumSupportedMacOSMajor) or later.")
}

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

func preferredExistingPath(_ candidates: [String], fallback: String) -> String {
    for candidate in candidates where FileManager.default.fileExists(atPath: candidate) {
        return candidate
    }

    return fallback
}

let homebrewPrefixCandidates = uniquePaths(
    [
        environment["HOMEBREW_PREFIX"],
        "/opt/homebrew",
    ].compactMap { $0 }
)
let homebrewPrefix = preferredExistingPath(homebrewPrefixCandidates,
                                           fallback: environment["HOMEBREW_PREFIX"] ?? "/opt/homebrew")
let thirdPartyPrefix = environment["CWRU_OVPN_THIRD_PARTY_PREFIX"]
let preferStaticThirdPartyLibraries = environment["CWRU_OVPN_STATIC_THIRD_PARTY"] == "1"

func dependencyPrefix(overrideKey: String, homebrewName: String) -> String {
    if preferStaticThirdPartyLibraries {
        guard let thirdPartyPrefix, !thirdPartyPrefix.isEmpty else {
            fatalError("CWRU_OVPN_THIRD_PARTY_PREFIX is required for static third-party builds.")
        }
        return thirdPartyPrefix
    }

    return preferredExistingPath(
        [environment[overrideKey], thirdPartyPrefix].compactMap { $0 }
            + homebrewPrefixCandidates.map { "\($0)/opt/\(homebrewName)" },
        fallback: environment[overrideKey] ?? thirdPartyPrefix ?? "\(homebrewPrefix)/opt/\(homebrewName)"
    )
}

let openSSLPrefix = dependencyPrefix(overrideKey: "OPENSSL_PREFIX", homebrewName: "openssl@4")
let lz4Prefix = dependencyPrefix(overrideKey: "LZ4_PREFIX", homebrewName: "lz4")
let fmtPrefix = dependencyPrefix(overrideKey: "FMT_PREFIX", homebrewName: "fmt")
let openVPN3Root = firstExistingPath(
    [
        environment["OPENVPN3_DIR"],
        "\(packageRoot)/openvpn3",
        "\(workspaceRoot)/openvpn3",
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
let thirdPartyIncludeDirs = uniquePaths(
    [
        thirdPartyPrefix.map { "\($0)/include" },
        "\(openSSLPrefix)/include",
        "\(lz4Prefix)/include",
        "\(fmtPrefix)/include",
    ].compactMap { $0 }
        + (preferStaticThirdPartyLibraries
            ? []
            : homebrewPrefixCandidates.map { "\($0)/include" })
)
let dynamicLibrarySearchPaths = uniquePaths(
    [
        "\(openSSLPrefix)/lib",
        "\(lz4Prefix)/lib",
        "\(fmtPrefix)/lib",
    ] + homebrewPrefixCandidates.map { "\($0)/lib" }
)
let openVPN3CompileFlags =
    ["-std=c++20", "-isystem", openVPN3Root, "-isystem", asioIncludeDir]
    + thirdPartyIncludeDirs.flatMap { ["-isystem", $0] }
    + ["-isystem", "\(openVPN3Root)/openvpn/crypto"]
let openVPN3Defines: [CXXSetting] = [
    .define("ASIO_STANDALONE"),
    .define("USE_ASIO"),
    .define("HAVE_LZ4"),
    .define("USE_OPENSSL"),
    .define("CWRU_OVPN_DISABLE_REMOTE_BYPASS"),
]

let wrapperLinkerSettings: [LinkerSetting] = {
    var linkerOptions: [LinkerSetting] = [
        .linkedLibrary("pthread"),
        .linkedFramework("CoreFoundation"),
        .linkedFramework("CoreServices"),
        .linkedFramework("IOKit"),
        .linkedFramework("SystemConfiguration"),
    ]

    if preferStaticThirdPartyLibraries {
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
            name: "COpenVPN3",
            path: "Sources/COpenVPN3",
            publicHeadersPath: "include",
            cxxSettings: [.unsafeFlags(openVPN3CompileFlags)] + openVPN3Defines
        ),
        .target(
            name: "COpenVPN3Wrapper",
            dependencies: ["COpenVPN3"],
            path: "Sources/COpenVPN3Wrapper",
            publicHeadersPath: "include",
            cxxSettings: [
                .unsafeFlags(openVPN3CompileFlags + ["-Wall", "-Wextra", "-Wpedantic", "-Wconversion", "-Wshadow"]),
            ] + openVPN3Defines,
            linkerSettings: wrapperLinkerSettings
        ),
        .executableTarget(
            name: "cwru-ovpn",
            dependencies: ["COpenVPN3Wrapper"],
            path: "Sources/cwru-ovpn",
            linkerSettings: [
                .linkedFramework("AppKit"),
                .linkedFramework("AuthenticationServices"),
                .linkedFramework("Network"),
            ]
        ),
        .testTarget(
            name: "cwru-ovpnTests",
            dependencies: ["cwru-ovpn", "COpenVPN3Wrapper"],
            path: "Tests/cwru-ovpnTests"
        ),
    ]
)
