import COpenVPN3Wrapper
import Foundation

enum OpenVPNProfileError: LocalizedError {
    case malformed(String)

    var errorDescription: String? {
        switch self {
        case .malformed(let reason):
            return "OpenVPN 3 could not parse the profile: \(reason)"
        }
    }
}

struct OpenVPNProfile {
    enum Option: Equatable {
        case directive([String])
        case block(String)
        case connectionBlock([Option])
        case accessServerMetadata(String)
    }

    private typealias Entry = (kind: cwru_ovpn_profile_option_kind_t, arguments: [String])

    private typealias Enumerator = @convention(c) (UnsafePointer<CChar>?,
                                                   cwru_ovpn_profile_option_callback_t?,
                                                   UnsafeMutableRawPointer?,
                                                   UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?) -> Bool

    private final class EntryCollector {
        var entries: [Entry] = []
    }

    private static let connectionBlockName = "connection"

    let options: [Option]

    init(content: String) throws {
        options = try Self.entries(in: content, enumerator: cwru_ovpn_profile_enumerate_options).map { entry in
            switch entry.kind {
            case CWRU_OVPN_PROFILE_OPTION_ACCESS_SERVER_METADATA:
                return .accessServerMetadata(entry.arguments[0])
            case CWRU_OVPN_PROFILE_OPTION_BLOCK:
                guard entry.arguments[0] == Self.connectionBlockName else {
                    return .block(entry.arguments[0])
                }
                return .connectionBlock(try Self.connectionBlockOptions(in: entry.arguments[1]))
            default:
                let arguments = entry.arguments
                let isSetenvOption = arguments.count >= 3 && arguments[0] == "setenv" && arguments[1] == "opt"
                return .directive(isSetenvOption ? Array(arguments.dropFirst(2)) : arguments)
            }
        }
    }

    static func connectContent(_ profileContent: String, for tunnelMode: AppTunnelMode) -> String {
        let filters: [String]
        switch tunnelMode {
        case .split:
            filters = [
                "route-nopull",
                "pull-filter ignore \"route ''\"",
                "pull-filter ignore \"route-ipv6 ''\"",
                "pull-filter ignore redirect-gateway",
                "pull-filter ignore redirect-private",
                "pull-filter ignore dns",
                "pull-filter ignore dhcp-option",
                "pull-filter ignore block-ipv4",
                "pull-filter ignore block-ipv6",
            ]
        case .full:
            filters = [
                "pull-filter ignore \"route ''\"",
                "pull-filter ignore \"route-ipv6 ''\"",
                "pull-filter ignore redirect-gateway",
                "pull-filter ignore redirect-private",
                "pull-filter ignore block-ipv4",
                "pull-filter ignore block-ipv6",
            ]
        }
        return "\(filters.joined(separator: "\n"))\n\(profileContent)"
    }

    var firstRemoteHost: String? {
        let connectionBlockOptions = options.flatMap { option -> [Option] in
            guard case .connectionBlock(let connectionOptions) = option else {
                return []
            }
            return connectionOptions
        }
        return (options + connectionBlockOptions).lazy.compactMap(Self.remoteHost).first
    }

    private static func remoteHost(of option: Option) -> String? {
        guard case .directive(let arguments) = option, arguments[0] == "remote", arguments.count >= 2 else {
            return nil
        }
        return arguments[1]
    }

    private static func connectionBlockOptions(in content: String) throws -> [Option] {
        try entries(in: content, enumerator: cwru_ovpn_profile_enumerate_connection_block_options).map { entry in
            entry.kind == CWRU_OVPN_PROFILE_OPTION_BLOCK ? .block(entry.arguments[0]) : .directive(entry.arguments)
        }
    }

    private static func entries(in content: String, enumerator: Enumerator) throws -> [Entry] {
        let collector = EntryCollector()
        var errorMessage: UnsafeMutablePointer<CChar>?
        let parsed = content.withCString { contentCString in
            enumerator(contentCString, { context, kind, arguments, argumentCount in
                let collector = Unmanaged<EntryCollector>.fromOpaque(context!).takeUnretainedValue()
                let values = UnsafeBufferPointer(start: arguments!, count: argumentCount)
                    .map { String(cString: $0!) }
                collector.entries.append((kind, values))
            }, Unmanaged.passUnretained(collector).toOpaque(), &errorMessage)
        }
        defer {
            cwru_ovpn_string_free(errorMessage)
        }
        guard parsed else {
            throw OpenVPNProfileError.malformed(errorMessage.map { String(cString: $0) } ?? "unknown parser failure")
        }
        return collector.entries
    }
}
