import Darwin
import Foundation

struct DetachedStartupStatus: Codable {
    private static let maximumBytes = 4096

    let message: String

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case message
    }

    init(message: String) {
        self.message = message
    }

    init(from decoder: Decoder) throws {
        try rejectUnknownJSONKeys(in: decoder,
                                  allowedBy: CodingKeys.self,
                                  context: "detached startup status")
        message = try decoder.container(keyedBy: CodingKeys.self).decode(String.self, forKey: .message)
    }

    static func report(_ message: String, to channel: FileHandle = .standardOutput) {
        var channelInfo = stat()
        guard fstat(channel.fileDescriptor, &channelInfo) == 0,
              (channelInfo.st_mode & S_IFMT) == S_IFREG else {
            return
        }
        do {
            let prefix = message.unicodeScalars.prefix(600)
            let detail = String(prefix) + (prefix.endIndex == message.unicodeScalars.endIndex ? "" : "…")
            let data = try JSONEncoder().encode(Self(message: detail))
            try channel.truncate(atOffset: 0)
            try channel.write(contentsOf: data)
            try channel.synchronize()
        } catch {
            fputs("\(AppIdentity.executableName): failed to report detached startup status: \(error.localizedDescription)\n", stderr)
        }
    }

    static func load(from channel: FileHandle) -> DetachedStartupStatus? {
        var buffer = [UInt8](repeating: 0, count: maximumBytes)
        let count = buffer.withUnsafeMutableBytes { pread(channel.fileDescriptor, $0.baseAddress, $0.count, 0) }
        guard count > 0 else {
            return nil
        }
        return try? JSONDecoder().decode(Self.self, from: Data(buffer.prefix(count)))
    }
}
