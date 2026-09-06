import Foundation

struct DetachedStartupStatus: Codable {
    private static let maxStartupStatusBytes = 4096

    enum State: String, Codable {
        case failed
    }

    let state: State
    let message: String

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case state
        case message
    }

    init(state: State, message: String) {
        self.state = state
        self.message = message
    }

    init(from decoder: Decoder) throws {
        try rejectUnknownJSONKeys(in: decoder,
                                  allowedBy: CodingKeys.self,
                                  context: "detached startup status")
        let container = try decoder.container(keyedBy: CodingKeys.self)
        state = try container.decode(State.self, forKey: .state)
        message = try container.decode(String.self, forKey: .message)
    }

    static func load(from path: String?) -> DetachedStartupStatus? {
        guard let path, !path.isEmpty else {
            return nil
        }

        let url = URL(fileURLWithPath: path).standardized
        guard let data = try? SecureFile.readRegularFile(
            at: url,
            maximumBytes: maxStartupStatusBytes,
            context: "detached startup status \(url.path)"
        ) else {
            return nil
        }

        return try? JSONDecoder().decode(Self.self, from: data)
    }

    static func writeFailure(message: String, to path: String?) {
        guard let path, !path.isEmpty else {
            return
        }

        let url = URL(fileURLWithPath: path).standardized
        let payload = Self(state: .failed, message: message)

        do {
            let data = try JSONEncoder().encode(payload)
            try data.write(to: url, options: .atomic)
            try RuntimePaths.secureSessionStateFile(at: url)
        } catch {
            fputs("\(AppIdentity.executableName): failed to write detached startup status: \(error.localizedDescription)\n", stderr)
        }
    }
}
