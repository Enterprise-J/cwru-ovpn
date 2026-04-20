import Foundation

struct DetachedStartupStatus: Codable {
    enum State: String, Codable {
        case failed
    }

    let state: State
    let message: String

    static func load(from path: String?) -> DetachedStartupStatus? {
        guard let path, !path.isEmpty else {
            return nil
        }

        let url = URL(fileURLWithPath: path).standardized
        guard let data = try? Data(contentsOf: url) else {
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
        } catch {
            fputs("\(AppIdentity.executableName): failed to write detached startup status: \(error.localizedDescription)\n", stderr)
        }
    }
}
