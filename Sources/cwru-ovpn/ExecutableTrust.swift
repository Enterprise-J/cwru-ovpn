import Foundation
import MachO

enum ExecutableTrustError: LocalizedError {
    case invalidExecutable
    case unsafeDependency(String)
    case unsafeLoaderPath(String)

    var errorDescription: String? {
        switch self {
        case .invalidExecutable:
            return "Could not validate the executable for passwordless installation."
        case .unsafeDependency(let path):
            return "Passwordless installation requires statically linked third-party libraries. Unsupported dependency: \(path.debugDescription)."
        case .unsafeLoaderPath(let path):
            return "Passwordless installation refuses the dynamic loader path \(path.debugDescription)."
        }
    }
}

enum ExecutableTrust {
    static func validate(_ data: Data) throws {
        guard data.count >= 32, try word(data, at: 0) == UInt32(MH_MAGIC_64),
              try word(data, at: 4) == UInt32(bitPattern: CPU_TYPE_ARM64),
              try word(data, at: 12) == UInt32(MH_EXECUTE) else {
            throw ExecutableTrustError.invalidExecutable
        }
        let count = Int(try word(data, at: 16))
        let size = Int(try word(data, at: 20))
        guard count > 0, count <= size / 8, size <= data.count - 32 else {
            throw ExecutableTrustError.invalidExecutable
        }
        let dependencyCommands: Set<UInt32> = [
            UInt32(LC_LOAD_DYLIB), UInt32(LC_LOAD_WEAK_DYLIB),
            UInt32(LC_REEXPORT_DYLIB), UInt32(LC_LOAD_UPWARD_DYLIB),
            UInt32(LC_LAZY_LOAD_DYLIB),
        ]
        let end = 32 + size
        var offset = 32
        for _ in 0..<count {
            guard offset <= end - 8 else { throw ExecutableTrustError.invalidExecutable }
            let command = try word(data, at: offset)
            let length = Int(try word(data, at: offset + 4))
            guard length >= 8, length.isMultiple(of: 8), length <= end - offset else {
                throw ExecutableTrustError.invalidExecutable
            }
            if command == UInt32(LC_DYLD_ENVIRONMENT) {
                throw ExecutableTrustError.unsafeLoaderPath("embedded loader environment")
            }
            if dependencyCommands.contains(command) || command == UInt32(LC_LOAD_DYLINKER)
                || command == UInt32(LC_RPATH) {
                let minimumSize = dependencyCommands.contains(command) ? 24 : 12
                guard length >= minimumSize else { throw ExecutableTrustError.invalidExecutable }
                let stringOffset = Int(try word(data, at: offset + 8))
                guard stringOffset >= minimumSize, stringOffset < length,
                      let terminator = data[(offset + stringOffset)..<(offset + length)].firstIndex(of: 0),
                      let path = String(data: data[(offset + stringOffset)..<terminator], encoding: .utf8),
                      !path.isEmpty else {
                    throw ExecutableTrustError.invalidExecutable
                }
                if command == UInt32(LC_RPATH) {
                    guard isSystemPath(path) || path == "@loader_path" || path == "@executable_path" else {
                        throw ExecutableTrustError.unsafeLoaderPath(path)
                    }
                } else if !isSystemPath(path) {
                    throw ExecutableTrustError.unsafeDependency(path)
                }
            }
            offset += length
        }
        guard offset == end else { throw ExecutableTrustError.invalidExecutable }
    }

    private static func word(_ data: Data, at offset: Int) throws -> UInt32 {
        guard offset >= 0, data.count >= 4, offset <= data.count - 4 else {
            throw ExecutableTrustError.invalidExecutable
        }
        return data.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: offset, as: UInt32.self).littleEndian }
    }

    private static func isSystemPath(_ path: String) -> Bool {
        (path.hasPrefix("/usr/lib/") || path.hasPrefix("/System/Library/"))
            && URL(fileURLWithPath: path).standardizedFileURL.path == path
    }
}
