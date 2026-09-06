import Darwin
import Foundation

enum FileIO {
    static func readAll(from fileDescriptor: Int32, maximumBytes: Int) throws -> Data {
        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 64 * 1024)
        while true {
            let bytesRead = buffer.withUnsafeMutableBytes { read(fileDescriptor, $0.baseAddress, $0.count) }
            if bytesRead == 0 {
                return data
            }
            if bytesRead < 0 {
                if errno == EINTR {
                    continue
                }
                throw posixError(errno)
            }
            guard data.count + bytesRead <= maximumBytes else {
                throw posixError(EFBIG)
            }
            data.append(buffer, count: bytesRead)
        }
    }

    static func writeAll(_ data: Data, to fileDescriptor: Int32) throws {
        try data.withUnsafeBytes { bytes in
            var written = 0
            while written < bytes.count {
                let result = write(fileDescriptor, bytes.baseAddress!.advanced(by: written), bytes.count - written)
                if result < 0 {
                    if errno == EINTR {
                        continue
                    }
                    throw posixError(errno)
                }
                guard result > 0 else {
                    throw posixError(EIO)
                }
                written += result
            }
        }
    }

    static func posixError(_ code: Int32) -> POSIXError {
        POSIXError(POSIXErrorCode(rawValue: code) ?? .EIO)
    }

    static func failure(_ context: String, _ code: Int32) -> NSError {
        NSError(domain: NSPOSIXErrorDomain,
                code: Int(code),
                userInfo: [NSLocalizedDescriptionKey: "\(context): \(String(cString: strerror(code)))"])
    }
}
