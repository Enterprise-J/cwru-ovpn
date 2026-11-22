import Darwin
import Foundation

struct ResolverDirectory {
    let fd: Int32
    let owner: uid_t
    let group: gid_t

    func read(_ name: String) throws -> Data? {
        try AnchoredFileIO.readOwnedRegularFile(in: fd, name: name, userID: owner, groupID: group,
                                                maximumBytes: RouteManager.maxResolverFileBytes, mode: RouteManager.resolverFileMode)
    }

    static func isManaged(_ data: Data) -> Bool {
        let marker = Data(RouteManager.resolverManagedMarker.utf8)
        return data == marker || data.starts(with: marker + [10])
    }

    func sync() throws {
        guard fsync(fd) == 0 else { throw FileIO.failure("Failed to sync the resolver directory", errno) }
    }

    private func rename(_ from: String, _ to: String, _ flags: UInt32) throws {
        guard renameatx_np(fd, from, fd, to, flags) == 0 else { throw FileIO.failure("Could not rename \(from) to \(to)", errno) }
    }

    private func unlink(_ name: String) throws {
        guard unlinkat(fd, name, 0) == 0 else { throw FileIO.failure("Could not remove resolver \(name)", errno) }
    }

    func recover(_ name: String, names: [String]) throws {
        let prefix = ".\(name)."
        for entry in names.sorted() where entry.hasPrefix(prefix) {
            let fields = entry.dropFirst(prefix.count).split(separator: ".", omittingEmptySubsequences: false)
            guard fields.count == 2, UUID(uuidString: String(fields[0])) != nil,
                  fields[1] == "tmp" || fields[1] == "remove",
                  let data = try? read(entry) else { continue }
            if fields[1] == "tmp" {
                guard Self.isManaged(data) || Data(RouteManager.resolverManagedMarker.utf8).starts(with: data) else { continue }
            } else {
                guard Self.isManaged(data) else { continue }
                if try read(name) == nil {
                    try rename(entry, name, UInt32(RENAME_EXCL))
                    try sync()
                    continue
                }
            }
            try unlink(entry)
            try sync()
        }
    }

    func install(_ data: Data, as name: String) throws {
        let temporary = ".\(name).\(UUID().uuidString).tmp"
        let file = openat(fd, temporary, O_WRONLY | O_CLOEXEC | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600)
        guard file >= 0 else { throw FileIO.failure("Could not create resolver \(temporary)", errno) }
        var removeTemporary = true
        defer {
            close(file)
            if removeTemporary { _ = unlinkat(fd, temporary, 0) }
        }
        guard fchown(file, owner, group) == 0, fchmod(file, RouteManager.resolverFileMode) == 0 else {
            throw FileIO.failure("Could not set resolver ownership", errno)
        }
        try FileIO.writeAll(data, to: file)
        guard fsync(file) == 0 else { throw FileIO.failure("Could not sync resolver \(name)", errno) }
        if renameatx_np(fd, temporary, fd, name, UInt32(RENAME_EXCL)) == 0 {
            removeTemporary = false
        } else {
            guard errno == EEXIST else { throw FileIO.failure("Could not install resolver \(name)", errno) }
            try rename(temporary, name, UInt32(RENAME_SWAP))
            removeTemporary = false
            do {
                guard let original = try read(temporary), Self.isManaged(original) else {
                    throw RouteManagerError.refusingToReplaceUnmanagedResolverFile(name)
                }
                try sync()
            } catch {
                try rename(temporary, name, UInt32(RENAME_SWAP))
                removeTemporary = true
                try sync()
                throw error
            }
            try unlink(temporary)
        }
        try sync()
    }

    func remove(_ name: String) throws -> Bool {
        guard let original = try read(name), Self.isManaged(original) else { return false }
        let temporary = ".\(name).\(UUID().uuidString).remove"
        try rename(name, temporary, UInt32(RENAME_EXCL))
        do {
            guard try read(temporary) == original else { throw RouteManagerError.refusingToReplaceUnmanagedResolverFile(name) }
            try sync()
        } catch {
            try rename(temporary, name, UInt32(RENAME_EXCL))
            try sync()
            throw error
        }
        try unlink(temporary)
        try sync()
        return true
    }
}
