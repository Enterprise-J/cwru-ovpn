import Dispatch
import Darwin
import Foundation

final class BlockingEventMonitor {
    private let queue = DispatchQueue(label: "cwru-ovpn.blocking-event-monitor")
    private let semaphore = DispatchSemaphore(value: 0)
    private var fileSources: [DispatchSourceFileSystemObject] = []
    private var processSources: [DispatchSourceProcess] = []

    init(directoryURLs: [URL], processIDs: [Int32] = []) {
        let directoryPaths = Set(
            directoryURLs.map {
                $0.standardizedFileURL
                    .resolvingSymlinksInPath()
                    .path
            }
        )

        for path in directoryPaths {
            addDirectorySource(path: path)
        }

        for pid in processIDs where pid > 1 {
            addProcessSource(pid: pid)
        }
    }

    deinit {
        for source in processSources {
            source.cancel()
        }

        for source in fileSources {
            source.cancel()
        }
    }

    func wait(until deadline: DispatchTime) -> DispatchTimeoutResult {
        semaphore.wait(timeout: deadline)
    }

    private func addDirectorySource(path: String) {
        let fd = open(path, O_EVTONLY)
        guard fd >= 0 else {
            return
        }

        let source = DispatchSource.makeFileSystemObjectSource(fileDescriptor: fd,
                                                               eventMask: [.write, .rename, .delete, .extend],
                                                               queue: queue)
        source.setEventHandler { [semaphore] in
            semaphore.signal()
        }
        source.setCancelHandler {
            close(fd)
        }
        source.resume()

        fileSources.append(source)
    }

    private func addProcessSource(pid: Int32) {
        let source = DispatchSource.makeProcessSource(identifier: pid_t(pid),
                                                      eventMask: .exit,
                                                      queue: queue)
        source.setEventHandler { [semaphore] in
            semaphore.signal()
        }
        source.resume()
        processSources.append(source)
    }
}
