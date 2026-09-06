import Foundation
import IOKit.pwr_mgt

enum PowerManagementError: LocalizedError {
    case failedToCreateUserIdleSystemSleepAssertion(IOReturn)

    var errorDescription: String? {
        switch self {
        case .failedToCreateUserIdleSystemSleepAssertion(let result):
            return String(format: "Could not create PreventUserIdleSystemSleep assertion (IOReturn 0x%08x).",
                          UInt32(bitPattern: result))
        }
    }
}

enum PowerManagement {
    typealias AssertionID = IOPMAssertionID

    static func beginPreventUserIdleSystemSleepAssertion(reason: String) throws -> AssertionID {
        let assertionType = kIOPMAssertPreventUserIdleSystemSleep as CFString
        var assertionID = AssertionID(0)
        let result = IOPMAssertionCreateWithName(assertionType,
                                                 IOPMAssertionLevel(kIOPMAssertionLevelOn),
                                                 reason as CFString,
                                                 &assertionID)
        guard result == kIOReturnSuccess else {
            throw PowerManagementError.failedToCreateUserIdleSystemSleepAssertion(result)
        }

        return assertionID
    }

    static func endAssertion(_ assertionID: AssertionID) {
        _ = IOPMAssertionRelease(assertionID)
    }
}
