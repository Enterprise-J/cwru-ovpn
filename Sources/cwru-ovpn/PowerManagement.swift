import Foundation
import IOKit.ps

enum PowerManagement {
    static var isLowPowerModeEnabled: Bool {
        ProcessInfo.processInfo.isLowPowerModeEnabled
    }

    static var isRunningOnBatteryPower: Bool {
        guard let snapshotRef = IOPSCopyPowerSourcesInfo() else {
            return false
        }

        let snapshot = snapshotRef.takeRetainedValue()
        guard let rawPowerSource = IOPSGetProvidingPowerSourceType(snapshot)?.takeUnretainedValue() else {
            return false
        }

        return rawPowerSource as String == kIOPSBatteryPowerValue
    }
}
