import Foundation

struct PrivilegedConnectIntent {
    let profilePath: String
    let configFilePath: String?
    let configuration: AppConfig
    let verbosity: AppVerbosity
    let tunnelMode: AppTunnelMode
    let preventSleep: Bool

    static func resolve(configFilePath: String?,
                        verbosityOverride: AppVerbosity?,
                        tunnelModeOverride: AppTunnelMode?,
                        homeConfigFile: URL = RuntimePaths.homeConfigFile,
                        homeProfileFile: URL = RuntimePaths.homeProfileFile) throws -> PrivilegedConnectIntent {
        let configURL = AppConfig.resolvedConfigURL(explicitConfigPath: configFilePath,
                                                    allowEnvironmentConfigPath: false,
                                                    homeConfigFile: homeConfigFile)
        let configuration = try AppConfig.load(at: configURL)
        return PrivilegedConnectIntent(
            profilePath: try AppConfig.approvedProfilePath(homeProfileFile: homeProfileFile),
            configFilePath: configURL?.path,
            configuration: configuration,
            verbosity: verbosityOverride ?? .daily,
            tunnelMode: tunnelModeOverride ?? configuration.tunnelMode,
            preventSleep: configuration.preventSleep
        )
    }
}
