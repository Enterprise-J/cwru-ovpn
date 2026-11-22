import Foundation

struct PrivilegedConnectIntent {
    let profilePath: String
    let configFilePath: String?
    let configuration: AppConfig
    let verbosity: AppVerbosity
    let tunnelMode: AppTunnelMode

    static func resolve(configFilePath: String?,
                        verbosityOverride: AppVerbosity?,
                        tunnelModeOverride: AppTunnelMode?,
                        homeConfigFile: URL = RuntimePaths.homeConfigFile,
                        homeProfileFile: URL = RuntimePaths.homeProfileFile) throws -> PrivilegedConnectIntent {
        let (configURL, configuration) = try AppConfig.resolve(explicitConfigPath: configFilePath, homeConfigFile: homeConfigFile)
        return PrivilegedConnectIntent(
            profilePath: try AppConfig.approvedProfilePath(homeProfileFile: homeProfileFile),
            configFilePath: configURL?.path,
            configuration: configuration,
            verbosity: verbosityOverride ?? .daily,
            tunnelMode: tunnelModeOverride ?? configuration.tunnelMode
        )
    }
}
