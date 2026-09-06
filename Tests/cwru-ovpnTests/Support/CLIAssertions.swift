import Testing

@testable import cwru_ovpn

func expectRejectsUnexpectedArgument(
    _ arguments: [String],
    command: String,
    argument expectedArgument: String
) throws {
    do {
        _ = try CLI.parse(arguments: arguments)
        Issue.record("\(command) should reject \(expectedArgument).")
    } catch CLIError.unexpectedArgument(let argument) {
        #expect(
            argument == expectedArgument,
            "\(command) should reject \(expectedArgument) as an unexpected argument.")
    } catch {
        Issue.record(
            "\(command) should reject \(expectedArgument) with an unexpected argument error.")
    }
}

func expectRejectsInvalidPID(
    _ arguments: [String],
    command: String,
    pid: String
) throws {
    do {
        _ = try CLI.parse(arguments: arguments)
        Issue.record("\(command) should reject invalid PID \(pid).")
    } catch CLIError.invalidPID(let value) {
        #expect(
            value == pid,
            "\(command) should report the invalid PID value.")
    } catch {
        Issue.record("\(command) should reject \(pid) with an invalid PID error.")
    }
}

func expectRejectsMissingValue(
    _ arguments: [String],
    command: String,
    argument expectedArgument: String
) throws {
    do {
        _ = try CLI.parse(arguments: arguments)
        Issue.record("\(command) should reject missing value for \(expectedArgument).")
    } catch CLIError.missingValue(let argument) {
        #expect(
            argument == expectedArgument,
            "\(command) should report \(expectedArgument) as the option missing a value.")
    } catch {
        Issue.record("\(command) should reject \(expectedArgument) with a missing value error.")
    }
}
