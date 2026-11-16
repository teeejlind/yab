import Foundation
import Security
import YabStore

// A `yab mcp` that outlived its own binary: hands its client to one started
// from the copy on disk now.
//
// An agent's server lives as long as the agent's chat, for hours, and Claude
// Code or Codex never start it again on their own. An update replaces
// yab.app under it, and the browser that comes back answers only Yab's own
// code (BenchCaller): Code Signing checks the caller's running code against
// its file on disk, which is now the new build's, and says
// errSecCSStaticCodeChanged. Every call of the old server was refused with
// BenchCaller.refusal for the rest of the chat, while `yab` in the same
// shell, started from the new copy, worked.
//
// The check is right: the old process is not the code on disk. So the
// server that finds itself refused for that reason starts `yab mcp` again
// from its own path, with its own arguments, says the client's `initialize`
// to it, and from then on only carries lines both ways. The new server is
// an ordinary one; nothing it is handed is anything a program couldn't
// already give `yab mcp` by starting it.

final class McpHandover: @unchecked Sendable {
    /// Whether the code this process runs is no longer what is on disk at
    /// its path: an update or a new copy replaced it. Asked only after a
    /// refusal, as validating a whole bundle takes a fifth of a second.
    static func replacedOnDisk() -> Bool {
        var me: SecCode?
        guard SecCodeCopySelf([], &me) == errSecSuccess, let me else { return false }
        return SecCodeCheckValidity(me, [], nil) == errSecCSStaticCodeChanged
    }

    private let process: Process
    private let input: FileHandle
    private let output: FileHandle
    private let client: (Data) -> Void
    private let lock = NSLock()

    /// Starts `executable` with `arguments` and has it take over from the
    /// client's `greeting` (its `initialize`, whose answer the client
    /// already has) and the `initialized` that followed. Lines it says go to
    /// `client`. Nil when it can't be started or doesn't answer the greeting.
    init?(executable: String, arguments: [String], greeting: [String: Any],
          client: @escaping (Data) -> Void) {
        guard let url = ProcessLaunch.executableURL(executable) else { return nil }
        let process = Process()
        process.executableURL = url
        process.arguments = arguments
        var environment = ProcessInfo.processInfo.environment
        // The new copy checks for itself whether its app is whole.
        environment[LaunchCopy.relaunched] = nil
        process.environment = environment
        let toChild = Pipe(), fromChild = Pipe()
        process.standardInput = toChild
        process.standardOutput = fromChild
        guard (try? process.runValidated()) != nil else { return nil }
        self.process = process
        input = toChild.fileHandleForWriting
        // A new server that died early is a failed write, not SIGPIPE.
        _ = fcntl(input.fileDescriptor, F_SETNOSIGPIPE, 1)
        output = fromChild.fileHandleForReading
        self.client = client
        // Its answer to the greeting is the client's already, so it is read
        // here and dropped.
        guard send(greeting), let answer = Self.line(output), !answer.isEmpty,
              send(["jsonrpc": "2.0", "method": "notifications/initialized"]) else {
            process.terminate()
            return nil
        }
    }

    /// One message to the new server, as the client sent it.
    @discardableResult
    func send(_ message: [String: Any]) -> Bool {
        guard var data = try? JSONSerialization.data(withJSONObject: message) else { return false }
        data.append(0x0A)
        return send(data)
    }

    /// One line from the client, carried as it came.
    @discardableResult
    func send(line: String) -> Bool {
        send(Data((line + "\n").utf8))
    }

    private func send(_ data: Data) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return (try? input.write(contentsOf: data)) != nil
    }

    /// Carries what the new server says to the client until it ends, on a
    /// thread of its own; `ended` once it has.
    func carry(ended: @escaping @Sendable () -> Void) {
        let output = output, client = client
        Thread.detachNewThread {
            while true {
                let data = output.availableData
                if data.isEmpty { break }
                client(data)
            }
            ended()
        }
    }

    /// The client has gone: so does the new server's input, and this waits
    /// for it to say goodbye to the browser and leave.
    func finish() {
        lock.lock()
        try? input.close()
        lock.unlock()
        process.waitUntilExit()
    }

    /// The next line `handle` says, read a byte at a time so nothing after
    /// it is taken from what `carry` passes on.
    private static func line(_ handle: FileHandle) -> Data? {
        var line = Data()
        while true {
            guard let byte = try? handle.read(upToCount: 1), let first = byte.first else { return nil }
            if first == 0x0A { return line }
            line.append(first)
        }
    }
}
