// Agent Gateway Enforcer - File Security System Extension
// Endpoint Security client for blocking file access

import Foundation
import EndpointSecurity
import os.log

/// Main Endpoint Security extension class
class FileSecurityExtension {
    private var client: OpaquePointer?
    private var blockedProcesses: Set<String> = []
    private var blockedPaths: [String] = []
    private var isEnabled: Bool = true
    private let logger = Logger(subsystem: "com.agent-gateway-enforcer.filesecurity", category: "ES")

    // Configuration file path
    private let configPath = "/etc/agent-gateway-enforcer/blocked.json"

    init() {
        loadConfiguration()
    }

    /// Start the Endpoint Security client
    func start() -> Bool {
        logger.info("Starting Endpoint Security client...")

        var newClient: OpaquePointer?

        // Create ES client with message handler
        let result = es_new_client(&newClient) { [weak self] (client, message) in
            self?.handleMessage(client: client, message: message)
        }

        guard result == ES_NEW_CLIENT_RESULT_SUCCESS else {
            logger.error("Failed to create ES client: \(result.rawValue)")
            logESError(result)
            return false
        }

        guard let client = newClient else {
            logger.error("ES client is nil after successful creation")
            return false
        }

        self.client = client

        // Clear any existing subscriptions
        es_unsubscribe_all(client)

        // Subscribe to file auth events
        let events: [es_event_type_t] = [
            ES_EVENT_TYPE_AUTH_OPEN,
            ES_EVENT_TYPE_AUTH_CREATE,
            ES_EVENT_TYPE_AUTH_UNLINK,
            ES_EVENT_TYPE_AUTH_RENAME,
            ES_EVENT_TYPE_AUTH_CLONE,
            ES_EVENT_TYPE_AUTH_EXCHANGEDATA,
            ES_EVENT_TYPE_AUTH_TRUNCATE,
            ES_EVENT_TYPE_AUTH_LINK,
            ES_EVENT_TYPE_AUTH_SETATTRLIST,
            ES_EVENT_TYPE_AUTH_SETEXTATTR,
            ES_EVENT_TYPE_AUTH_SETFLAGS,
            ES_EVENT_TYPE_AUTH_SETMODE,
            ES_EVENT_TYPE_AUTH_SETOWNER
        ]

        let subscribeResult = es_subscribe(client, events, UInt32(events.count))
        guard subscribeResult == ES_RETURN_SUCCESS else {
            logger.error("Failed to subscribe to events: \(subscribeResult.rawValue)")
            es_delete_client(client)
            self.client = nil
            return false
        }

        logger.info("Endpoint Security client started successfully")
        logger.info("Monitoring \(self.blockedProcesses.count) blocked processes")
        logger.info("Blocking access to \(self.blockedPaths.count) paths")

        return true
    }

    /// Handle incoming ES message
    private func handleMessage(client: OpaquePointer, message: UnsafePointer<es_message_t>) {
        guard isEnabled else {
            // If disabled, allow everything
            es_respond_auth_result(client, message, ES_AUTH_RESULT_ALLOW, false)
            return
        }

        let msg = message.pointee

        // Get process information
        let processPath = getProcessPath(from: msg.process)
        let processName = getProcessName(from: processPath)

        // Check if this process should be blocked
        guard shouldBlockProcess(name: processName, path: processPath) else {
            // Allow non-blocked processes
            es_respond_auth_result(client, message, ES_AUTH_RESULT_ALLOW, false)
            return
        }

        // Get the file path being accessed
        let filePath = getFilePath(from: msg)

        // Check if access to this path should be blocked
        if shouldBlockPath(filePath) {
            let pid = audit_token_to_pid(msg.process.pointee.audit_token)
            logger.warning("BLOCKED: Process '\(processName)' (PID: \(pid)) accessing '\(filePath)'")
            es_respond_auth_result(client, message, ES_AUTH_RESULT_DENY, false)
        } else {
            es_respond_auth_result(client, message, ES_AUTH_RESULT_ALLOW, false)
        }
    }

    /// Check if a process should be blocked
    private func shouldBlockProcess(name: String, path: String) -> Bool {
        let lowerName = name.lowercased()
        let lowerPath = path.lowercased()

        for blocked in blockedProcesses {
            let lowerBlocked = blocked.lowercased()
            if lowerName.contains(lowerBlocked) || lowerPath.contains(lowerBlocked) {
                return true
            }
        }
        return false
    }

    /// Check if a path should be blocked
    private func shouldBlockPath(_ path: String) -> Bool {
        // If no specific paths configured, block all
        if blockedPaths.isEmpty {
            return true
        }

        // Check if path starts with any blocked prefix
        for blockedPath in blockedPaths {
            if path.hasPrefix(blockedPath) {
                return true
            }
        }
        return false
    }

    /// Get process path from es_process_t
    private func getProcessPath(from process: UnsafeMutablePointer<es_process_t>) -> String {
        let executable = process.pointee.executable
        return String(cString: executable.pointee.path.data)
    }

    /// Extract process name from path
    private func getProcessName(from path: String) -> String {
        return (path as NSString).lastPathComponent
    }

    /// Get file path from ES message
    private func getFilePath(from message: es_message_t) -> String {
        switch message.event_type {
        case ES_EVENT_TYPE_AUTH_OPEN:
            return String(cString: message.event.open.file.pointee.path.data)

        case ES_EVENT_TYPE_AUTH_CREATE:
            let destination = message.event.create.destination
            if destination.destination_type == ES_DESTINATION_TYPE_NEW_PATH {
                let dir = String(cString: destination.new_path.dir.pointee.path.data)
                let filename = String(cString: destination.new_path.filename.data)
                return (dir as NSString).appendingPathComponent(filename)
            } else {
                return String(cString: destination.existing_file.pointee.path.data)
            }

        case ES_EVENT_TYPE_AUTH_UNLINK:
            return String(cString: message.event.unlink.target.pointee.path.data)

        case ES_EVENT_TYPE_AUTH_RENAME:
            return String(cString: message.event.rename.source.pointee.path.data)

        case ES_EVENT_TYPE_AUTH_CLONE:
            return String(cString: message.event.clone.source.pointee.path.data)

        case ES_EVENT_TYPE_AUTH_TRUNCATE:
            return String(cString: message.event.truncate.target.pointee.path.data)

        case ES_EVENT_TYPE_AUTH_LINK:
            return String(cString: message.event.link.source.pointee.path.data)

        case ES_EVENT_TYPE_AUTH_EXCHANGEDATA:
            return String(cString: message.event.exchangedata.file1.pointee.path.data)

        default:
            return "<unknown>"
        }
    }

    /// Load configuration from file
    private func loadConfiguration() {
        // Default blocked processes (AI coding agents)
        blockedProcesses = [
            "opencode",
            "open-code",
            "opencode-agent"
        ]

        // Default blocked paths (entire filesystem for blocked processes)
        blockedPaths = [
            "/Users",
            "/tmp",
            "/var",
            "/etc",
            "/private",
            "/Applications"
        ]

        // Try to load from config file
        if FileManager.default.fileExists(atPath: configPath) {
            do {
                let data = try Data(contentsOf: URL(fileURLWithPath: configPath))
                if let config = try JSONSerialization.jsonObject(with: data) as? [String: Any] {
                    if let processes = config["blocked_processes"] as? [String] {
                        blockedProcesses = Set(processes)
                    }
                    if let paths = config["blocked_paths"] as? [String] {
                        blockedPaths = paths
                    }
                    if let enabled = config["enabled"] as? Bool {
                        isEnabled = enabled
                    }
                }
                logger.info("Loaded configuration from \(self.configPath)")
            } catch {
                logger.warning("Failed to load config, using defaults: \(error.localizedDescription)")
            }
        } else {
            logger.info("No config file found at \(self.configPath), using defaults")
        }
    }

    /// Reload configuration
    func reloadConfiguration() {
        loadConfiguration()
        logger.info("Configuration reloaded")
    }

    /// Enable/disable enforcement
    func setEnabled(_ enabled: Bool) {
        isEnabled = enabled
        logger.info("Enforcement \(enabled ? "enabled" : "disabled")")
    }

    /// Stop the Endpoint Security client
    func stop() {
        if let client = client {
            es_unsubscribe_all(client)
            es_delete_client(client)
            self.client = nil
            logger.info("Endpoint Security client stopped")
        }
    }

    /// Log ES client creation errors
    private func logESError(_ result: es_new_client_result_t) {
        switch result {
        case ES_NEW_CLIENT_RESULT_ERR_INVALID_ARGUMENT:
            logger.error("Invalid argument to es_new_client")
        case ES_NEW_CLIENT_RESULT_ERR_INTERNAL:
            logger.error("Internal error in ES framework")
        case ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED:
            logger.error("Missing Endpoint Security entitlement")
            logger.error("Ensure com.apple.developer.endpoint-security.client is in entitlements")
        case ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED:
            logger.error("Not permitted - approve in System Preferences > Security & Privacy")
        case ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED:
            logger.error("Not running as root - ES requires root privileges")
        case ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS:
            logger.error("Too many ES clients running")
        default:
            logger.error("Unknown ES error: \(result.rawValue)")
        }
    }

    deinit {
        stop()
    }
}
