// Agent Gateway Enforcer - Container App
// This app installs and manages the File Security System Extension

import Cocoa
import SystemExtensions
import os.log

@main
class AppDelegate: NSObject, NSApplicationDelegate {
    private let logger = Logger(subsystem: "com.agent-gateway-enforcer", category: "App")
    private var statusItem: NSStatusItem?

    // Extension bundle identifier
    private let extensionIdentifier = "com.agent-gateway-enforcer.filesecurity"

    func applicationDidFinishLaunching(_ notification: Notification) {
        logger.info("Agent Gateway Enforcer starting...")

        // Create menu bar item
        setupStatusItem()

        // Request extension activation
        activateExtension()
    }

    func applicationWillTerminate(_ notification: Notification) {
        logger.info("Agent Gateway Enforcer shutting down...")
    }

    // MARK: - Status Bar

    private func setupStatusItem() {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)

        if let button = statusItem?.button {
            button.title = "AGE"
            button.toolTip = "Agent Gateway Enforcer"
        }

        let menu = NSMenu()
        menu.addItem(NSMenuItem(title: "Status: Starting...", action: nil, keyEquivalent: ""))
        menu.addItem(NSMenuItem.separator())
        menu.addItem(NSMenuItem(title: "Activate Extension", action: #selector(activateExtension), keyEquivalent: "a"))
        menu.addItem(NSMenuItem(title: "Deactivate Extension", action: #selector(deactivateExtension), keyEquivalent: "d"))
        menu.addItem(NSMenuItem.separator())
        menu.addItem(NSMenuItem(title: "Open System Preferences", action: #selector(openSystemPreferences), keyEquivalent: "p"))
        menu.addItem(NSMenuItem.separator())
        menu.addItem(NSMenuItem(title: "Quit", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q"))

        statusItem?.menu = menu
    }

    private func updateStatus(_ status: String) {
        DispatchQueue.main.async {
            if let menu = self.statusItem?.menu,
               let statusItem = menu.items.first {
                statusItem.title = "Status: \(status)"
            }
        }
    }

    // MARK: - Extension Management

    @objc func activateExtension() {
        logger.info("Requesting extension activation...")
        updateStatus("Activating...")

        let request = OSSystemExtensionRequest.activationRequest(
            forExtensionWithIdentifier: extensionIdentifier,
            queue: .main
        )
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    @objc func deactivateExtension() {
        logger.info("Requesting extension deactivation...")
        updateStatus("Deactivating...")

        let request = OSSystemExtensionRequest.deactivationRequest(
            forExtensionWithIdentifier: extensionIdentifier,
            queue: .main
        )
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    @objc func openSystemPreferences() {
        // Open Security & Privacy preferences
        if let url = URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles") {
            NSWorkspace.shared.open(url)
        }
    }
}

// MARK: - OSSystemExtensionRequestDelegate

extension AppDelegate: OSSystemExtensionRequestDelegate {

    func request(_ request: OSSystemExtensionRequest,
                 actionForReplacingExtension existing: OSSystemExtensionProperties,
                 withExtension ext: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction {
        logger.info("Replacing existing extension (v\(existing.bundleVersion)) with v\(ext.bundleVersion)")
        return .replace
    }

    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        logger.warning("Extension needs user approval in System Preferences")
        updateStatus("Needs Approval")

        // Show alert
        DispatchQueue.main.async {
            let alert = NSAlert()
            alert.messageText = "System Extension Approval Required"
            alert.informativeText = "Please approve the Agent Gateway Enforcer extension in System Preferences > Security & Privacy > General"
            alert.alertStyle = .informational
            alert.addButton(withTitle: "Open System Preferences")
            alert.addButton(withTitle: "Later")

            if alert.runModal() == .alertFirstButtonReturn {
                self.openSystemPreferences()
            }
        }
    }

    func request(_ request: OSSystemExtensionRequest,
                 didFinishWithResult result: OSSystemExtensionRequest.Result) {
        switch result {
        case .completed:
            logger.info("Extension request completed successfully")
            updateStatus("Active")
        case .willCompleteAfterReboot:
            logger.info("Extension will be active after reboot")
            updateStatus("Reboot Required")
        @unknown default:
            logger.warning("Unknown result: \(result.rawValue)")
            updateStatus("Unknown")
        }
    }

    func request(_ request: OSSystemExtensionRequest,
                 didFailWithError error: Error) {
        logger.error("Extension request failed: \(error.localizedDescription)")
        updateStatus("Error")

        // Show error alert
        DispatchQueue.main.async {
            let alert = NSAlert()
            alert.messageText = "Extension Error"
            alert.informativeText = error.localizedDescription
            alert.alertStyle = .critical
            alert.addButton(withTitle: "OK")
            alert.runModal()
        }
    }
}
