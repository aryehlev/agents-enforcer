// Agent Gateway Enforcer - File Security Extension Entry Point

import Foundation
import os.log

let logger = Logger(subsystem: "com.agent-gateway-enforcer.filesecurity", category: "Main")

logger.info("File Security Extension starting...")

// Create and start the extension
let securityExtension = FileSecurityExtension()

if securityExtension.start() {
    logger.info("Extension started successfully, entering run loop")

    // Set up signal handlers for graceful shutdown
    signal(SIGTERM) { _ in
        logger.info("Received SIGTERM, shutting down...")
        exit(0)
    }

    signal(SIGINT) { _ in
        logger.info("Received SIGINT, shutting down...")
        exit(0)
    }

    // Run forever
    RunLoop.main.run()
} else {
    logger.error("Failed to start extension")
    exit(1)
}
