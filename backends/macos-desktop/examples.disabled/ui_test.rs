//! Test the UI components independently

use agent_gateway_enforcer_backend_macos::ui::{
    MenuBarApp, PermissionPrompt, PreferencesWindow, SystemIntegration, UIEvent, PromptType,
    FileOperation,
};
use tokio::sync::mpsc;
use std::net::IpAddr;

fn main() {
    println!("Testing macOS UI Components");
    
    // Test event channel
    let (tx, mut rx) = mpsc::unbounded_channel::<UIEvent>();
    
    // Test MenuBarApp creation
    match MenuBarApp::new(tx.clone()) {
        Ok(menu_bar) => {
            println!("✓ MenuBarApp created successfully");
            
            // Test updating status
            if let Err(e) = menu_bar.update_status("Running") {
                println!("✗ Failed to update status: {}", e);
            } else {
                println!("✓ Status updated successfully");
            }
        }
        Err(e) => {
            println!("✗ Failed to create MenuBarApp: {}", e);
        }
    }
    
    // Test SystemIntegration
    println!("\nTesting SystemIntegration:");
    
    match SystemIntegration::get_bundle_identifier() {
        Ok(bundle_id) => println!("✓ Bundle ID: {}", bundle_id),
        Err(e) => println!("✗ Failed to get bundle ID: {}", e),
    }
    
    match SystemIntegration::get_app_version() {
        Ok(version) => println!("✓ App Version: {}", version),
        Err(e) => println!("✗ Failed to get app version: {}", e),
    }
    
    // Test notification (non-blocking)
    match SystemIntegration::post_info_notification("Test", "UI components are working!") {
        Ok(_) => println!("✓ Notification posted successfully"),
        Err(e) => println!("✗ Failed to post notification: {}", e),
    }
    
    // Test PreferencesWindow creation
    match PreferencesWindow::new() {
        Ok(prefs) => {
            println!("✓ PreferencesWindow created successfully");
            // Don't show it in automated test
        }
        Err(e) => {
            println!("✗ Failed to create PreferencesWindow: {}", e);
        }
    }
    
    println!("\nAll UI component tests completed!");
}
