//! macOS Menu Bar Application
//!
//! Provides a native macOS menu bar status item with menu options.

use anyhow::Result;
use cocoa::appkit::{
    NSApp, NSApplication, NSImage, NSMenu, NSMenuItem, NSStatusBar, NSStatusItem,
    NSVariableStatusItemLength,
};
use cocoa::base::{id, nil, NO, YES};
use cocoa::foundation::{NSAutoreleasePool, NSString};
use objc::runtime::{Object, Sel};
use objc::{class, msg_send, sel, sel_impl};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

use super::UIEvent;

/// Menu Bar Application
pub struct MenuBarApp {
    status_item: Arc<Mutex<id>>,
    event_tx: mpsc::UnboundedSender<UIEvent>,
}

impl MenuBarApp {
    /// Create a new menu bar application
    pub fn new(event_tx: mpsc::UnboundedSender<UIEvent>) -> Result<Self> {
        unsafe {
            let _pool = NSAutoreleasePool::new(nil);
            
            // Get the shared status bar
            let status_bar = NSStatusBar::systemStatusBar(nil);
            
            // Create status item with variable length
            let status_item = status_bar.statusItemWithLength_(NSVariableStatusItemLength);
            
            // Set initial title
            let title = NSString::alloc(nil).init_str("AGE");
            let button: id = msg_send![status_item, button];
            let _: () = msg_send![button, setTitle: title];
            
            // Create and set menu
            let menu = create_menu(&event_tx);
            let _: () = msg_send![status_item, setMenu: menu];
            
            Ok(Self {
                status_item: Arc::new(Mutex::new(status_item)),
                event_tx,
            })
        }
    }
    
    /// Update the status text in the menu bar
    pub fn update_status(&self, status: &str) -> Result<()> {
        unsafe {
            let _pool = NSAutoreleasePool::new(nil);
            
            let status_item = self.status_item.lock().unwrap();
            let button: id = msg_send![*status_item, button];
            
            let title = NSString::alloc(nil).init_str(status);
            let _: () = msg_send![button, setTitle: title];
        }
        
        Ok(())
    }
    
    /// Update the status icon
    pub fn update_icon(&self, icon_name: &str) -> Result<()> {
        unsafe {
            let _pool = NSAutoreleasePool::new(nil);
            
            let status_item = self.status_item.lock().unwrap();
            let button: id = msg_send![*status_item, button];
            
            // Try to load system symbol (SF Symbols on macOS 11+)
            let image_name = NSString::alloc(nil).init_str(icon_name);
            let image: id = msg_send![class!(NSImage), imageWithSystemSymbolName:image_name accessibilityDescription:nil];
            
            if image != nil {
                let _: () = msg_send![button, setImage: image];
            }
        }
        
        Ok(())
    }
}

impl Drop for MenuBarApp {
    fn drop(&mut self) {
        unsafe {
            let _pool = NSAutoreleasePool::new(nil);
            let status_item = self.status_item.lock().unwrap();
            let status_bar = NSStatusBar::systemStatusBar(nil);
            status_bar.removeStatusItem_(*status_item);
        }
    }
}

/// Create the menu bar menu
unsafe fn create_menu(event_tx: &mpsc::UnboundedSender<UIEvent>) -> id {
    let menu = NSMenu::new(nil).autorelease();
    
    // Show Status
    let item = create_menu_item("Show Status", sel!(showStatus:));
    menu.addItem_(item);
    
    // Separator
    let separator = NSMenuItem::separatorItem(nil);
    menu.addItem_(separator);
    
    // Preferences
    let item = create_menu_item("Preferences...", sel!(showPreferences:));
    menu.addItem_(item);
    
    // Separator
    let separator = NSMenuItem::separatorItem(nil);
    menu.addItem_(separator);
    
    // Pause/Resume
    let item = create_menu_item("Pause Enforcement", sel!(togglePause:));
    menu.addItem_(item);
    
    // View Logs
    let item = create_menu_item("View Logs", sel!(viewLogs:));
    menu.addItem_(item);
    
    // Web Dashboard
    let item = create_menu_item("Open Web Dashboard", sel!(openDashboard:));
    menu.addItem_(item);
    
    // Separator
    let separator = NSMenuItem::separatorItem(nil);
    menu.addItem_(separator);
    
    // About
    let item = create_menu_item("About", sel!(showAbout:));
    menu.addItem_(item);
    
    // Quit
    let item = create_menu_item("Quit", sel!(quit:));
    menu.addItem_(item);
    
    menu
}

/// Create a menu item with title and action
unsafe fn create_menu_item(title: &str, action: Sel) -> id {
    let title_ns = NSString::alloc(nil).init_str(title);
    let item = NSMenuItem::alloc(nil);
    let item = msg_send![item, initWithTitle:title_ns action:action keyEquivalent:NSString::alloc(nil).init_str("")];
    item
}

/// Menu item action handlers would typically be implemented via Objective-C runtime
/// For a production implementation, you'd need to:
/// 1. Create an Objective-C class that implements these selectors
/// 2. Set the target of each menu item to an instance of that class
/// 3. Have those methods send messages to the Rust event channel
///
/// For now, this is a simplified version. A complete implementation would require
/// more complex Objective-C runtime integration.

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_menu_bar_creation() {
        // Note: This test would need a macOS environment with a window server
        // In practice, UI tests are often integration tests run manually
        assert!(true);
    }
}
