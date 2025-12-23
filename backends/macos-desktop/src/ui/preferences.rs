//! Preferences Window
//!
//! Native macOS preferences window with tabbed interface.

use anyhow::Result;
use cocoa::appkit::{
    NSApp, NSApplication, NSBackingStoreType, NSTabView, NSTabViewItem, NSTextField, NSWindow,
    NSWindowStyleMask,
};
use cocoa::base::{id, nil, NO, YES};
use cocoa::foundation::{NSAutoreleasePool, NSPoint, NSRect, NSSize, NSString};
use objc::{class, msg_send, sel, sel_impl};
use std::sync::{Arc, Mutex};

use agent_gateway_enforcer_common::config::UnifiedConfig;

/// Preferences window tabs
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreferencesTab {
    General,
    Network,
    FileAccess,
    Agents,
    Advanced,
}

impl PreferencesTab {
    fn title(&self) -> &str {
        match self {
            PreferencesTab::General => "General",
            PreferencesTab::Network => "Network",
            PreferencesTab::FileAccess => "File Access",
            PreferencesTab::Agents => "Agents",
            PreferencesTab::Advanced => "Advanced",
        }
    }
}

/// Preferences Window
pub struct PreferencesWindow {
    window: Arc<Mutex<id>>,
    config: Arc<Mutex<UnifiedConfig>>,
}

impl PreferencesWindow {
    /// Create a new preferences window
    pub fn new() -> Result<Self> {
        unsafe {
            let _pool = NSAutoreleasePool::new(nil);
            
            // Create window
            let window = Self::create_window();
            
            // Create tab view
            let tab_view = Self::create_tab_view();
            
            // Add tab view to window
            let content_view: id = msg_send![window, contentView];
            let _: () = msg_send![content_view, addSubview: tab_view];
            
            // Load default config
            let config = UnifiedConfig::default();
            
            Ok(Self {
                window: Arc::new(Mutex::new(window)),
                config: Arc::new(Mutex::new(config)),
            })
        }
    }
    
    /// Create the main window
    unsafe fn create_window() -> id {
        let window = NSWindow::alloc(nil);
        
        let frame = NSRect::new(
            NSPoint::new(100.0, 100.0),
            NSSize::new(600.0, 500.0),
        );
        
        let style_mask = NSWindowStyleMask::NSTitledWindowMask
            | NSWindowStyleMask::NSClosableWindowMask
            | NSWindowStyleMask::NSMiniaturizableWindowMask
            | NSWindowStyleMask::NSResizableWindowMask;
        
        let window: id = msg_send![
            window,
            initWithContentRect:frame
            styleMask:style_mask
            backing:NSBackingStoreType::NSBackingStoreBuffered
            defer:NO
        ];
        
        let title = NSString::alloc(nil).init_str("Agent Gateway Enforcer Preferences");
        let _: () = msg_send![window, setTitle: title];
        
        // Center window
        let _: () = msg_send![window, center];
        
        window
    }
    
    /// Create the tab view
    unsafe fn create_tab_view() -> id {
        let tab_view = NSTabView::alloc(nil);
        let frame = NSRect::new(
            NSPoint::new(0.0, 0.0),
            NSSize::new(600.0, 500.0),
        );
        let tab_view: id = msg_send![tab_view, initWithFrame: frame];
        
        // Add tabs
        Self::add_general_tab(tab_view);
        Self::add_network_tab(tab_view);
        Self::add_file_access_tab(tab_view);
        Self::add_agents_tab(tab_view);
        Self::add_advanced_tab(tab_view);
        
        tab_view
    }
    
    /// Add General tab
    unsafe fn add_general_tab(tab_view: id) {
        let tab_item = NSTabViewItem::alloc(nil);
        let label = NSString::alloc(nil).init_str(PreferencesTab::General.title());
        let tab_item: id = msg_send![tab_item, initWithIdentifier: label];
        let _: () = msg_send![tab_item, setLabel: label];
        
        // Create view for tab content
        let view = Self::create_general_view();
        let _: () = msg_send![tab_item, setView: view];
        
        let _: () = msg_send![tab_view, addTabViewItem: tab_item];
    }
    
    /// Add Network tab
    unsafe fn add_network_tab(tab_view: id) {
        let tab_item = NSTabViewItem::alloc(nil);
        let label = NSString::alloc(nil).init_str(PreferencesTab::Network.title());
        let tab_item: id = msg_send![tab_item, initWithIdentifier: label];
        let _: () = msg_send![tab_item, setLabel: label];
        
        // Create view for tab content
        let view = Self::create_network_view();
        let _: () = msg_send![tab_item, setView: view];
        
        let _: () = msg_send![tab_view, addTabViewItem: tab_item];
    }
    
    /// Add File Access tab
    unsafe fn add_file_access_tab(tab_view: id) {
        let tab_item = NSTabViewItem::alloc(nil);
        let label = NSString::alloc(nil).init_str(PreferencesTab::FileAccess.title());
        let tab_item: id = msg_send![tab_item, initWithIdentifier: label];
        let _: () = msg_send![tab_item, setLabel: label];
        
        // Create view for tab content
        let view = Self::create_file_access_view();
        let _: () = msg_send![tab_item, setView: view];
        
        let _: () = msg_send![tab_view, addTabViewItem: tab_item];
    }
    
    /// Add Agents tab
    unsafe fn add_agents_tab(tab_view: id) {
        let tab_item = NSTabViewItem::alloc(nil);
        let label = NSString::alloc(nil).init_str(PreferencesTab::Agents.title());
        let tab_item: id = msg_send![tab_item, initWithIdentifier: label];
        let _: () = msg_send![tab_item, setLabel: label];
        
        // Create view for tab content
        let view = Self::create_agents_view();
        let _: () = msg_send![tab_item, setView: view];
        
        let _: () = msg_send![tab_view, addTabViewItem: tab_item];
    }
    
    /// Add Advanced tab
    unsafe fn add_advanced_tab(tab_view: id) {
        let tab_item = NSTabViewItem::alloc(nil);
        let label = NSString::alloc(nil).init_str(PreferencesTab::Advanced.title());
        let tab_item: id = msg_send![tab_item, initWithIdentifier: label];
        let _: () = msg_send![tab_item, setLabel: label];
        
        // Create view for tab content
        let view = Self::create_advanced_view();
        let _: () = msg_send![tab_item, setView: view];
        
        let _: () = msg_send![tab_view, addTabViewItem: tab_item];
    }
    
    /// Create General tab view
    unsafe fn create_general_view() -> id {
        let view: id = msg_send![class!(NSView), alloc];
        let frame = NSRect::new(
            NSPoint::new(0.0, 0.0),
            NSSize::new(580.0, 450.0),
        );
        let view: id = msg_send![view, initWithFrame: frame];
        
        // Add label
        let label = Self::create_label("General Settings", 20.0, 400.0);
        let _: () = msg_send![view, addSubview: label];
        
        // Add description
        let desc = Self::create_label(
            "Configure general application settings",
            20.0,
            370.0,
        );
        let _: () = msg_send![view, addSubview: desc];
        
        view
    }
    
    /// Create Network tab view
    unsafe fn create_network_view() -> id {
        let view: id = msg_send![class!(NSView), alloc];
        let frame = NSRect::new(
            NSPoint::new(0.0, 0.0),
            NSSize::new(580.0, 450.0),
        );
        let view: id = msg_send![view, initWithFrame: frame];
        
        // Add label
        let label = Self::create_label("Network Settings", 20.0, 400.0);
        let _: () = msg_send![view, addSubview: label];
        
        // Add description
        let desc = Self::create_label(
            "Configure network gateway enforcement rules",
            20.0,
            370.0,
        );
        let _: () = msg_send![view, addSubview: desc];
        
        view
    }
    
    /// Create File Access tab view
    unsafe fn create_file_access_view() -> id {
        let view: id = msg_send![class!(NSView), alloc];
        let frame = NSRect::new(
            NSPoint::new(0.0, 0.0),
            NSSize::new(580.0, 450.0),
        );
        let view: id = msg_send![view, initWithFrame: frame];
        
        // Add label
        let label = Self::create_label("File Access Settings", 20.0, 400.0);
        let _: () = msg_send![view, addSubview: label];
        
        // Add description
        let desc = Self::create_label(
            "Configure file access control policies",
            20.0,
            370.0,
        );
        let _: () = msg_send![view, addSubview: desc];
        
        view
    }
    
    /// Create Agents tab view
    unsafe fn create_agents_view() -> id {
        let view: id = msg_send![class!(NSView), alloc];
        let frame = NSRect::new(
            NSPoint::new(0.0, 0.0),
            NSSize::new(580.0, 450.0),
        );
        let view: id = msg_send![view, initWithFrame: frame];
        
        // Add label
        let label = Self::create_label("Agent Settings", 20.0, 400.0);
        let _: () = msg_send![view, addSubview: label];
        
        // Add description
        let desc = Self::create_label(
            "Configure agent-specific permissions and settings",
            20.0,
            370.0,
        );
        let _: () = msg_send![view, addSubview: desc];
        
        view
    }
    
    /// Create Advanced tab view
    unsafe fn create_advanced_view() -> id {
        let view: id = msg_send![class!(NSView), alloc];
        let frame = NSRect::new(
            NSPoint::new(0.0, 0.0),
            NSSize::new(580.0, 450.0),
        );
        let view: id = msg_send![view, initWithFrame: frame];
        
        // Add label
        let label = Self::create_label("Advanced Settings", 20.0, 400.0);
        let _: () = msg_send![view, addSubview: label];
        
        // Add description
        let desc = Self::create_label(
            "Advanced configuration options",
            20.0,
            370.0,
        );
        let _: () = msg_send![view, addSubview: desc];
        
        view
    }
    
    /// Create a text label
    unsafe fn create_label(text: &str, x: f64, y: f64) -> id {
        let label = NSTextField::alloc(nil);
        let frame = NSRect::new(
            NSPoint::new(x, y),
            NSSize::new(540.0, 24.0),
        );
        let label: id = msg_send![label, initWithFrame: frame];
        
        let text_ns = NSString::alloc(nil).init_str(text);
        let _: () = msg_send![label, setStringValue: text_ns];
        let _: () = msg_send![label, setBezeled: NO];
        let _: () = msg_send![label, setDrawsBackground: NO];
        let _: () = msg_send![label, setEditable: NO];
        let _: () = msg_send![label, setSelectable: NO];
        
        label
    }
    
    /// Show the preferences window
    pub fn show(&self) -> Result<()> {
        unsafe {
            let _pool = NSAutoreleasePool::new(nil);
            let window = self.window.lock().unwrap();
            let _: () = msg_send![*window, makeKeyAndOrderFront: nil];
        }
        Ok(())
    }
    
    /// Hide the preferences window
    pub fn hide(&self) -> Result<()> {
        unsafe {
            let _pool = NSAutoreleasePool::new(nil);
            let window = self.window.lock().unwrap();
            let _: () = msg_send![*window, orderOut: nil];
        }
        Ok(())
    }
    
    /// Load configuration
    pub fn load_config(&self, config: UnifiedConfig) -> Result<()> {
        let mut current_config = self.config.lock().unwrap();
        *current_config = config;
        
        // Update UI with new config
        // TODO: Implement UI update logic
        
        Ok(())
    }
    
    /// Save configuration
    pub fn save_config(&self) -> Result<UnifiedConfig> {
        let config = self.config.lock().unwrap();
        Ok(config.clone())
    }
    
    /// Validate current configuration
    pub fn validate_config(&self) -> Result<()> {
        let _config = self.config.lock().unwrap();
        
        // TODO: Implement validation logic
        
        Ok(())
    }
}

impl Drop for PreferencesWindow {
    fn drop(&mut self) {
        unsafe {
            let _pool = NSAutoreleasePool::new(nil);
            let window = self.window.lock().unwrap();
            let _: () = msg_send![*window, close];
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_preferences_tab_titles() {
        assert_eq!(PreferencesTab::General.title(), "General");
        assert_eq!(PreferencesTab::Network.title(), "Network");
        assert_eq!(PreferencesTab::FileAccess.title(), "File Access");
        assert_eq!(PreferencesTab::Agents.title(), "Agents");
        assert_eq!(PreferencesTab::Advanced.title(), "Advanced");
    }
}
