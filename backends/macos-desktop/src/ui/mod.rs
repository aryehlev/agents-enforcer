//! macOS UI Components
//!
//! This module provides native macOS user interface components including:
//! - Menu bar status item
//! - Permission prompt dialogs
//! - Preferences window
//! - System integration

pub mod menu_bar;
pub mod prompts;
pub mod preferences;
pub mod system_integration;

use anyhow::Result;
use tokio::sync::mpsc;

pub use menu_bar::MenuBarApp;
pub use prompts::{PermissionPrompt, PromptResponse, PromptType};
pub use preferences::PreferencesWindow;
pub use system_integration::SystemIntegration;

/// UI Event types
#[derive(Debug, Clone)]
pub enum UIEvent {
    /// Show status window
    ShowStatus,
    /// Show preferences
    ShowPreferences,
    /// Pause/Resume enforcement
    TogglePause(bool),
    /// View logs
    ViewLogs,
    /// Open web dashboard
    OpenDashboard,
    /// Show about dialog
    ShowAbout,
    /// Quit application
    Quit,
    /// Permission prompt response
    PermissionResponse(PromptResponse),
}

/// UI Manager for coordinating all UI components
pub struct UIManager {
    menu_bar: Option<MenuBarApp>,
    preferences: Option<PreferencesWindow>,
    event_tx: mpsc::UnboundedSender<UIEvent>,
    event_rx: mpsc::UnboundedReceiver<UIEvent>,
}

impl UIManager {
    /// Create a new UI manager
    pub fn new() -> Self {
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        
        Self {
            menu_bar: None,
            preferences: None,
            event_tx,
            event_rx,
        }
    }
    
    /// Initialize the UI components
    pub fn initialize(&mut self) -> Result<()> {
        tracing::info!("Initializing macOS UI components");
        
        // Initialize menu bar
        self.menu_bar = Some(MenuBarApp::new(self.event_tx.clone())?);
        
        Ok(())
    }
    
    /// Get event receiver
    pub fn event_receiver(&mut self) -> &mut mpsc::UnboundedReceiver<UIEvent> {
        &mut self.event_rx
    }
    
    /// Update menu bar status
    pub fn update_status(&self, status: &str) -> Result<()> {
        if let Some(menu_bar) = &self.menu_bar {
            menu_bar.update_status(status)?;
        }
        Ok(())
    }
    
    /// Show permission prompt
    pub fn show_permission_prompt(&self, prompt_type: PromptType) -> Result<PromptResponse> {
        PermissionPrompt::show(prompt_type)
    }
    
    /// Show preferences window
    pub fn show_preferences(&mut self) -> Result<()> {
        if self.preferences.is_none() {
            self.preferences = Some(PreferencesWindow::new()?);
        }
        
        if let Some(prefs) = &self.preferences {
            prefs.show()?;
        }
        
        Ok(())
    }
    
    /// Cleanup UI components
    pub fn cleanup(&mut self) -> Result<()> {
        tracing::info!("Cleaning up macOS UI components");
        
        self.menu_bar = None;
        self.preferences = None;
        
        Ok(())
    }
}

impl Default for UIManager {
    fn default() -> Self {
        Self::new()
    }
}
