//! Permission Prompt Dialogs
//!
//! Native macOS NSAlert dialogs for security decisions.

use anyhow::Result;
use cocoa::appkit::{NSAlert, NSAlertStyle};
use cocoa::base::{id, nil};
use cocoa::foundation::{NSAutoreleasePool, NSString};
use objc::{msg_send, sel, sel_impl};
use std::net::IpAddr;

/// Type of permission prompt
#[derive(Debug, Clone)]
pub enum PromptType {
    /// Network connection request
    NetworkConnection {
        destination: IpAddr,
        port: u16,
        protocol: String,
        process: Option<String>,
    },
    /// File access request
    FileAccess {
        path: String,
        operation: FileOperation,
        process: Option<String>,
    },
}

/// File operation types
#[derive(Debug, Clone)]
pub enum FileOperation {
    Read,
    Write,
    Execute,
    Delete,
    Create,
}

impl FileOperation {
    fn as_str(&self) -> &str {
        match self {
            FileOperation::Read => "read",
            FileOperation::Write => "write",
            FileOperation::Execute => "execute",
            FileOperation::Delete => "delete",
            FileOperation::Create => "create",
        }
    }
}

/// User response to permission prompt
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PromptResponse {
    /// Allow this request once
    AllowOnce,
    /// Allow all future requests
    AllowAlways,
    /// Block this request
    Block,
    /// Block all future requests
    BlockAlways,
    /// Prompt was cancelled or timed out
    Cancelled,
}

/// Permission prompt handler
pub struct PermissionPrompt;

impl PermissionPrompt {
    /// Show a permission prompt and wait for user response
    pub fn show(prompt_type: PromptType) -> Result<PromptResponse> {
        unsafe {
            let _pool = NSAutoreleasePool::new(nil);
            
            // Create alert
            let alert: id = msg_send![class!(NSAlert), new];
            
            // Configure alert based on prompt type
            match &prompt_type {
                PromptType::NetworkConnection {
                    destination,
                    port,
                    protocol,
                    process,
                } => {
                    Self::configure_network_alert(alert, destination, *port, protocol, process);
                }
                PromptType::FileAccess {
                    path,
                    operation,
                    process,
                } => {
                    Self::configure_file_alert(alert, path, operation, process);
                }
            }
            
            // Show alert and get response
            let response: i64 = msg_send![alert, runModal];
            
            // Map button response to PromptResponse
            Ok(Self::map_response(response, &prompt_type))
        }
    }
    
    /// Configure network connection alert
    unsafe fn configure_network_alert(
        alert: id,
        destination: &IpAddr,
        port: u16,
        protocol: &str,
        process: &Option<String>,
    ) {
        // Set alert style
        let _: () = msg_send![alert, setAlertStyle: NSAlertStyle::NSWarningAlertStyle];
        
        // Set message text
        let message = NSString::alloc(nil)
            .init_str("Network Connection Request");
        let _: () = msg_send![alert, setMessageText: message];
        
        // Set informative text
        let process_name = process
            .as_ref()
            .map(|p| p.as_str())
            .unwrap_or("Unknown process");
        
        let info = format!(
            "Process '{}' is attempting to connect to:\n\n\
             Destination: {}\n\
             Port: {}\n\
             Protocol: {}\n\n\
             Do you want to allow this connection?",
            process_name, destination, port, protocol
        );
        let info_text = NSString::alloc(nil).init_str(&info);
        let _: () = msg_send![alert, setInformativeText: info_text];
        
        // Add buttons
        let _: () = msg_send![alert, addButtonWithTitle: NSString::alloc(nil).init_str("Allow Once")];
        let _: () = msg_send![alert, addButtonWithTitle: NSString::alloc(nil).init_str("Allow Always")];
        let _: () = msg_send![alert, addButtonWithTitle: NSString::alloc(nil).init_str("Block")];
    }
    
    /// Configure file access alert
    unsafe fn configure_file_alert(
        alert: id,
        path: &str,
        operation: &FileOperation,
        process: &Option<String>,
    ) {
        // Set alert style
        let _: () = msg_send![alert, setAlertStyle: NSAlertStyle::NSWarningAlertStyle];
        
        // Set message text
        let message = NSString::alloc(nil)
            .init_str("File Access Request");
        let _: () = msg_send![alert, setMessageText: message];
        
        // Set informative text
        let process_name = process
            .as_ref()
            .map(|p| p.as_str())
            .unwrap_or("Unknown process");
        
        let info = format!(
            "Process '{}' is attempting to {} file:\n\n\
             Path: {}\n\n\
             Do you want to allow this operation?",
            process_name,
            operation.as_str(),
            path
        );
        let info_text = NSString::alloc(nil).init_str(&info);
        let _: () = msg_send![alert, setInformativeText: info_text];
        
        // Add buttons
        let _: () = msg_send![alert, addButtonWithTitle: NSString::alloc(nil).init_str("Allow Once")];
        let _: () = msg_send![alert, addButtonWithTitle: NSString::alloc(nil).init_str("Allow Always")];
        let _: () = msg_send![alert, addButtonWithTitle: NSString::alloc(nil).init_str("Block")];
    }
    
    /// Map NSAlert response to PromptResponse
    fn map_response(response: i64, _prompt_type: &PromptType) -> PromptResponse {
        // NSAlert returns 1000 for first button, 1001 for second, 1002 for third, etc.
        match response {
            1000 => PromptResponse::AllowOnce,
            1001 => PromptResponse::AllowAlways,
            1002 => PromptResponse::Block,
            _ => PromptResponse::Cancelled,
        }
    }
    
    /// Show a simple information alert
    pub fn show_info(title: &str, message: &str) -> Result<()> {
        unsafe {
            let _pool = NSAutoreleasePool::new(nil);
            
            let alert: id = msg_send![class!(NSAlert), new];
            let _: () = msg_send![alert, setAlertStyle: NSAlertStyle::NSInformationalAlertStyle];
            
            let title_ns = NSString::alloc(nil).init_str(title);
            let _: () = msg_send![alert, setMessageText: title_ns];
            
            let message_ns = NSString::alloc(nil).init_str(message);
            let _: () = msg_send![alert, setInformativeText: message_ns];
            
            let _: () = msg_send![alert, addButtonWithTitle: NSString::alloc(nil).init_str("OK")];
            
            let _response: i64 = msg_send![alert, runModal];
        }
        
        Ok(())
    }
    
    /// Show a simple error alert
    pub fn show_error(title: &str, message: &str) -> Result<()> {
        unsafe {
            let _pool = NSAutoreleasePool::new(nil);
            
            let alert: id = msg_send![class!(NSAlert), new];
            let _: () = msg_send![alert, setAlertStyle: NSAlertStyle::NSCriticalAlertStyle];
            
            let title_ns = NSString::alloc(nil).init_str(title);
            let _: () = msg_send![alert, setMessageText: title_ns];
            
            let message_ns = NSString::alloc(nil).init_str(message);
            let _: () = msg_send![alert, setInformativeText: message_ns];
            
            let _: () = msg_send![alert, addButtonWithTitle: NSString::alloc(nil).init_str("OK")];
            
            let _response: i64 = msg_send![alert, runModal];
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_file_operation_as_str() {
        assert_eq!(FileOperation::Read.as_str(), "read");
        assert_eq!(FileOperation::Write.as_str(), "write");
        assert_eq!(FileOperation::Execute.as_str(), "execute");
        assert_eq!(FileOperation::Delete.as_str(), "delete");
        assert_eq!(FileOperation::Create.as_str(), "create");
    }
    
    #[test]
    fn test_prompt_response_equality() {
        assert_eq!(PromptResponse::AllowOnce, PromptResponse::AllowOnce);
        assert_ne!(PromptResponse::AllowOnce, PromptResponse::Block);
    }
}
