//! Migration CLI tool for Linux eBPF backend configuration
//!
//! This tool helps migrate from legacy configuration formats to the new unified format.

use agent_gateway_enforcer_backend_ebpf_linux::migration::{
    ConfigMigrator, MigrationArgs, MigratorCli,
};
use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "config-migrator")]
#[command(about = "Migration tool for agent gateway enforcer configuration")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Migrate configuration file
    Migrate {
        /// Input configuration file
        #[arg(short, long)]
        input: PathBuf,

        /// Output configuration file (optional, prints to stdout if not provided)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Validate only (don't migrate)
        #[arg(long)]
        validate_only: bool,
    },

    /// Validate configuration file
    Validate {
        /// Configuration file to validate
        #[arg(short, long)]
        input: PathBuf,
    },

    /// Show configuration schema
    Schema {
        /// Output format (json, toml)
        #[arg(short, long, default_value = "json")]
        format: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Migrate {
            input,
            output,
            validate_only,
        } => {
            let args = MigrationArgs {
                input_file: input,
                output_file: output,
                validate_only,
            };

            if validate_only {
                let migrator = ConfigMigrator::new();
                let config = migrator.load_and_migrate_file(&args.input_file)?;
                migrator.validate_config(&config)?;
                println!("Configuration is valid!");
            } else {
                MigratorCli::run_migration(&args).await?;
            }
        }

        Commands::Validate { input } => {
            let migrator = ConfigMigrator::new();
            let config = migrator.load_and_migrate_file(&input)?;
            migrator.validate_config(&config)?;
            println!("Configuration is valid!");
        }

        Commands::Schema { format } => {
            let schema = generate_schema(&format)?;
            println!("{}", schema);
        }
    }

    Ok(())
}

fn generate_schema(format: &str) -> Result<String> {
    use serde_json::json;

    let schema = json!({
        "$schema": "http://json-schema.org/draft-07/schema#",
        "title": "Agent Gateway Enforcer Configuration",
        "description": "Unified configuration for agent gateway enforcer",
        "type": "object",
        "properties": {
            "gateways": {
                "type": "array",
                "description": "List of allowed network gateways",
                "items": {
                    "type": "object",
                    "properties": {
                        "address": {
                            "type": "string",
                            "description": "Gateway IP address"
                        },
                        "port": {
                            "type": "integer",
                            "minimum": 1,
                            "maximum": 65535,
                            "description": "Gateway port number"
                        },
                        "enabled": {
                            "type": "boolean",
                            "description": "Whether this gateway is enabled"
                        },
                        "description": {
                            "type": "string",
                            "description": "Optional description"
                        }
                    },
                    "required": ["address", "port", "enabled"]
                }
            },
            "file_access": {
                "type": "object",
                "description": "File access control configuration",
                "properties": {
                    "allowed_paths": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "List of allowed file paths"
                    },
                    "denied_paths": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "List of denied file paths"
                    },
                    "default_deny": {
                        "type": "boolean",
                        "description": "Whether to deny by default"
                    }
                }
            },
            "backend_settings": {
                "type": "object",
                "description": "Backend-specific settings"
            }
        }
    });

    match format.to_lowercase().as_str() {
        "json" => Ok(serde_json::to_string_pretty(&schema)?),
        "toml" => Ok(toml::to_string_pretty(&schema)?),
        _ => Err(anyhow::anyhow!("Unsupported format: {}", format)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_schema_generation() {
        let schema = generate_schema("json").unwrap();
        assert!(schema.contains("gateways"));
        assert!(schema.contains("file_access"));
        assert!(schema.contains("backend_settings"));
    }

    #[tokio::test]
    async fn test_migration_cli() {
        let temp_dir = tempdir().unwrap();
        let input_file = temp_dir.path().join("input.json");

        // Create test input
        let legacy_config = r#"
        {
            "gateways": ["10.0.0.1:8080", "192.168.1.100:443"],
            "file_enforcement": {
                "enabled": true,
                "default_deny": false,
                "allow_paths": ["/tmp", "/var/log"],
                "deny_paths": ["/etc/shadow", "/root"]
            }
        }
        "#;

        fs::write(&input_file, legacy_config).unwrap();

        let args = MigrationArgs {
            input_file: input_file.clone(),
            output_file: None,
            validate_only: false,
        };

        // Should not panic
        let result = MigratorCli::run_migration(&args).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_validation_only() {
        let temp_dir = tempdir().unwrap();
        let input_file = temp_dir.path().join("input.json");

        // Create valid test input
        let legacy_config = r#"
        {
            "gateways": ["10.0.0.1:8080"],
            "file_enforcement": {
                "enabled": true,
                "default_deny": true,
                "allow_paths": [],
                "deny_paths": ["/etc/shadow"]
            }
        }
        "#;

        fs::write(&input_file, legacy_config).unwrap();

        let args = MigrationArgs {
            input_file: input_file.clone(),
            output_file: None,
            validate_only: true,
        };

        // Should not panic
        let result = MigratorCli::run_migration(&args).await;
        assert!(result.is_ok());
    }
}
