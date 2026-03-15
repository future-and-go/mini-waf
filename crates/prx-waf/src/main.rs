use std::sync::Arc;

use clap::{Parser, Subcommand};
use tracing::info;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

use waf_api::{start_api_server, AppState};
use waf_common::config::{load_config, AppConfig};
use waf_engine::{WafEngine, WafEngineConfig};
use waf_storage::Database;
use gateway::{HostRouter, WafProxy};

/// PRX-WAF — High-performance Pingora-based Web Application Firewall
#[derive(Parser, Debug)]
#[command(name = "prx-waf", version, about)]
struct Cli {
    /// Path to configuration file
    #[arg(short, long, default_value = "configs/default.toml")]
    config: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Start the proxy and management API
    Run,
    /// Run database migrations only
    Migrate,
}

fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::from_default_env()
                .add_directive("info".parse().unwrap()),
        )
        .init();

    let cli = Cli::parse();
    info!("PRX-WAF v{}", env!("CARGO_PKG_VERSION"));

    let config = load_config(&cli.config).unwrap_or_else(|e| {
        tracing::warn!(
            "Failed to load config from {}: {}. Using defaults.",
            cli.config,
            e
        );
        AppConfig::default()
    });

    match cli.command {
        Commands::Migrate => {
            // One-shot async task for migration
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?
                .block_on(run_migrate(&config))?;
        }
        Commands::Run => {
            run_server(config)?;
        }
    }

    Ok(())
}

/// Run database migrations only
async fn run_migrate(config: &AppConfig) -> anyhow::Result<()> {
    info!("Running database migrations...");
    let db =
        Database::connect(&config.storage.database_url, config.storage.max_connections).await?;
    db.migrate().await?;
    info!("Migrations complete.");
    Ok(())
}

/// Start the full server: async init → API server thread → Pingora proxy
fn run_server(config: AppConfig) -> anyhow::Result<()> {
    use pingora_core::server::Server;

    // Phase 1: async initialization (db, engine, rules)
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    let (engine, router, api_state) = rt.block_on(init_async(&config))?;

    // Phase 2: start the management API in a background thread
    let api_listen = config.api.listen_addr.clone();
    let api_state_bg = Arc::clone(&api_state);
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("failed to build API runtime");
        rt.block_on(async move {
            if let Err(e) = start_api_server(&api_listen, api_state_bg).await {
                tracing::error!("API server error: {}", e);
            }
        });
    });

    // Phase 3: build and run Pingora proxy (blocks forever)
    let mut server = Server::new(None)?;
    server.bootstrap();

    let proxy = WafProxy::new(router, engine);
    let mut proxy_service = pingora_proxy::http_proxy_service(&server.configuration, proxy);
    proxy_service.add_tcp(&config.proxy.listen_addr);
    server.add_service(proxy_service);

    info!("Proxy listening on {}", config.proxy.listen_addr);
    info!("Management API listening on {}", config.api.listen_addr);
    info!("Press Ctrl+C to stop");

    server.run_forever();
}

/// Async initialization: database, engine, rule loading, host registration
async fn init_async(
    config: &AppConfig,
) -> anyhow::Result<(Arc<WafEngine>, Arc<HostRouter>, Arc<AppState>)> {
    info!("Connecting to database...");
    let db = Arc::new(
        Database::connect(&config.storage.database_url, config.storage.max_connections).await?,
    );

    info!("Running database migrations...");
    db.migrate().await?;

    // WAF engine
    let engine = Arc::new(WafEngine::new(Arc::clone(&db), WafEngineConfig::default()));
    engine.reload_rules().await?;

    // Host router
    let router = Arc::new(HostRouter::new());

    // Load hosts from database
    let hosts = db.list_hosts().await?;
    info!("Loading {} hosts from database", hosts.len());
    for host in &hosts {
        use waf_common::HostConfig;
        let cfg = Arc::new(HostConfig {
            code: host.code.clone(),
            host: host.host.clone(),
            port: host.port as u16,
            ssl: host.ssl,
            guard_status: host.guard_status,
            remote_host: host.remote_host.clone(),
            remote_port: host.remote_port as u16,
            remote_ip: host.remote_ip.clone(),
            cert_file: host.cert_file.clone(),
            key_file: host.key_file.clone(),
            start_status: host.start_status,
            ..HostConfig::default()
        });
        router.register(cfg);
    }

    // Register hosts from config file
    for entry in &config.hosts {
        use waf_common::HostConfig;
        let code = format!(
            "cfg-{}",
            &uuid::Uuid::new_v4().to_string().replace('-', "")[..8]
        );
        let cfg = Arc::new(HostConfig {
            code,
            host: entry.host.clone(),
            port: entry.port,
            ssl: entry.ssl.unwrap_or(false),
            guard_status: entry.guard_status.unwrap_or(true),
            remote_host: entry.remote_host.clone(),
            remote_port: entry.remote_port,
            cert_file: entry.cert_file.clone(),
            key_file: entry.key_file.clone(),
            ..HostConfig::default()
        });
        router.register(cfg);
    }

    info!("Registered {} host routes", router.len());

    let api_state = Arc::new(AppState::new(
        Arc::clone(&db),
        Arc::clone(&engine),
        Arc::clone(&router),
    ));

    Ok((engine, router, api_state))
}
