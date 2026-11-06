mod analytics;
mod apps;
mod db;
mod output;
mod record;
mod resolve;
mod sniff;
mod tagger;
mod trackers;

use anyhow::Result;
use clap::{Parser, Subcommand};
use output::{run_sql, Format};
use std::path::PathBuf;

const DEFAULT_DATA_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../data");

/// Log where this Mac's network connections go, and analyze them.
#[derive(Parser)]
#[command(name = "netlog", version, after_help = "AI agents: run `netlog guide` first, then `netlog suggest`.")]
struct Cli {
    /// SQLite database (shared with the netmap web viewer)
    #[arg(long, global = true, env = "NETLOG_DB")]
    db: Option<PathBuf>,
    /// Output format; auto = table in a terminal, JSON when piped
    #[arg(long, short, global = true, value_enum, default_value_t = Format::Auto)]
    format: Format,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Record connections (lsof, or pktap when root) and hostnames (DNS + TLS SNI) until stopped
    Record {
        /// Seconds between lsof polls
        #[arg(long, default_value_t = 2.0)]
        interval: f64,
        /// Skip packet capture (no hostnames, no BPF access needed)
        #[arg(long)]
        no_sniff: bool,
        /// Don't use pktap for process names even when running as root
        #[arg(long)]
        no_pktap: bool,
        /// Directory holding the DB-IP .mmdb files
        #[arg(long)]
        data_dir: Option<PathBuf>,
    },
    /// Run a logging DNS server for the LAN (point the router's DNS at this machine)
    Resolve {
        /// Address to listen on
        #[arg(long, default_value = "0.0.0.0:53")]
        listen: String,
        /// Upstream DNS servers, tried in order
        #[arg(long, default_values_t = ["1.1.1.1".to_string(), "9.9.9.9".to_string()])]
        upstream: Vec<String>,
    },
    /// Give a LAN device a name for reports (by IP or MAC)
    Name {
        device: String,
        label: String,
    },
    /// Rank findings worth investigating; each comes with a command to run next
    Suggest {
        #[arg(long, default_value = "24h")]
        since: String,
    },
    /// Run a built-in report (omit NAME to list them)
    Report {
        name: Option<String>,
        /// Time window: 90s, 15m, 1h, 24h, 7d or all
        #[arg(long, default_value = "24h")]
        since: String,
        /// Only this app (exact process name, see `report apps`)
        #[arg(long)]
        app: Option<String>,
        /// Only this LAN device (label, MAC or IP, see `report devices`)
        #[arg(long)]
        device: Option<String>,
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    /// Run read-only SQL. Helpers: since('1h'), base_domain(host), is_tracker(host)
    Query {
        sql: String,
        #[arg(long, default_value_t = 200)]
        limit: usize,
    },
    /// Live log of connections as they open (JSON lines when piped)
    Tail {
        /// Only this app
        #[arg(long)]
        app: Option<String>,
        /// Also show the last N opens before following
        #[arg(long, default_value_t = 0)]
        last: usize,
        /// Exit after printing N opens (useful for agents)
        #[arg(long)]
        count: Option<usize>,
    },
    /// Describe the data model, helper functions and example queries
    Schema,
    /// Is the recorder running, and how much data is there?
    Status,
    /// Usage guide for AI agents
    Guide,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let data_dir = PathBuf::from(DEFAULT_DATA_DIR);
    let db_path = cli.db.clone().unwrap_or_else(|| data_dir.join("netmap.sqlite"));
    let fmt = cli.format;

    match cli.cmd {
        Cmd::Record { interval, no_sniff, no_pktap, data_dir: dir } => {
            record::run(&db_path, &dir.unwrap_or(data_dir), record::Options { interval, sniff: !no_sniff, pktap: !no_pktap })?
        }
        Cmd::Guide => print!("{}", analytics::GUIDE),
        Cmd::Schema => analytics::schema(fmt),
        Cmd::Report { name: None, .. } => analytics::list_reports().print(fmt),
        Cmd::Report { name: Some(name), since, app, device, limit } => {
            let conn = db::open(&db_path, true)?;
            analytics::report(&conn, &name, &since, app.as_deref(), device.as_deref(), limit)?.print(fmt)
        }
        Cmd::Resolve { listen, upstream } => resolve::run(&db_path, resolve::Options { listen, upstreams: upstream })?,
        Cmd::Name { device, label } => {
            let conn = db::open(&db_path, false)?;
            let n = conn.execute("UPDATE devices SET label = ?1 WHERE ip = ?2 OR mac = lower(?2)", (&label, &device))?;
            if n == 0 {
                anyhow::bail!("no device {device:?} seen yet; run `netlog report devices` for the list");
            }
            println!("named {device} {label:?}");
        }
        Cmd::Suggest { since } => analytics::suggest(&db::open(&db_path, true)?, &since)?.print(fmt),
        Cmd::Query { sql, limit } => run_sql(&db::open(&db_path, true)?, &sql, &[], limit)?.print(fmt),
        Cmd::Tail { app, last, count } => {
            analytics::tail(&db::open(&db_path, true)?, app.as_deref(), last, count, fmt)?
        }
        Cmd::Status => analytics::status(&db::open(&db_path, true)?)?.print(fmt),
    }
    Ok(())
}
