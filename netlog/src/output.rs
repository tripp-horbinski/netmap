//! Result tables and how they print: aligned text for people, JSON or CSV for tools.

use anyhow::Result;
use clap::ValueEnum;
use rusqlite::types::ValueRef;
use rusqlite::{Connection, ToSql};
use serde_json::{json, Map, Value};
use std::io::IsTerminal;

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Format {
    /// Table in a terminal, JSON when piped (e.g. when an agent runs it)
    Auto,
    Table,
    Json,
    Csv,
}

impl Format {
    pub fn resolve(self) -> Format {
        match self {
            Format::Auto if std::io::stdout().is_terminal() => Format::Table,
            Format::Auto => Format::Json,
            f => f,
        }
    }
}

pub struct Table {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<Value>>,
    pub truncated: bool,
}

/// Run SQL with named parameters (only those the statement uses are bound).
pub fn run_sql(conn: &Connection, sql: &str, params: &[(&str, &dyn ToSql)], limit: usize) -> Result<Table> {
    let mut stmt = conn.prepare(sql)?;
    for (name, value) in params {
        if let Some(i) = stmt.parameter_index(name)? {
            stmt.raw_bind_parameter(i, value)?;
        }
    }
    let columns: Vec<String> = stmt.column_names().map(|s| s.to_string()).collect();
    let mut rows = Vec::new();
    let mut truncated = false;
    let mut raw = stmt.raw_query();
    while let Some(row) = raw.next()? {
        if rows.len() >= limit {
            truncated = true;
            break;
        }
        let vals = (0..columns.len())
            .map(|i| {
                Ok(match row.get_ref(i)? {
                    ValueRef::Null => Value::Null,
                    ValueRef::Integer(n) => json!(n),
                    ValueRef::Real(f) => json!((f * 1000.0).round() / 1000.0),
                    ValueRef::Text(t) => json!(String::from_utf8_lossy(t)),
                    ValueRef::Blob(b) => json!(format!("<{} bytes>", b.len())),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        rows.push(vals);
    }
    Ok(Table { columns, rows, truncated })
}

impl Table {
    pub fn to_json(&self) -> Value {
        Value::Array(
            self.rows
                .iter()
                .map(|r| {
                    let mut m = Map::new();
                    for (c, v) in self.columns.iter().zip(r) {
                        m.insert(c.clone(), v.clone());
                    }
                    Value::Object(m)
                })
                .collect(),
        )
    }

    pub fn print(&self, format: Format) {
        match format.resolve() {
            Format::Json => {
                let out = if self.truncated {
                    json!({ "rows": self.to_json(), "truncated": true,
                            "note": "more rows exist; raise --limit or aggregate in SQL" })
                } else {
                    self.to_json()
                };
                println!("{}", serde_json::to_string_pretty(&out).unwrap());
            }
            Format::Csv => {
                println!("{}", self.columns.iter().map(|c| csv_cell(c)).collect::<Vec<_>>().join(","));
                for r in &self.rows {
                    println!("{}", r.iter().map(|v| csv_cell(&plain(v))).collect::<Vec<_>>().join(","));
                }
            }
            _ => self.print_text(),
        }
    }

    fn print_text(&self) {
        if self.rows.is_empty() {
            println!("(no rows)");
            return;
        }
        const MAX: usize = 48;
        let cells: Vec<Vec<String>> = self
            .rows
            .iter()
            .map(|r| r.iter().map(|v| clip(&plain(v), MAX)).collect())
            .collect();
        let widths: Vec<usize> = (0..self.columns.len())
            .map(|i| {
                cells.iter().map(|r| r[i].chars().count()).chain([self.columns[i].len()]).max().unwrap_or(0)
            })
            .collect();
        let line = |vals: Vec<&str>| {
            vals.iter()
                .zip(&widths)
                .map(|(v, w)| format!("{v:<w$}"))
                .collect::<Vec<_>>()
                .join("  ")
                .trim_end()
                .to_string()
        };
        println!("{}", line(self.columns.iter().map(String::as_str).collect()));
        println!("{}", line(widths.iter().map(|w| "─".repeat(*w)).collect::<Vec<_>>().iter().map(String::as_str).collect()));
        for r in &cells {
            println!("{}", line(r.iter().map(String::as_str).collect()));
        }
        if self.truncated {
            println!("… more rows (raise --limit)");
        }
    }
}

fn plain(v: &Value) -> String {
    match v {
        Value::Null => String::new(),
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

fn clip(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(max - 1).collect::<String>())
    }
}

fn csv_cell(s: &str) -> String {
    if s.contains([',', '"', '\n']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}
