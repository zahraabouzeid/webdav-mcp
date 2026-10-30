//! One SQLite file, brought up to date at start by the numbered scripts in
//! `migrations/`.

use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use rusqlite::Connection;

use crate::error::{Result, WebdavError};

const FILE: &str = "webdav-mcp.db";

/// In the order they are applied. A released script is never changed again;
/// a change to the tables is a new script at the end.
const MIGRATIONS: &[&str] = &[include_str!("../../migrations/0001_oauth.sql")];

pub struct Database {
    connection: Mutex<Connection>,
}

pub fn sql(e: rusqlite::Error) -> WebdavError {
    WebdavError::new(format!("database error: {e}"))
}

impl Database {
    pub fn open(folder: &Path) -> Result<Arc<Self>> {
        let file = folder.join(FILE);
        let cannot = |e: &dyn std::fmt::Display| {
            WebdavError::new(format!("cannot open {}: {e}", file.display()))
        };
        fs::create_dir_all(folder).map_err(|e| cannot(&e))?;
        let connection = Connection::open(&file).map_err(|e| cannot(&e))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&file, fs::Permissions::from_mode(0o600))
                .map_err(|e| cannot(&e))?;
        }
        Self::prepare(connection, MIGRATIONS)
    }

    fn prepare(mut connection: Connection, migrations: &[&str]) -> Result<Arc<Self>> {
        connection
            .busy_timeout(Duration::from_secs(5))
            .map_err(sql)?;
        // Off by default in SQLite; ending a connection relies on it.
        connection
            .pragma_update(None, "foreign_keys", true)
            .map_err(sql)?;
        migrate(&mut connection, migrations)?;
        Ok(Arc::new(Self {
            connection: Mutex::new(connection),
        }))
    }

    /// Runs `work` on the database, one caller at a time.
    pub fn with<T>(&self, work: impl FnOnce(&mut Connection) -> Result<T>) -> Result<T> {
        let mut connection = self
            .connection
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        work(&mut connection)
    }
}

/// Applies the scripts the database has not seen yet. Each runs in a
/// transaction of its own, so a failing one leaves the database as it was.
fn migrate(connection: &mut Connection, migrations: &[&str]) -> Result<()> {
    let applied: usize = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(sql)?;
    if applied > migrations.len() {
        return Err(WebdavError::new(
            "the database was made by a newer version of this server",
        ));
    }
    for (index, script) in migrations.iter().enumerate().skip(applied) {
        let transaction = connection.transaction().map_err(sql)?;
        transaction.execute_batch(script).map_err(sql)?;
        transaction
            .pragma_update(None, "user_version", index + 1)
            .map_err(sql)?;
        transaction.commit().map_err(sql)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn version(connection: &Connection) -> usize {
        connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .expect("version")
    }

    #[test]
    fn scripts_are_applied_once_and_in_order() {
        let mut connection = Connection::open_in_memory().expect("database");
        let first = ["CREATE TABLE a (x INTEGER);"];
        migrate(&mut connection, &first).expect("first");
        assert_eq!(version(&connection), 1);

        let both = [first[0], "CREATE TABLE b (z TEXT);"];
        migrate(&mut connection, &both).expect("second");
        migrate(&mut connection, &both).expect("again");
        assert_eq!(version(&connection), 2);
    }

    #[test]
    fn a_failing_script_leaves_the_database_as_it_was() {
        let mut connection = Connection::open_in_memory().expect("database");
        let broken = [
            "CREATE TABLE a (x INTEGER);",
            "CREATE TABLE b (z TEXT); NOT SQL;",
        ];
        assert!(migrate(&mut connection, &broken).is_err());
        assert_eq!(version(&connection), 1);
    }

    #[test]
    fn a_database_from_a_newer_version_is_not_touched() {
        let mut connection = Connection::open_in_memory().expect("database");
        let newer = ["CREATE TABLE a (x INTEGER);", "CREATE TABLE b (z TEXT);"];
        migrate(&mut connection, &newer).expect("newer");
        let error = migrate(&mut connection, &newer[..1]).expect_err("older");
        assert!(error.to_string().contains("newer version"));
    }

    #[test]
    fn the_real_scripts_build_the_tables() {
        let connection = Connection::open_in_memory().expect("database");
        Database::prepare(connection, MIGRATIONS).expect("prepare");
    }
}
