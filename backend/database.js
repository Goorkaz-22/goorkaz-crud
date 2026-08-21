const Database = require("better-sqlite3");
const path = require("path");

const dbPath = path.join(__dirname, "goorkaz.db");

const db = new Database(dbPath);

db.pragma("journal_mode = WAL");

db.exec(`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'consulta',
        active INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS records (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT NOT NULL,
        phone TEXT,
        category TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'Activo',
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        action TEXT NOT NULL,
        record_id INTEGER,
        description TEXT,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

        FOREIGN KEY(user_id)
        REFERENCES users(id)
    );
`);

console.log("✓ Base de datos Goorkaz inicializada");

module.exports = db;
