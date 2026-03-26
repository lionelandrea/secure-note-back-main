const sqlite3 = require("sqlite3").verbose();
const db = new sqlite3.Database("./securenotes.db");

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users ( 
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT,
    password TEXT,
    role TEXT,
    login_attempts INTEGER DEFAULT 0,
    lock_until INTEGER DEFAULT NULL,
    bio TEXT DEFAULT ''
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    content TEXT NOT NULL,
    user_id INTEGER,
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);

  db.run(`ALTER TABLE users ADD COLUMN login_attempts INTEGER DEFAULT 0`, (err) => {});
  db.run(`ALTER TABLE users ADD COLUMN lock_until INTEGER DEFAULT NULL`, (err) => {});
  db.run(`ALTER TABLE users ADD COLUMN bio TEXT DEFAULT ''`, () => {});


  console.log("Base de données SQLite initialisée avec succès.");
});

module.exports = db;