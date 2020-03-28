DROP TABLE if exists users;
DROP TABLE if exists transactions;
DROP TABLE if exists accounts;

CREATE TABLE users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL,
  secretKey TEXT
);

CREATE TABLE accounts (
id INTEGER PRIMARY KEY AUTOINCREMENT,
username TEXT UNIQUE NOT NULL,
balance TEXT NOT NULL
);

CREATE TABLE transactions (
id INTEGER PRIMARY KEY AUTOINCREMENT,
username TEXT NOT NULL,
date TEXT NOT NULL,
amount TEXT NOT NULL
);

INSERT INTO users (username, password) VALUES ('admin', 'gotTheMoney');

INSERT INTO accounts (username, balance) VALUES ('admin', '5000');