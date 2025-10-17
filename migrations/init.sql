-- users
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  login TEXT UNIQUE,
  pass TEXT,
  name TEXT,
  phone TEXT,
  isAdmin INTEGER DEFAULT 0,
  blocked INTEGER DEFAULT 0,
  created_at INTEGER DEFAULT (strftime('%s','now'))
);

-- listings
CREATE TABLE IF NOT EXISTS listings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT,
  category TEXT,
  price REAL,
  desc TEXT,
  img TEXT,
  ownerId INTEGER,
  approved INTEGER DEFAULT 0,
  fromStore INTEGER DEFAULT 0,
  phone TEXT,
  created_at INTEGER DEFAULT (strftime('%s','now')),
  FOREIGN KEY(ownerId) REFERENCES users(id)
);

-- reports
CREATE TABLE IF NOT EXISTS reports (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  type TEXT,
  text TEXT,
  fromId INTEGER,
  targetListingId INTEGER,
  targetUserId INTEGER,
  created_at INTEGER DEFAULT (strftime('%s','now'))
);

-- chats
CREATE TABLE IF NOT EXISTS chats (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  listingId INTEGER,
  buyerId INTEGER,
  sellerId INTEGER,
  created_at INTEGER DEFAULT (strftime('%s','now')),
  UNIQUE(listingId,buyerId,sellerId)
);

-- messages
CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  chatId INTEGER,
  fromId INTEGER,
  fromName TEXT,
  text TEXT,
  created_at INTEGER DEFAULT (strftime('%s','now')),
  FOREIGN KEY(chatId) REFERENCES chats(id)
);
