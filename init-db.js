// Creates tables from schema.sql and (optionally) seeds demo data.
// Usage: npm run db:init            -> schema + demo data
//        SEED=0 npm run db:init     -> schema only
const Database = require('better-sqlite3'), bcrypt = require('bcryptjs'), fs = require('fs'), path = require('path');
const db = new Database(process.env.DB || path.join(__dirname, '..', 'lostfound.db'));
db.pragma('foreign_keys = ON');
db.exec(fs.readFileSync(path.join(__dirname, '..', 'schema.sql'), 'utf8'));
console.log('Schema ready');

if (process.env.SEED !== '0' && !db.prepare('SELECT 1 FROM users LIMIT 1').get()) {
  const hash = bcrypt.hashSync('Demo@1234', 10), hashA = bcrypt.hashSync('LF000', 10);
  const u = db.prepare('INSERT INTO users(name,reg_no,email,phone,password_hash,verified) VALUES(?,?,?,?,?,1)');
  const a = u.run('Afraz Kumar', '25BCE0000', 'afraz.kumar2025@vitstudent.ac.in', '9876543210', hashA).lastInsertRowid;
  const b = u.run('Meera Nair', '22BIT1002', 'meera.nair2022@vitstudent.ac.in', '9123456780', hash).lastInsertRowid;
  const i = db.prepare('INSERT INTO items(user_id,type,title,description,category,venue,challenge) VALUES(?,?,?,?,?,?,?)');
  i.run(a, 'found', 'VIT ID Card near SJT lift', 'Found a student ID card lying near the SJT ground-floor lift lobby.', 'ID Cards', 'SJT', 'What name and branch are printed on the ID card?');
  i.run(a, 'found', 'Casio fx-991EX calculator', 'Black scientific calculator left on a desk in the Central Library.', 'Calculators', 'Central Library', 'What name or sticker is on the back cover?');
  i.run(b, 'lost', 'Room key with blue tag', 'Lost my room key with a blue tag somewhere between MH-K and the Gazebo.', 'Room Keys', 'MH-K', 'What room number is written on the tag?');
  i.run(b, 'found', 'Black wallet at Food Mall', 'Small black leather wallet found near the Food Mall billing counter.', 'Wallets', 'Food Mall', 'Name one card inside and the last 4 digits of any card.');
  console.log('Demo data seeded. Login: 25BCE0000 / LF000  or  22BIT1002 / Demo@1234');
}
