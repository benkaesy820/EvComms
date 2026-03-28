const Database = require('better-sqlite3');
const db = new Database('./data.db');

try {
  let rows = db.prepare('SELECT * FROM internal_message_reads').all();
  console.log('Reads before:', rows);

  db.prepare(`
    INSERT INTO internal_message_reads (id, user_id, last_read_at, unread_count, updated_at)
    SELECT
      lower(hex(randomblob(10))),
      u.id,
      unixepoch(),
      COALESCE((SELECT unread_count FROM internal_message_reads WHERE user_id = u.id), 0) + 1,
      unixepoch()
    FROM users u
    WHERE u.role IN ('ADMIN', 'SUPER_ADMIN')
  `).run();

  rows = db.prepare('SELECT * FROM internal_message_reads').all();
  console.log('Reads after 1st insert:', rows);

  db.prepare(`
    INSERT INTO internal_message_reads (id, user_id, last_read_at, unread_count, updated_at)
    SELECT
      lower(hex(randomblob(10))),
      u.id,
      unixepoch(),
      COALESCE((SELECT unread_count FROM internal_message_reads WHERE user_id = u.id), 0) + 1,
      unixepoch()
    FROM users u
    WHERE u.role IN ('ADMIN', 'SUPER_ADMIN')
    ON CONFLICT(user_id) DO UPDATE SET
      unread_count = internal_message_reads.unread_count + 1,
      updated_at = unixepoch()
  `).run();

  rows = db.prepare('SELECT * FROM internal_message_reads').all();
  console.log('Reads after 2nd insert with conflict:', rows);
} catch (err) {
  console.error(err);
}
