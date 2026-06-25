import type { Config, Connection } from "@tidbcloud/serverless";

const statements = [
  `CREATE TABLE IF NOT EXISTS users (
    id VARCHAR(36) PRIMARY KEY,
    role VARCHAR(32) NOT NULL,
    name VARCHAR(160) NOT NULL,
    email VARCHAR(320) NOT NULL,
    phone VARCHAR(32),
    password_hash VARCHAR(255) NOT NULL,
    status VARCHAR(32) NOT NULL,
    registration_note TEXT,
    email_notifications_enabled INT NOT NULL DEFAULT 1,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY users_email_unique (email)
  )`,
  `ALTER TABLE users ADD COLUMN registration_note TEXT`,
  `ALTER TABLE users ADD COLUMN email_notifications_enabled INT NOT NULL DEFAULT 1`,
  `CREATE TABLE IF NOT EXISTS sessions (
    id VARCHAR(36) PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL,
    token_hash VARCHAR(64) NOT NULL,
    user_agent VARCHAR(512),
    ip_prefix VARCHAR(64),
    expires_at TIMESTAMP NOT NULL,
    revoked_at TIMESTAMP NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY sessions_token_hash_unique (token_hash),
    KEY sessions_user_id_idx (user_id),
    CONSTRAINT sessions_user_id_fk FOREIGN KEY (user_id) REFERENCES users(id)
  )`,
  `CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id VARCHAR(36) PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL,
    token_hash VARCHAR(64) NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    used_at TIMESTAMP NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY password_reset_tokens_hash_unique (token_hash),
    KEY password_reset_tokens_user_id_idx (user_id),
    CONSTRAINT password_reset_tokens_user_id_fk FOREIGN KEY (user_id) REFERENCES users(id)
  )`,
  `CREATE TABLE IF NOT EXISTS auth_rate_limits (
    id VARCHAR(36) PRIMARY KEY,
    scope VARCHAR(32) NOT NULL,
    identifier_hash VARCHAR(64) NOT NULL,
    attempts INT NOT NULL DEFAULT 0,
    locked_until TIMESTAMP NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY auth_rate_limits_scope_identifier_unique (scope, identifier_hash),
    KEY auth_rate_limits_locked_until_idx (locked_until)
  )`,
  `CREATE TABLE IF NOT EXISTS audit_logs (
    id VARCHAR(36) PRIMARY KEY,
    actor_id VARCHAR(36),
    action VARCHAR(96) NOT NULL,
    target_type VARCHAR(64) NOT NULL,
    target_id VARCHAR(64),
    metadata JSON,
    ip_prefix VARCHAR(64),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    KEY audit_logs_actor_id_idx (actor_id),
    KEY audit_logs_action_idx (action),
    KEY audit_logs_target_idx (target_type, target_id),
    KEY audit_logs_created_at_idx (created_at)
  )`,
  `ALTER TABLE audit_logs ADD KEY audit_logs_action_idx (action)`,
  `ALTER TABLE audit_logs ADD KEY audit_logs_target_idx (target_type, target_id)`,
  `ALTER TABLE audit_logs ADD KEY audit_logs_created_at_idx (created_at)`,
  `CREATE TABLE IF NOT EXISTS settings (
    setting_key VARCHAR(96) PRIMARY KEY,
    value_json JSON NOT NULL,
    updated_by VARCHAR(36),
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
  )`,
  `CREATE TABLE IF NOT EXISTS conversations (
    id VARCHAR(36) PRIMARY KEY,
    customer_id VARCHAR(36) NOT NULL,
    assigned_agent_id VARCHAR(36),
    status VARCHAR(32) NOT NULL,
    last_message_at TIMESTAMP NULL,
    last_customer_message_at TIMESTAMP NULL,
    last_agent_message_at TIMESTAMP NULL,
    last_message_preview VARCHAR(180),
    customer_unread_count INT NOT NULL DEFAULT 0,
    agent_unread_count INT NOT NULL DEFAULT 0,
    closed_at TIMESTAMP NULL,
    closed_by VARCHAR(36),
    closing_note TEXT,
    registration_note TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY conversations_customer_id_unique (customer_id),
    KEY conversations_assigned_agent_id_idx (assigned_agent_id),
    KEY conversations_status_last_message_idx (status, last_message_at),
    KEY conversations_waiting_idx (status, last_customer_message_at, last_agent_message_at),
    CONSTRAINT conversations_customer_id_fk FOREIGN KEY (customer_id) REFERENCES users(id),
    CONSTRAINT conversations_assigned_agent_id_fk FOREIGN KEY (assigned_agent_id) REFERENCES users(id),
    CONSTRAINT conversations_closed_by_fk FOREIGN KEY (closed_by) REFERENCES users(id)
  )`,
  `ALTER TABLE conversations ADD COLUMN last_message_preview VARCHAR(180)`,
  `ALTER TABLE conversations ADD COLUMN last_customer_message_at TIMESTAMP NULL`,
  `ALTER TABLE conversations ADD COLUMN last_agent_message_at TIMESTAMP NULL`,
  `ALTER TABLE conversations ADD COLUMN customer_unread_count INT NOT NULL DEFAULT 0`,
  `ALTER TABLE conversations ADD COLUMN agent_unread_count INT NOT NULL DEFAULT 0`,
  `ALTER TABLE conversations ADD COLUMN closed_at TIMESTAMP NULL`,
  `ALTER TABLE conversations ADD COLUMN closed_by VARCHAR(36)`,
  `ALTER TABLE conversations ADD COLUMN closing_note TEXT`,
  `ALTER TABLE conversations ADD COLUMN registration_note TEXT`,
  `ALTER TABLE conversations ADD KEY conversations_waiting_idx (status, last_customer_message_at, last_agent_message_at)`,
  `CREATE TABLE IF NOT EXISTS messages (
    id VARCHAR(36) PRIMARY KEY,
    conversation_id VARCHAR(36) NOT NULL,
    sender_id VARCHAR(36) NOT NULL,
    body TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    KEY messages_conversation_created_idx (conversation_id, created_at),
    KEY messages_sender_id_idx (sender_id),
    CONSTRAINT messages_conversation_id_fk FOREIGN KEY (conversation_id) REFERENCES conversations(id),
    CONSTRAINT messages_sender_id_fk FOREIGN KEY (sender_id) REFERENCES users(id)
  )`,
  `UPDATE conversations c
    SET last_message_preview = (
      SELECT LEFT(m.body, 180)
      FROM messages m
      WHERE m.conversation_id = c.id
      ORDER BY m.created_at DESC
      LIMIT 1
    )
    WHERE last_message_preview IS NULL
      AND EXISTS (
        SELECT 1
        FROM messages m
        WHERE m.conversation_id = c.id
      )`,
  `UPDATE conversations c
    SET last_customer_message_at = (
      SELECT MAX(m.created_at)
      FROM messages m
      INNER JOIN users u ON u.id = m.sender_id
      WHERE m.conversation_id = c.id
        AND u.role = 'customer'
    )
    WHERE last_customer_message_at IS NULL
      AND EXISTS (
        SELECT 1
        FROM messages m
        INNER JOIN users u ON u.id = m.sender_id
        WHERE m.conversation_id = c.id
          AND u.role = 'customer'
      )`,
  `UPDATE conversations c
    SET last_agent_message_at = (
      SELECT MAX(m.created_at)
      FROM messages m
      INNER JOIN users u ON u.id = m.sender_id
      WHERE m.conversation_id = c.id
        AND u.role <> 'customer'
    )
    WHERE last_agent_message_at IS NULL
      AND EXISTS (
        SELECT 1
        FROM messages m
        INNER JOIN users u ON u.id = m.sender_id
        WHERE m.conversation_id = c.id
          AND u.role <> 'customer'
      )`,
  `CREATE TABLE IF NOT EXISTS notification_jobs (
    id VARCHAR(36) PRIMARY KEY,
    recipient_id VARCHAR(36) NOT NULL,
    channel VARCHAR(32) NOT NULL,
    type VARCHAR(96) NOT NULL,
    status VARCHAR(32) NOT NULL,
    dedupe_key VARCHAR(255),
    payload JSON NOT NULL,
    attempts INT NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    sent_at TIMESTAMP NULL,
    provider VARCHAR(32),
    last_error TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY notification_jobs_dedupe_key_unique (dedupe_key),
    KEY notification_jobs_status_next_attempt_idx (status, next_attempt_at),
    KEY notification_jobs_recipient_id_idx (recipient_id),
    CONSTRAINT notification_jobs_recipient_id_fk FOREIGN KEY (recipient_id) REFERENCES users(id)
  )`,
  `ALTER TABLE notification_jobs ADD COLUMN provider VARCHAR(32)`
];

export async function runMigrations(connection: Connection<Config>) {
  for (const statement of statements) {
    try {
      await connection.execute(statement);
    } catch (error) {
      if (!isIgnorableMigrationError(error)) {
        throw error;
      }
    }
  }
}

function isIgnorableMigrationError(error: unknown) {
  if (!(error instanceof Error)) return false;
  return /Duplicate column|1060|Duplicate key name|1061/i.test(error.message);
}
