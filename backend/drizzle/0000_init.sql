-- ============================================================
-- Fresh initial schema — single source of truth
-- Run: npm run db:push   (drizzle-kit push)
-- ============================================================

CREATE TABLE IF NOT EXISTS `users` (
	`id` text PRIMARY KEY NOT NULL,
	`email` text NOT NULL,
	`password_hash` text NOT NULL,
	`name` text NOT NULL,
	`phone` text,
	`role` text DEFAULT 'USER' NOT NULL,
	`status` text DEFAULT 'PENDING' NOT NULL,
	`media_permission` integer DEFAULT false NOT NULL,
	`email_notify_on_message` integer DEFAULT true NOT NULL,
	`subsidiary_ids` text,
	`rejection_reason` text,
	`created_at` integer DEFAULT (unixepoch()) NOT NULL,
	`updated_at` integer DEFAULT (unixepoch()) NOT NULL,
	`last_seen_at` integer
);
--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS `users_email_unique` ON `users` (`email`);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `idx_users_status_created` ON `users` (`status`,`created_at`);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `idx_users_role_created` ON `users` (`role`,`created_at`);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `idx_users_name` ON `users` (`name`);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `idx_users_last_seen` ON `users` (`last_seen_at`);

--> statement-breakpoint
CREATE TABLE IF NOT EXISTS `sessions` (
	`id` text PRIMARY KEY NOT NULL,
	`user_id` text NOT NULL,
	`device_info` text,
	`ip_address` text,
	`priority` integer DEFAULT 0 NOT NULL,
	`created_at` integer DEFAULT (unixepoch()) NOT NULL,
	`expires_at` integer NOT NULL,
	`last_active_at` integer DEFAULT (unixepoch()) NOT NULL,
	`revoked_at` integer,
	FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `idx_sessions_user_active` ON `sessions` (`user_id`,`revoked_at`,`expires_at`);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `idx_sessions_priority` ON `sessions` (`user_id`,`priority`);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `idx_sessions_expires` ON `sessions` (`expires_at`);

--> statement-breakpoint
CREATE TABLE IF NOT EXISTS `refresh_tokens` (
	`id` text PRIMARY KEY NOT NULL,
	`user_id` text NOT NULL,
	`session_id` text NOT NULL,
	`token_hash` text NOT NULL,
	`device_info` text,
	`ip_address` text,
	`last_used_at` integer DEFAULT (unixepoch()) NOT NULL,
	`expires_at` integer NOT NULL,
	`revoked_at` integer,
	`created_at` integer DEFAULT (unixepoch()) NOT NULL,
	FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`session_id`) REFERENCES `sessions`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS `refresh_tokens_token_hash_unique` ON `refresh_tokens` (`token_hash`);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `idx_refresh_session` ON `refresh_tokens` (`session_id`);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `idx_refresh_active` ON `refresh_tokens` (`user_id`,`revoked_at`,`expires_at`);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `idx_refresh_expires` ON `refresh_tokens` (`expires_at`);

--> statement-breakpoint
CREATE TABLE IF NOT EXISTS `password_reset_tokens` (
	`id` text PRIMARY KEY NOT NULL,
	`user_id` text NOT NULL,
	`token_hash` text NOT NULL,
	`ip_address` text,
	`expires_at` integer NOT NULL,
	`used_at` integer,
	`created_at` integer DEFAULT (unixepoch()) NOT NULL,
	FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS `password_reset_tokens_token_hash_unique` ON `password_reset_tokens` (`token_hash`);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `idx_password_reset_user_expires` ON `password_reset_tokens` (`user_id`,`expires_at`);

--> statement-breakpoint
CREATE TABLE IF NOT EXISTS `media` (
	`id` text PRIMARY KEY NOT NULL,
	`uploaded_by` text NOT NULL,
	`type` text NOT NULL,
	`mime_type` text NOT NULL,
	`size` integer NOT NULL,
	`filename` text NOT NULL,
	`r2_key` text NOT NULL,
	`cdn_url` text,
	`hash` text,
	`metadata` text,
	`status` text DEFAULT 'pending' NOT NULL,
	`uploaded_at` integer DEFAULT (unixepoch()) NOT NULL,
	`confirmed_at` integer,
	FOREIGN KEY (`uploaded_by`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `idx_media_uploaded_by` ON `media` (`uploaded_by`);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `idx_media_pending_upload` ON `media` (`status`,`uploaded_at`) WHERE "media"."status" = 'pending';
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `idx_media_hash` ON `media` (`hash`) WHERE "media"."hash" IS NOT NULL;

--> statement-breakpoint
CREATE TABLE IF NOT EXISTS `registration_reports` (
	`id` text PRIMARY KEY NOT NULL,
	`user_id` text NOT NULL,
	`subject` text NOT NULL,
	`description` text NOT NULL,
	`media_id` text,
	`status` text DEFAULT 'PENDING' NOT NULL,
	`reviewed_at` integer,
	`reviewed_by` text,
	`created_at` integer DEFAULT (unixepoch()) NOT NULL,
	`updated_at` integer DEFAULT (unixepoch()) NOT NULL,
	FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`media_id`) REFERENCES `media`(`id`) ON UPDATE no action ON DELETE set null,
	FOREIGN KEY (`reviewed_by`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE set null
);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `idx_reg_reports_status_created` ON `registration_reports` (`status`,`created_at`);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `idx_reg_reports_user` ON `registration_reports` (`user_id`);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `idx_reg_reports_reviewed_by` ON `registration_reports` (`reviewed_by`);

--> statement-breakpoint
CREATE TABLE IF NOT EXISTS `conversations` (
	`id` text PRIMARY KEY NOT NULL,
	`user_id` text NOT NULL,
	`assigned_admin_id` text,
	`created_at` integer DEFAULT (unixepoch()) NOT NULL,
	`last_message_at` integer,
	`unread_count` integer DEFAULT 0 NOT NULL,
	`admin_unread_count` integer DEFAULT 0 NOT NULL,
	`deleted_at` integer,
	`archived_at` integer,
	`archived_by` text,
	`updated_at` integer DEFAULT (unixepoch()) NOT NULL,
	`subsidiary_id` text,
	`registration_report_id` text,
	`waiting_since` integer,
	`last_admin_reply_at` integer,
	FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`assigned_admin_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE set null,
	FOREIGN KEY (`archived_by`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE set null,
	FOREIGN KEY (`registration_report_id`) REFERENCES `registration_reports`(`id`) ON UPDATE no action ON DELETE set null
);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `idx_conversations_unread_last` ON `conversations` (`unread_count`,`last_message_at`);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `idx_conversations_admin_unread` ON `conversations` (`admin_unread_count`,`last_message_at`);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `idx_conversations_last_message` ON `conversations` (`last_message_at`);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `idx_conversations_assigned_admin` ON `conversations` (`assigned_admin_id`,`archived_at`,`last_message_at`);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `idx_conversations_user` ON `conversations` (`user_id`);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `idx_conversations_archived` ON `conversations` (`archived_at`);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `idx_conversations_archived_by` ON `conversations` (`archived_by`);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `idx_conversations_active` ON `conversations` (`deleted_at`,`archived_at`,`last_message_at`);

--> statement-breakpoint
CREATE TABLE IF NOT EXISTS `announcements` (
	`id` text PRIMARY KEY NOT NULL,
	`title` text NOT NULL,
	`content` text NOT NULL,
	`type` text DEFAULT 'INFO' NOT NULL,
	`template` text DEFAULT 'DEFAULT' NOT NULL,
	`media_id` text,
	`target_roles` text DEFAULT '["USER","ADMIN","SUPER_ADMIN"]' NOT NULL,
	`created_by` text NOT NULL,
	`upvote_count` integer DEFAULT 0 NOT NULL,
	`downvote_count` integer DEFAULT 0 NOT NULL,
	`is_active` integer DEFAULT true NOT NULL,
	`is_public` integer DEFAULT false NOT NULL,
	`created_at` integer DEFAULT (unixepoch()) NOT NULL,
	`expires_at` integer,
	FOREIGN KEY (`media_id`) REFERENCES `media`(`id`) ON UPDATE no action ON DELETE set null,
	FOREIGN KEY (`created_by`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `idx_announcements_active_created` ON `announcements` (`is_active`,`created_at`);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `idx_announcements_public_active` ON `announcements` (`is_public`,`is_active`,`created_at`);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `idx_announcements_created_by` ON `announcements` (`created_by`);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `idx_announcements_expires` ON `announcements` (`expires_at`) WHERE "announcements"."expires_at" IS NOT NULL;

--> statement-breakpoint
CREATE TABLE IF NOT EXISTS `messages` (
	`id` text PRIMARY KEY NOT NULL,
	`conversation_id` text NOT NULL,
	`sender_id` text NOT NULL,
	`type` text DEFAULT 'TEXT' NOT NULL,
	`content` text,
	`media_id` text,
	`status` text DEFAULT 'SENT' NOT NULL,
	`read_at` integer,
	`reply_to_id` text,
	`announcement_id` text,
	`deleted_at` integer,
	`deleted_by` text,
	`hidden_for` text DEFAULT '[]' NOT NULL,
	`created_at` integer DEFAULT (unixepoch()) NOT NULL,
	`updated_at` integer DEFAULT (unixepoch()) NOT NULL,
	FOREIGN KEY (`conversation_id`) REFERENCES `conversations`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`sender_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`media_id`) REFERENCES `media`(`id`) ON UPDATE no action ON DELETE set null,
	FOREIGN KEY (`reply_to_id`) REFERENCES `messages`(`id`) ON UPDATE no action ON DELETE set null,
	FOREIGN KEY (`announcement_id`) REFERENCES `announcements`(`id`) ON UPDATE no action ON DELETE set null,
	FOREIGN KEY (`deleted_by`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE set null
);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `idx_messages_conv_created` ON `messages` (`conversation_id`,`created_at`) WHERE "messages"."deleted_at" IS NULL;
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `idx_messages_conv_unread` ON `messages` (`conversation_id`,`status`,`deleted_at`) WHERE "messages"."deleted_at" IS NULL;
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `idx_messages_sender_created` ON `messages` (`sender_id`,`created_at`);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `idx_messages_reply_to` ON `messages` (`reply_to_id`) WHERE "messages"."reply_to_id" IS NOT NULL;
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `idx_messages_media_id` ON `messages` (`media_id`) WHERE "messages"."media_id" IS NOT NULL;

--> statement-breakpoint
CREATE TABLE IF NOT EXISTS `message_reactions` (
	`id` text PRIMARY KEY NOT NULL,
	`message_id` text NOT NULL,
	`user_id` text NOT NULL,
	`emoji` text NOT NULL,
	`created_at` integer DEFAULT (unixepoch()) NOT NULL,
	FOREIGN KEY (`message_id`) REFERENCES `messages`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `idx_message_reactions_message` ON `message_reactions` (`message_id`);
--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS `uq_message_reaction` ON `message_reactions` (`message_id`,`user_id`,`emoji`);

--> statement-breakpoint
CREATE TABLE IF NOT EXISTS `announcement_comments` (
	`id` text PRIMARY KEY NOT NULL,
	`announcement_id` text NOT NULL,
	`user_id` text NOT NULL,
	`content` text NOT NULL,
	`deleted_at` integer,
	`created_at` integer DEFAULT (unixepoch()) NOT NULL,
	FOREIGN KEY (`announcement_id`) REFERENCES `announcements`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `idx_ann_comments_created` ON `announcement_comments` (`announcement_id`,`created_at`);

--> statement-breakpoint
CREATE TABLE IF NOT EXISTS `announcement_reactions` (
	`id` text PRIMARY KEY NOT NULL,
	`announcement_id` text NOT NULL,
	`user_id` text NOT NULL,
	`emoji` text NOT NULL,
	`created_at` integer DEFAULT (unixepoch()) NOT NULL,
	FOREIGN KEY (`announcement_id`) REFERENCES `announcements`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS `uq_announcement_reaction` ON `announcement_reactions` (`announcement_id`,`user_id`,`emoji`);

--> statement-breakpoint
CREATE TABLE IF NOT EXISTS `announcement_votes` (
	`id` text PRIMARY KEY NOT NULL,
	`announcement_id` text NOT NULL,
	`user_id` text NOT NULL,
	`vote` integer NOT NULL,
	`created_at` integer DEFAULT (unixepoch()) NOT NULL,
	FOREIGN KEY (`announcement_id`) REFERENCES `announcements`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS `uq_announcement_vote` ON `announcement_votes` (`announcement_id`,`user_id`);

--> statement-breakpoint
CREATE TABLE IF NOT EXISTS `audit_logs` (
	`id` text PRIMARY KEY NOT NULL,
	`user_id` text NOT NULL,
	`ip_address` text,
	`action` text NOT NULL,
	`entity_type` text NOT NULL,
	`entity_id` text NOT NULL,
	`details` text,
	`created_at` integer DEFAULT (unixepoch()) NOT NULL,
	FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `idx_audit_entity_created` ON `audit_logs` (`entity_type`,`entity_id`,`created_at`);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `idx_audit_user_created` ON `audit_logs` (`user_id`,`created_at`);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `idx_audit_action_created` ON `audit_logs` (`action`,`created_at`);

--> statement-breakpoint
CREATE TABLE IF NOT EXISTS `user_status_history` (
	`id` text PRIMARY KEY NOT NULL,
	`user_id` text NOT NULL,
	`previous_status` text NOT NULL,
	`new_status` text NOT NULL,
	`changed_by` text NOT NULL,
	`reason` text,
	`created_at` integer DEFAULT (unixepoch()) NOT NULL,
	FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`changed_by`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `idx_status_history_user_created` ON `user_status_history` (`user_id`,`created_at`);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `idx_status_history_changed_by` ON `user_status_history` (`changed_by`);

--> statement-breakpoint
CREATE TABLE IF NOT EXISTS `user_reports` (
	`id` text PRIMARY KEY NOT NULL,
	`user_id` text NOT NULL,
	`subject` text NOT NULL,
	`description` text NOT NULL,
	`media_id` text,
	`status` text DEFAULT 'PENDING' NOT NULL,
	`resolved_at` integer,
	`resolved_by` text,
	`created_at` integer DEFAULT (unixepoch()) NOT NULL,
	`updated_at` integer DEFAULT (unixepoch()) NOT NULL,
	FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`media_id`) REFERENCES `media`(`id`) ON UPDATE no action ON DELETE set null,
	FOREIGN KEY (`resolved_by`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE set null
);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `idx_user_reports_status_created` ON `user_reports` (`status`,`created_at`);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `idx_user_reports_user` ON `user_reports` (`user_id`);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `idx_user_reports_resolver` ON `user_reports` (`resolved_by`);

--> statement-breakpoint
CREATE TABLE IF NOT EXISTS `internal_messages` (
	`id` text PRIMARY KEY NOT NULL,
	`sender_id` text NOT NULL,
	`type` text DEFAULT 'TEXT' NOT NULL,
	`content` text,
	`media_id` text,
	`reply_to_id` text,
	`deleted_at` integer,
	`hidden_for` text,
	`created_at` integer DEFAULT (unixepoch()) NOT NULL,
	FOREIGN KEY (`sender_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`media_id`) REFERENCES `media`(`id`) ON UPDATE no action ON DELETE set null,
	FOREIGN KEY (`reply_to_id`) REFERENCES `internal_messages`(`id`) ON UPDATE no action ON DELETE set null
);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `idx_internal_messages_created` ON `internal_messages` (`created_at`);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `idx_internal_messages_reply_to` ON `internal_messages` (`reply_to_id`) WHERE "internal_messages"."reply_to_id" IS NOT NULL;

--> statement-breakpoint
CREATE TABLE IF NOT EXISTS `internal_message_reactions` (
	`id` text PRIMARY KEY NOT NULL,
	`message_id` text NOT NULL,
	`user_id` text NOT NULL,
	`emoji` text NOT NULL,
	`created_at` integer DEFAULT (unixepoch()) NOT NULL,
	FOREIGN KEY (`message_id`) REFERENCES `internal_messages`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `idx_internal_reactions_message` ON `internal_message_reactions` (`message_id`);
--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS `uq_internal_reaction` ON `internal_message_reactions` (`message_id`,`user_id`,`emoji`);

--> statement-breakpoint
CREATE TABLE IF NOT EXISTS `internal_message_reads` (
	`id` text PRIMARY KEY NOT NULL,
	`user_id` text NOT NULL,
	`last_read_message_id` text,
	`last_read_at` integer DEFAULT (unixepoch()) NOT NULL,
	`unread_count` integer DEFAULT 0 NOT NULL,
	`updated_at` integer DEFAULT (unixepoch()) NOT NULL,
	FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`last_read_message_id`) REFERENCES `internal_messages`(`id`) ON UPDATE no action ON DELETE set null
);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `idx_internal_reads_unread` ON `internal_message_reads` (`unread_count`) WHERE "internal_message_reads"."unread_count" > 0;
--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS `uq_internal_reads_user` ON `internal_message_reads` (`user_id`);

--> statement-breakpoint
CREATE TABLE IF NOT EXISTS `direct_messages` (
	`id` text PRIMARY KEY NOT NULL,
	`sender_id` text NOT NULL,
	`recipient_id` text NOT NULL,
	`type` text DEFAULT 'TEXT' NOT NULL,
	`content` text,
	`media_id` text,
	`reply_to_id` text,
	`deleted_at` integer,
	`hidden_for` text,
	`created_at` integer DEFAULT (unixepoch()) NOT NULL,
	FOREIGN KEY (`sender_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`recipient_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`media_id`) REFERENCES `media`(`id`) ON UPDATE no action ON DELETE set null,
	FOREIGN KEY (`reply_to_id`) REFERENCES `direct_messages`(`id`) ON UPDATE no action ON DELETE set null
);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `idx_dm_thread_fwd` ON `direct_messages` (`sender_id`,`recipient_id`,`created_at`);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `idx_dm_thread_rev` ON `direct_messages` (`recipient_id`,`sender_id`,`created_at`);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `idx_dm_recipient_created` ON `direct_messages` (`recipient_id`,`created_at`);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `idx_dm_reply_to` ON `direct_messages` (`reply_to_id`) WHERE "direct_messages"."reply_to_id" IS NOT NULL;

--> statement-breakpoint
CREATE TABLE IF NOT EXISTS `direct_message_reactions` (
	`id` text PRIMARY KEY NOT NULL,
	`message_id` text NOT NULL,
	`user_id` text NOT NULL,
	`emoji` text NOT NULL,
	`created_at` integer DEFAULT (unixepoch()) NOT NULL,
	FOREIGN KEY (`message_id`) REFERENCES `direct_messages`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `idx_dm_reactions_message` ON `direct_message_reactions` (`message_id`);
--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS `uq_dm_reaction` ON `direct_message_reactions` (`message_id`,`user_id`,`emoji`);

--> statement-breakpoint
CREATE TABLE IF NOT EXISTS `dm_recipient_status` (
	`id` text PRIMARY KEY NOT NULL,
	`user_id` text NOT NULL,
	`partner_id` text NOT NULL,
	`last_read_at` integer DEFAULT (unixepoch()) NOT NULL,
	`unread_count` integer DEFAULT 0 NOT NULL,
	`updated_at` integer DEFAULT (unixepoch()) NOT NULL,
	FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`partner_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `idx_dm_status_user` ON `dm_recipient_status` (`user_id`);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `idx_dm_status_unread` ON `dm_recipient_status` (`user_id`,`unread_count`) WHERE "dm_recipient_status"."unread_count" > 0;
--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS `uq_dm_status` ON `dm_recipient_status` (`user_id`,`partner_id`);
