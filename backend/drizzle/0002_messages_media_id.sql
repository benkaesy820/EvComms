-- Migration: add media_id to messages for reliable forward-FK media join
-- The old design used media.message_id (reverse join) which is unreliable with LibSQL.
-- This aligns messages with internalMessages/directMessages which use a forward FK.

ALTER TABLE `messages` ADD COLUMN `media_id` text REFERENCES `media`(`id`) ON DELETE SET NULL;
--> statement-breakpoint

-- Backfill: set media_id on existing messages from media.message_id
UPDATE `messages` SET `media_id` = (
  SELECT `id` FROM `media` WHERE `media`.`message_id` = `messages`.`id` LIMIT 1
) WHERE `media_id` IS NULL;
--> statement-breakpoint

CREATE INDEX `idx_messages_media_id` ON `messages` (`media_id`) WHERE `media_id` IS NOT NULL;
