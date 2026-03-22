-- Migration: add subsidiary affinity to admins
-- subsidiary_ids stores a JSON array of subsidiary IDs the admin handles.
-- NULL means the admin handles all subsidiaries (generalist fallback).
ALTER TABLE `users` ADD COLUMN `subsidiary_ids` text;
