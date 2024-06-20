-- Add migration script here
ALTER TABLE IF EXISTS todo_items
    ADD COLUMN created_at timestamp with time zone NOT NULL DEFAULT now();
