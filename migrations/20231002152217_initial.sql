-- Add migration script here

CREATE TABLE todo_items (
    id serial PRIMARY KEY,
    item_description varchar(255) NOT NULL,
    is_complete boolean NOT NULL DEFAULT False
);