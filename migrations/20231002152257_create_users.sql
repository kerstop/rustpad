-- Add migration script here

CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) UNIQUE NOT NULL
);

INSERT INTO users (id, username, password_hash) VALUES (0, 'default', 'no_login');

ALTER TABLE todo_items 
    ADD owner_id int not NULL DEFAULT 0;

ALTER TABLE todo_items
    ADD FOREIGN KEY (owner_id) REFERENCES Users(id);

ALTER TABLE todo_items
    ALTER owner_id DROP DEFAULT;