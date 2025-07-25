INSERT INTO users (id, email, password_hash, is_locked) VALUES (
  'user-1',
  'test@example.com',
  '$2b$12$KIXQ4QyQeF2rQ1Q0Q0Q0QeQ0Q0Q0Q0Q0Q0Q0Q0Q0Q0Q0Q0Q0Q0Q0Q0Q0Q0Q0Q0Q0',
  FALSE
);

INSERT INTO roles (id, name) VALUES
  ('role-1', 'admin'),
  ('role-2', 'user');

INSERT INTO user_roles (user_id, role_id) VALUES
  ('user-1', 'role-1');
