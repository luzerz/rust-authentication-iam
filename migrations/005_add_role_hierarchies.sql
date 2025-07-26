-- Add role hierarchy support
ALTER TABLE roles ADD COLUMN parent_role_id TEXT REFERENCES roles(id) ON DELETE SET NULL;

-- Create index for efficient parent role lookups
CREATE INDEX idx_roles_parent_role_id ON roles(parent_role_id);
 
-- Add constraint to prevent circular references
-- This will be enforced at the application level for now
-- as PostgreSQL doesn't have built-in circular reference prevention for self-referencing tables 