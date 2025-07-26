-- Add permission groups table
CREATE TABLE IF NOT EXISTS permission_groups (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    description TEXT,
    category TEXT,
    metadata JSONB NOT NULL DEFAULT '{}',
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Add indexes for efficient querying
CREATE INDEX idx_permission_groups_name ON permission_groups(name);
CREATE INDEX idx_permission_groups_category ON permission_groups(category);
CREATE INDEX idx_permission_groups_active ON permission_groups(is_active);

-- Enhance permissions table with metadata and group association
ALTER TABLE permissions ADD COLUMN IF NOT EXISTS description TEXT;
ALTER TABLE permissions ADD COLUMN IF NOT EXISTS group_id TEXT REFERENCES permission_groups(id) ON DELETE SET NULL;
ALTER TABLE permissions ADD COLUMN IF NOT EXISTS metadata JSONB NOT NULL DEFAULT '{}';
ALTER TABLE permissions ADD COLUMN IF NOT EXISTS is_active BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE permissions ADD COLUMN IF NOT EXISTS created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW();
ALTER TABLE permissions ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW();

-- Add indexes for enhanced permissions
CREATE INDEX IF NOT EXISTS idx_permissions_group_id ON permissions(group_id);
CREATE INDEX IF NOT EXISTS idx_permissions_active ON permissions(is_active);
CREATE INDEX IF NOT EXISTS idx_permissions_name ON permissions(name);

-- Create a function to update the updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Create triggers to automatically update updated_at
CREATE TRIGGER update_permission_groups_updated_at 
    BEFORE UPDATE ON permission_groups 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_permissions_updated_at 
    BEFORE UPDATE ON permissions 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column(); 