-- Add priority and conflict resolution fields to ABAC policies table
ALTER TABLE abac_policies 
ADD COLUMN IF NOT EXISTS priority INTEGER DEFAULT 50 CHECK (priority >= 1 AND priority <= 100),
ADD COLUMN IF NOT EXISTS conflict_resolution TEXT DEFAULT 'deny_overrides' CHECK (conflict_resolution IN ('deny_overrides', 'allow_overrides', 'priority_wins', 'first_match'));

-- Create index for priority-based queries
CREATE INDEX IF NOT EXISTS idx_abac_policies_priority ON abac_policies(priority DESC);

-- Update existing policies to have default values
UPDATE abac_policies SET 
    priority = 50,
    conflict_resolution = 'deny_overrides'
WHERE priority IS NULL OR conflict_resolution IS NULL; 