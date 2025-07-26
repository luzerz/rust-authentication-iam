-- Create ABAC policies table
CREATE TABLE IF NOT EXISTS abac_policies (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    effect TEXT NOT NULL CHECK (effect IN ('allow', 'deny')),
    conditions_json TEXT NOT NULL, -- JSON serialized conditions
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create user ABAC policy assignments table
CREATE TABLE IF NOT EXISTS user_abac_policies (
    user_id TEXT NOT NULL,
    policy_id TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    PRIMARY KEY (user_id, policy_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (policy_id) REFERENCES abac_policies(id) ON DELETE CASCADE
);

-- Create role ABAC policy assignments table
CREATE TABLE IF NOT EXISTS role_abac_policies (
    role_id TEXT NOT NULL,
    policy_id TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    PRIMARY KEY (role_id, policy_id),
    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
    FOREIGN KEY (policy_id) REFERENCES abac_policies(id) ON DELETE CASCADE
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_user_abac_policies_user_id ON user_abac_policies(user_id);
CREATE INDEX IF NOT EXISTS idx_user_abac_policies_policy_id ON user_abac_policies(policy_id);
CREATE INDEX IF NOT EXISTS idx_role_abac_policies_role_id ON role_abac_policies(role_id);
CREATE INDEX IF NOT EXISTS idx_role_abac_policies_policy_id ON role_abac_policies(policy_id); 