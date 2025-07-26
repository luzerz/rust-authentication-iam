# ABAC (Attribute-Based Access Control) System Documentation

## Overview

The ABAC system provides a comprehensive attribute-based access control mechanism with policy management, advanced condition operators, priority-based conflict resolution, and detailed evaluation capabilities. It supports complex access control scenarios based on user attributes, resource attributes, and environmental conditions.

## Core Components

### 1. Domain Models

#### ABAC Policy
```rust
pub struct AbacPolicy {
    pub id: String,
    pub name: String,
    pub effect: AbacEffect,
    pub conditions: Vec<AbacCondition>,
    pub priority: Option<i32>, // 1-100, higher = more important
    pub conflict_resolution: Option<ConflictResolutionStrategy>,
}
```

#### ABAC Effect
```rust
pub enum AbacEffect {
    Allow,
    Deny,
}
```

#### ABAC Condition
```rust
pub struct AbacCondition {
    pub attribute: String, // e.g., "department", "role", "time"
    pub operator: String,  // e.g., "eq", "in", "gt", "contains"
    pub value: String,     // e.g., "engineering", "admin,user", "9"
}
```

#### Conflict Resolution Strategy
```rust
pub enum ConflictResolutionStrategy {
    DenyOverrides,    // Deny policies take precedence over Allow policies
    AllowOverrides,   // Allow policies take precedence over Deny policies
    PriorityWins,     // Higher priority policy wins regardless of effect
    FirstMatch,       // First matching policy wins (legacy behavior)
}
```

### 2. ABAC Service (`AuthZService`)

#### Key Methods

```rust
// Check if user has ABAC permission
async fn user_has_abac_permission(
    &self,
    user_id: &str,
    permission_name: &str,
    user_attrs: &HashMap<String, String>,
) -> Result<bool, sqlx::Error>

// Evaluate ABAC policies with detailed results
async fn evaluate_abac_policies(
    &self,
    user_id: &str,
    permission_name: &str,
    user_attrs: &HashMap<String, String>,
) -> Result<AbacEvaluationResponse, sqlx::Error>
```

## API Endpoints

### Policy Management

#### 1. Create ABAC Policy
```http
POST /v1/iam/abac/policies
Authorization: Bearer <access_token>
X-User-Id: <requesting_user_id>
Content-Type: application/json

{
  "name": "engineering_access",
  "effect": "Allow",
  "priority": 75,
  "conflict_resolution": "deny_overrides",
  "conditions": [
    {
      "attribute": "department",
      "operator": "eq",
      "value": "engineering"
    },
    {
      "attribute": "role",
      "operator": "in",
      "value": "admin,developer"
    }
  ]
}
```

**Response:**
```json
{
  "id": "policy123",
  "name": "engineering_access",
  "effect": "Allow",
  "priority": 75,
  "conflict_resolution": "deny_overrides",
  "conditions": [
    {
      "attribute": "department",
      "operator": "eq",
      "value": "engineering"
    },
    {
      "attribute": "role",
      "operator": "in",
      "value": "admin,developer"
    }
  ]
}
```

#### 2. Update ABAC Policy
```http
PUT /v1/iam/abac/policies/{policy_id}
Authorization: Bearer <access_token>
X-User-Id: <requesting_user_id>
Content-Type: application/json

{
  "name": "engineering_access_v2",
  "priority": 80,
  "conditions": [
    {
      "attribute": "department",
      "operator": "eq",
      "value": "engineering"
    },
    {
      "attribute": "security_level",
      "operator": "gte",
      "value": "3"
    }
  ]
}
```

#### 3. List ABAC Policies
```http
GET /v1/iam/abac/policies
Authorization: Bearer <access_token>
```

**Response:**
```json
{
  "policies": [
    {
      "id": "policy123",
      "name": "engineering_access",
      "effect": "Allow",
      "priority": 75,
      "conflict_resolution": "deny_overrides",
      "conditions": [...]
    }
  ]
}
```

#### 4. Delete ABAC Policy
```http
DELETE /v1/iam/abac/policies/{policy_id}
Authorization: Bearer <access_token>
X-User-Id: <requesting_user_id>
```

### Policy Assignment

#### 1. Assign Policy to User/Role
```http
POST /v1/iam/abac/assign
Authorization: Bearer <access_token>
X-User-Id: <requesting_user_id>
Content-Type: application/json

{
  "target_type": "user",
  "target_id": "user123",
  "policy_id": "policy456"
}
```

### Policy Evaluation

#### 1. Evaluate ABAC Policies
```http
POST /v1/iam/abac/evaluate
Authorization: Bearer <access_token>
X-User-Id: <requesting_user_id>
Content-Type: application/json

{
  "user_id": "user123",
  "permission_name": "access_system",
  "attributes": {
    "department": "engineering",
    "role": "admin",
    "security_level": "4",
    "location": "office",
    "time": "09:30"
  }
}
```

**Response:**
```json
{
  "user_id": "user123",
  "permission_name": "access_system",
  "allowed": true,
  "reason": "Policy 'engineering_access' applied with effect 'Allow'",
  "evaluated_policies": [
    {
      "policy_id": "policy123",
      "policy_name": "engineering_access",
      "effect": "Allow",
      "priority": 75,
      "conflict_resolution": "deny_overrides",
      "matched": true,
      "applied": true,
      "matched_conditions": [
        {
          "attribute": "department",
          "operator": "eq",
          "value": "engineering"
        },
        {
          "attribute": "role",
          "operator": "in",
          "value": "admin,developer"
        }
      ],
      "unmatched_conditions": []
    },
    {
      "policy_id": "policy456",
      "policy_name": "emergency_lockdown",
      "effect": "Deny",
      "priority": 95,
      "conflict_resolution": "deny_overrides",
      "matched": false,
      "applied": false,
      "matched_conditions": [],
      "unmatched_conditions": [
        {
          "attribute": "emergency_status",
          "operator": "eq",
          "value": "active"
        }
      ]
    }
  ]
}
```

## Condition Operators

### Supported Operators

#### 1. Equality Operators
- **`eq`** - Equal to
  ```json
  {
    "attribute": "department",
    "operator": "eq",
    "value": "engineering"
  }
  ```

- **`ne`** - Not equal to
  ```json
  {
    "attribute": "role",
    "operator": "ne",
    "value": "guest"
  }
  ```

#### 2. Collection Operators
- **`in`** - Value is in comma-separated list
  ```json
  {
    "attribute": "role",
    "operator": "in",
    "value": "admin,manager,developer"
  }
  ```

#### 3. Numeric Comparison Operators
- **`gt`** - Greater than
  ```json
  {
    "attribute": "security_level",
    "operator": "gt",
    "value": "3"
  }
  ```

- **`lt`** - Less than
  ```json
  {
    "attribute": "age",
    "operator": "lt",
    "value": "65"
  }
  ```

- **`gte`** - Greater than or equal to
  ```json
  {
    "attribute": "experience_years",
    "operator": "gte",
    "value": "5"
  }
  ```

- **`lte`** - Less than or equal to
  ```json
  {
    "attribute": "salary",
    "operator": "lte",
    "value": "100000"
  }
  ```

#### 4. String Operators
- **`contains`** - String contains substring
  ```json
  {
    "attribute": "description",
    "operator": "contains",
    "value": "confidential"
  }
  ```

- **`starts_with`** - String starts with prefix
  ```json
  {
    "attribute": "username",
    "operator": "starts_with",
    "value": "admin"
  }
  ```

- **`ends_with`** - String ends with suffix
  ```json
  {
    "attribute": "email",
    "operator": "ends_with",
    "value": "@company.com"
  }
  ```

## Conflict Resolution Strategies

### 1. DenyOverrides
- **Behavior**: Deny policies take precedence over Allow policies
- **Use Case**: Security-first approach, deny by default
- **Example**: Emergency lockdown policies override normal access

```json
{
  "name": "emergency_lockdown",
  "effect": "Deny",
  "priority": 95,
  "conflict_resolution": "deny_overrides",
  "conditions": [
    {
      "attribute": "emergency_status",
      "operator": "eq",
      "value": "active"
    }
  ]
}
```

### 2. AllowOverrides
- **Behavior**: Allow policies take precedence over Deny policies
- **Use Case**: Accessibility-first approach, allow by default
- **Example**: Override policies for special circumstances

```json
{
  "name": "override_access",
  "effect": "Allow",
  "priority": 90,
  "conflict_resolution": "allow_overrides",
  "conditions": [
    {
      "attribute": "override_approved",
      "operator": "eq",
      "value": "true"
    }
  ]
}
```

### 3. PriorityWins
- **Behavior**: Higher priority policy wins regardless of effect
- **Use Case**: Hierarchical policy management
- **Example**: Executive policies override department policies

```json
{
  "name": "executive_access",
  "effect": "Allow",
  "priority": 100,
  "conflict_resolution": "priority_wins",
  "conditions": [
    {
      "attribute": "role",
      "operator": "eq",
      "value": "executive"
    }
  ]
}
```

### 4. FirstMatch
- **Behavior**: First matching policy wins (legacy behavior)
- **Use Case**: Simple policy evaluation
- **Example**: Basic access control scenarios

```json
{
  "name": "basic_access",
  "effect": "Allow",
  "priority": 50,
  "conflict_resolution": "first_match",
  "conditions": [
    {
      "attribute": "department",
      "operator": "eq",
      "value": "engineering"
    }
  ]
}
```

## Database Schema

### ABAC Policies Table
```sql
CREATE TABLE abac_policies (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    effect TEXT NOT NULL CHECK (effect IN ('allow', 'deny')),
    conditions_json TEXT NOT NULL, -- JSON serialized conditions
    priority INTEGER DEFAULT 50 CHECK (priority >= 1 AND priority <= 100),
    conflict_resolution TEXT DEFAULT 'deny_overrides' 
        CHECK (conflict_resolution IN ('deny_overrides', 'allow_overrides', 'priority_wins', 'first_match')),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Index for priority-based queries
CREATE INDEX idx_abac_policies_priority ON abac_policies(priority DESC);
```

### Policy Assignments
```sql
-- User ABAC policy assignments
CREATE TABLE user_abac_policies (
    user_id TEXT NOT NULL,
    policy_id TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    PRIMARY KEY (user_id, policy_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (policy_id) REFERENCES abac_policies(id) ON DELETE CASCADE
);

-- Role ABAC policy assignments
CREATE TABLE role_abac_policies (
    role_id TEXT NOT NULL,
    policy_id TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    PRIMARY KEY (role_id, policy_id),
    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
    FOREIGN KEY (policy_id) REFERENCES abac_policies(id) ON DELETE CASCADE
);
```

## Policy Evaluation Process

### 1. Two-Pass Evaluation Algorithm

#### First Pass: Policy Evaluation
1. Retrieve all policies assigned to the user (directly or via roles)
2. Order policies by priority (highest first)
3. Evaluate each policy's conditions against user attributes
4. Collect all matching policies

#### Second Pass: Conflict Resolution
1. Apply the conflict resolution strategy
2. Determine which policy wins
3. Mark the winning policy as "applied"
4. Generate detailed reasoning

### 2. Evaluation Logic

```rust
// First pass: evaluate all policies
for policy in &policies {
    if policy.name == permission_name {
        let mut all_match = true;
        let mut matched_conditions = Vec::new();
        let mut unmatched_conditions = Vec::new();
        
        for condition in &policy.conditions {
            let attribute_value = user_attrs.get(&condition.attribute);
            
            match (attribute_value, condition.operator.as_str()) {
                (Some(value), "eq") if value == &condition.value => {
                    matched_conditions.push(condition.clone());
                }
                (Some(value), "in") => {
                    let allowed_values: Vec<&str> = condition.value.split(',').collect();
                    if allowed_values.contains(&value.as_str()) {
                        matched_conditions.push(condition.clone());
                    } else {
                        unmatched_conditions.push(condition.clone());
                        all_match = false;
                    }
                }
                // ... other operators
                _ => {
                    unmatched_conditions.push(condition.clone());
                    all_match = false;
                }
            }
        }
        
        if all_match {
            matching_policies.push((policy, evaluation_result));
        }
    }
}

// Second pass: apply conflict resolution
let conflict_strategy = matching_policies[0].0.conflict_resolution
    .as_ref()
    .unwrap_or(&ConflictResolutionStrategy::DenyOverrides);

match conflict_strategy {
    ConflictResolutionStrategy::DenyOverrides => {
        // Find deny policies first
        let deny_policy = matching_policies.iter()
            .find(|(p, _)| matches!(p.effect, AbacEffect::Deny));
        if let Some((policy, _)) = deny_policy {
            (false, format!("Deny policy '{}' overrides all allow policies", policy.name))
        } else {
            let (policy, _) = &matching_policies[0];
            (true, format!("Allow policy '{}' applied", policy.name))
        }
    }
    // ... other strategies
}
```

## Use Cases and Examples

### 1. Department-Based Access
```json
{
  "name": "engineering_department_access",
  "effect": "Allow",
  "priority": 60,
  "conflict_resolution": "deny_overrides",
  "conditions": [
    {
      "attribute": "department",
      "operator": "eq",
      "value": "engineering"
    },
    {
      "attribute": "employment_status",
      "operator": "eq",
      "value": "active"
    }
  ]
}
```

### 2. Time-Based Access
```json
{
  "name": "business_hours_access",
  "effect": "Allow",
  "priority": 70,
  "conflict_resolution": "deny_overrides",
  "conditions": [
    {
      "attribute": "time",
      "operator": "gte",
      "value": "09:00"
    },
    {
      "attribute": "time",
      "operator": "lte",
      "value": "17:00"
    },
    {
      "attribute": "day_of_week",
      "operator": "in",
      "value": "monday,tuesday,wednesday,thursday,friday"
    }
  ]
}
```

### 3. Security Level Access
```json
{
  "name": "high_security_access",
  "effect": "Allow",
  "priority": 80,
  "conflict_resolution": "priority_wins",
  "conditions": [
    {
      "attribute": "security_clearance",
      "operator": "gte",
      "value": "5"
    },
    {
      "attribute": "background_check",
      "operator": "eq",
      "value": "passed"
    }
  ]
}
```

### 4. Emergency Override
```json
{
  "name": "emergency_override",
  "effect": "Deny",
  "priority": 95,
  "conflict_resolution": "deny_overrides",
  "conditions": [
    {
      "attribute": "emergency_status",
      "operator": "eq",
      "value": "active"
    }
  ]
}
```

## Best Practices

### 1. Policy Design
- **Clear Naming**: Use descriptive policy names
- **Focused Conditions**: Keep conditions specific and relevant
- **Priority Planning**: Plan priority levels systematically
- **Conflict Strategy**: Choose appropriate conflict resolution

### 2. Attribute Management
- **Consistent Naming**: Use consistent attribute names
- **Data Types**: Ensure attribute values match expected types
- **Validation**: Validate attribute values before evaluation
- **Documentation**: Document all available attributes

### 3. Performance Optimization
- **Indexing**: Use database indexes for frequently queried attributes
- **Caching**: Cache policy evaluation results when appropriate
- **Batch Processing**: Evaluate multiple policies efficiently
- **Query Optimization**: Optimize database queries for policy retrieval

### 4. Security Considerations
- **Input Validation**: Validate all user attributes
- **Policy Review**: Regular review of policy effectiveness
- **Audit Logging**: Log all policy evaluation decisions
- **Testing**: Comprehensive testing of policy scenarios

## Testing

### Unit Tests
- Policy condition evaluation
- Conflict resolution strategies
- Priority-based ordering
- Error handling scenarios

### Integration Tests
- Complete policy evaluation workflows
- Database persistence and retrieval
- Policy assignment scenarios
- Multi-policy conflict resolution

### Performance Tests
- Large policy set evaluation
- Concurrent policy evaluation
- Database query performance
- Memory usage optimization

## Monitoring and Observability

### Metrics
- Policy evaluation success/failure rates
- Conflict resolution strategy usage
- Policy priority distribution
- Evaluation performance metrics

### Logging
- All policy evaluation decisions
- Conflict resolution reasoning
- Policy assignment changes
- Performance bottlenecks

### Alerts
- Policy evaluation failures
- Unusual access patterns
- Performance degradation
- Security violations 