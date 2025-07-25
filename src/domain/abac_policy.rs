use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AbacPolicy {
    pub id: String,
    pub name: String,
    pub effect: AbacEffect,
    pub conditions: Vec<AbacCondition>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum AbacEffect {
    Allow,
    Deny,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AbacCondition {
    pub attribute: String, // e.g. "department"
    pub operator: String,  // e.g. "eq", "ne", "in", etc.
    pub value: String,     // e.g. "engineering"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_abac_policy_creation() {
        let cond = AbacCondition {
            attribute: "department".to_string(),
            operator: "eq".to_string(),
            value: "engineering".to_string(),
        };
        let policy = AbacPolicy {
            id: "policy1".to_string(),
            name: "Allow engineers".to_string(),
            effect: AbacEffect::Allow,
            conditions: vec![cond],
        };
        assert_eq!(policy.name, "Allow engineers");
        assert_eq!(policy.conditions.len(), 1);
    }
}
