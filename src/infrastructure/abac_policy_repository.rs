use super::AbacPolicyRepository;
use super::RepoResult;
use crate::domain::abac_policy::AbacPolicy;
use async_trait::async_trait;
use sqlx::PgPool;
use std::collections::HashMap;
use std::sync::Mutex;
use tracing::{error, instrument};

pub struct InMemoryAbacPolicyRepository {
    pub policies: Mutex<HashMap<String, AbacPolicy>>,
    pub user_policies: Mutex<HashMap<String, Vec<String>>>, // user_id -> policy_ids
    pub role_policies: Mutex<HashMap<String, Vec<String>>>, // role_id -> policy_ids
}

impl InMemoryAbacPolicyRepository {
    pub fn new() -> Self {
        Self {
            policies: Mutex::new(HashMap::new()),
            user_policies: Mutex::new(HashMap::new()),
            role_policies: Mutex::new(HashMap::new()),
        }
    }
}

impl Default for InMemoryAbacPolicyRepository {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl AbacPolicyRepository for InMemoryAbacPolicyRepository {
    async fn create_policy(&self, policy: AbacPolicy) -> RepoResult<AbacPolicy> {
        let mut policies = self.policies.lock().unwrap();
        policies.insert(policy.id.clone(), policy.clone());
        Ok(policy)
    }
    async fn get_policy(&self, policy_id: &str) -> RepoResult<Option<AbacPolicy>> {
        let policies = self.policies.lock().unwrap();
        Ok(policies.get(policy_id).cloned())
    }
    async fn update_policy(
        &self,
        policy_id: &str,
        updated_policy: AbacPolicy,
    ) -> RepoResult<AbacPolicy> {
        let mut policies = self.policies.lock().unwrap();
        if let Some(existing_policy) = policies.get_mut(policy_id) {
            // Update the existing policy with new values
            existing_policy.name = updated_policy.name;
            existing_policy.effect = updated_policy.effect;
            existing_policy.conditions = updated_policy.conditions;
            Ok(existing_policy.clone())
        } else {
            Err(sqlx::Error::RowNotFound)
        }
    }
    async fn list_policies(&self) -> RepoResult<Vec<AbacPolicy>> {
        let policies = self.policies.lock().unwrap();
        Ok(policies.values().cloned().collect())
    }
    async fn delete_policy(&self, policy_id: &str) -> RepoResult<()> {
        let mut policies = self.policies.lock().unwrap();
        policies.remove(policy_id);
        // Remove from user and role assignments
        let mut user_policies = self.user_policies.lock().unwrap();
        for ids in user_policies.values_mut() {
            ids.retain(|id| id != policy_id);
        }
        let mut role_policies = self.role_policies.lock().unwrap();
        for ids in role_policies.values_mut() {
            ids.retain(|id| id != policy_id);
        }
        Ok(())
    }
    async fn assign_policy_to_user(&self, user_id: &str, policy_id: &str) -> RepoResult<()> {
        let mut user_policies = self.user_policies.lock().unwrap();
        let entry = user_policies.entry(user_id.to_string()).or_default();
        if !entry.contains(&policy_id.to_string()) {
            entry.push(policy_id.to_string());
        }
        Ok(())
    }
    async fn assign_policy_to_role(&self, role_id: &str, policy_id: &str) -> RepoResult<()> {
        let mut role_policies = self.role_policies.lock().unwrap();
        let entry = role_policies.entry(role_id.to_string()).or_default();
        if !entry.contains(&policy_id.to_string()) {
            entry.push(policy_id.to_string());
        }
        Ok(())
    }
    async fn get_policies_for_user(&self, user_id: &str) -> RepoResult<Vec<AbacPolicy>> {
        let user_policies = self.user_policies.lock().unwrap();
        let policies = self.policies.lock().unwrap();
        let ids = user_policies.get(user_id).cloned().unwrap_or_default();
        Ok(ids
            .into_iter()
            .filter_map(|id| policies.get(&id).cloned())
            .collect())
    }
    async fn get_policies_for_role(&self, role_id: &str) -> RepoResult<Vec<AbacPolicy>> {
        let role_policies = self.role_policies.lock().unwrap();
        let policies = self.policies.lock().unwrap();
        let ids = role_policies.get(role_id).cloned().unwrap_or_default();
        Ok(ids
            .into_iter()
            .filter_map(|id| policies.get(&id).cloned())
            .collect())
    }
}

#[derive(Debug, Clone)]
pub struct PostgresAbacPolicyRepository {
    pub pool: PgPool,
}

impl PostgresAbacPolicyRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl AbacPolicyRepository for PostgresAbacPolicyRepository {
    #[instrument]
    async fn create_policy(&self, policy: AbacPolicy) -> RepoResult<AbacPolicy> {
        // For now, we'll use a simple JSON serialization approach
        // In a real implementation, you might want to normalize this into separate tables
        let policy_json = serde_json::to_string(&policy).map_err(|e| {
            error!(error = %e, "Failed to serialize policy");
            sqlx::Error::RowNotFound
        })?;

        let rec = sqlx::query!(
            "INSERT INTO abac_policies (id, name, effect, conditions_json, priority, conflict_resolution) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, name, effect, conditions_json, priority, conflict_resolution",
            policy.id,
            policy.name,
            match policy.effect {
                crate::domain::abac_policy::AbacEffect::Allow => "allow",
                crate::domain::abac_policy::AbacEffect::Deny => "deny",
            },
            policy_json,
            policy.priority.unwrap_or(50),
            match policy.conflict_resolution.unwrap_or(crate::domain::abac_policy::ConflictResolutionStrategy::DenyOverrides) {
                crate::domain::abac_policy::ConflictResolutionStrategy::DenyOverrides => "deny_overrides",
                crate::domain::abac_policy::ConflictResolutionStrategy::AllowOverrides => "allow_overrides",
                crate::domain::abac_policy::ConflictResolutionStrategy::PriorityWins => "priority_wins",
                crate::domain::abac_policy::ConflictResolutionStrategy::FirstMatch => "first_match",
            }
        )
        .fetch_one(&self.pool)
        .await?;

        // Reconstruct the policy from the database record
        let conditions: Vec<crate::domain::abac_policy::AbacCondition> =
            serde_json::from_str(&rec.conditions_json).map_err(|e| {
                error!(error = %e, "Failed to deserialize conditions");
                sqlx::Error::RowNotFound
            })?;

        Ok(AbacPolicy {
            id: rec.id,
            name: rec.name,
            effect: match rec.effect.as_str() {
                "allow" => crate::domain::abac_policy::AbacEffect::Allow,
                "deny" => crate::domain::abac_policy::AbacEffect::Deny,
                _ => crate::domain::abac_policy::AbacEffect::Deny, // Default to deny
            },
            conditions,
            priority: rec.priority,
            conflict_resolution: rec.conflict_resolution.as_ref().map(|s| match s.as_str() {
                "deny_overrides" => {
                    crate::domain::abac_policy::ConflictResolutionStrategy::DenyOverrides
                }
                "allow_overrides" => {
                    crate::domain::abac_policy::ConflictResolutionStrategy::AllowOverrides
                }
                "priority_wins" => {
                    crate::domain::abac_policy::ConflictResolutionStrategy::PriorityWins
                }
                "first_match" => crate::domain::abac_policy::ConflictResolutionStrategy::FirstMatch,
                _ => crate::domain::abac_policy::ConflictResolutionStrategy::DenyOverrides, // Default
            }),
        })
    }

    #[instrument]
    async fn get_policy(&self, policy_id: &str) -> RepoResult<Option<AbacPolicy>> {
        let rec = sqlx::query!(
            "SELECT id, name, effect, conditions_json, priority, conflict_resolution FROM abac_policies WHERE id = $1",
            policy_id
        )
        .fetch_optional(&self.pool)
        .await?;

        match rec {
            Some(row) => {
                let conditions: Vec<crate::domain::abac_policy::AbacCondition> =
                    serde_json::from_str(&row.conditions_json).map_err(|e| {
                        error!(error = %e, "Failed to deserialize conditions");
                        sqlx::Error::RowNotFound
                    })?;

                Ok(Some(AbacPolicy {
                    id: row.id,
                    name: row.name,
                    effect: match row.effect.as_str() {
                        "allow" => crate::domain::abac_policy::AbacEffect::Allow,
                        "deny" => crate::domain::abac_policy::AbacEffect::Deny,
                        _ => crate::domain::abac_policy::AbacEffect::Deny,
                    },
                    conditions,
                    priority: row.priority,
                    conflict_resolution: row.conflict_resolution.as_ref().map(|s| match s.as_str() {
                        "deny_overrides" => crate::domain::abac_policy::ConflictResolutionStrategy::DenyOverrides,
                        "allow_overrides" => crate::domain::abac_policy::ConflictResolutionStrategy::AllowOverrides,
                        "priority_wins" => crate::domain::abac_policy::ConflictResolutionStrategy::PriorityWins,
                        "first_match" => crate::domain::abac_policy::ConflictResolutionStrategy::FirstMatch,
                        _ => crate::domain::abac_policy::ConflictResolutionStrategy::DenyOverrides, // Default
                    }),
                }))
            }
            None => Ok(None),
        }
    }

    #[instrument]
    async fn update_policy(
        &self,
        policy_id: &str,
        updated_policy: AbacPolicy,
    ) -> RepoResult<AbacPolicy> {
        // First check if the policy exists
        let existing_policy = self.get_policy(policy_id).await?;
        if existing_policy.is_none() {
            return Err(sqlx::Error::RowNotFound);
        }

        // Serialize the updated conditions
        let conditions_json = serde_json::to_string(&updated_policy.conditions).map_err(|e| {
            error!(error = %e, "Failed to serialize conditions");
            sqlx::Error::RowNotFound
        })?;

        // Update the policy
        let rec = sqlx::query!(
            "UPDATE abac_policies SET name = $1, effect = $2, conditions_json = $3, priority = $4, conflict_resolution = $5, updated_at = NOW() WHERE id = $6 RETURNING id, name, effect, conditions_json, priority, conflict_resolution",
            updated_policy.name,
            match updated_policy.effect {
                crate::domain::abac_policy::AbacEffect::Allow => "allow",
                crate::domain::abac_policy::AbacEffect::Deny => "deny",
            },
            conditions_json,
            updated_policy.priority,
            match updated_policy.conflict_resolution.unwrap_or(crate::domain::abac_policy::ConflictResolutionStrategy::DenyOverrides) {
                crate::domain::abac_policy::ConflictResolutionStrategy::DenyOverrides => "deny_overrides",
                crate::domain::abac_policy::ConflictResolutionStrategy::AllowOverrides => "allow_overrides",
                crate::domain::abac_policy::ConflictResolutionStrategy::PriorityWins => "priority_wins",
                crate::domain::abac_policy::ConflictResolutionStrategy::FirstMatch => "first_match",
            },
            policy_id
        )
        .fetch_one(&self.pool)
        .await?;

        // Deserialize the conditions back
        let conditions: Vec<crate::domain::abac_policy::AbacCondition> =
            serde_json::from_str(&rec.conditions_json).map_err(|e| {
                error!(error = %e, "Failed to deserialize conditions");
                sqlx::Error::RowNotFound
            })?;

        Ok(AbacPolicy {
            id: rec.id,
            name: rec.name,
            effect: match rec.effect.as_str() {
                "allow" => crate::domain::abac_policy::AbacEffect::Allow,
                "deny" => crate::domain::abac_policy::AbacEffect::Deny,
                _ => crate::domain::abac_policy::AbacEffect::Deny,
            },
            conditions,
            priority: rec.priority,
            conflict_resolution: rec.conflict_resolution.as_ref().map(|s| match s.as_str() {
                "deny_overrides" => {
                    crate::domain::abac_policy::ConflictResolutionStrategy::DenyOverrides
                }
                "allow_overrides" => {
                    crate::domain::abac_policy::ConflictResolutionStrategy::AllowOverrides
                }
                "priority_wins" => {
                    crate::domain::abac_policy::ConflictResolutionStrategy::PriorityWins
                }
                "first_match" => crate::domain::abac_policy::ConflictResolutionStrategy::FirstMatch,
                _ => crate::domain::abac_policy::ConflictResolutionStrategy::DenyOverrides, // Default
            }),
        })
    }

    #[instrument]
    async fn list_policies(&self) -> RepoResult<Vec<AbacPolicy>> {
        let rows = sqlx::query!(
            "SELECT id, name, effect, conditions_json, priority, conflict_resolution FROM abac_policies ORDER BY priority DESC"
        )
        .fetch_all(&self.pool)
        .await?;

        let mut policies = Vec::new();
        for row in rows {
            let conditions: Vec<crate::domain::abac_policy::AbacCondition> =
                serde_json::from_str(&row.conditions_json).map_err(|e| {
                    error!(error = %e, "Failed to deserialize conditions");
                    sqlx::Error::RowNotFound
                })?;

            policies.push(AbacPolicy {
                id: row.id,
                name: row.name,
                effect: match row.effect.as_str() {
                    "allow" => crate::domain::abac_policy::AbacEffect::Allow,
                    "deny" => crate::domain::abac_policy::AbacEffect::Deny,
                    _ => crate::domain::abac_policy::AbacEffect::Deny,
                },
                conditions,
                priority: row.priority,
                conflict_resolution: row.conflict_resolution.as_ref().map(|s| match s.as_str() {
                    "deny_overrides" => {
                        crate::domain::abac_policy::ConflictResolutionStrategy::DenyOverrides
                    }
                    "allow_overrides" => {
                        crate::domain::abac_policy::ConflictResolutionStrategy::AllowOverrides
                    }
                    "priority_wins" => {
                        crate::domain::abac_policy::ConflictResolutionStrategy::PriorityWins
                    }
                    "first_match" => {
                        crate::domain::abac_policy::ConflictResolutionStrategy::FirstMatch
                    }
                    _ => crate::domain::abac_policy::ConflictResolutionStrategy::DenyOverrides, // Default
                }),
            });
        }

        Ok(policies)
    }

    #[instrument]
    async fn delete_policy(&self, policy_id: &str) -> RepoResult<()> {
        sqlx::query!("DELETE FROM abac_policies WHERE id = $1", policy_id)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                error!(error = %e, "Failed to delete policy");
                e
            })?;

        // Clean up assignments
        let _ = sqlx::query!(
            "DELETE FROM user_abac_policies WHERE policy_id = $1",
            policy_id
        )
        .execute(&self.pool)
        .await;
        let _ = sqlx::query!(
            "DELETE FROM role_abac_policies WHERE policy_id = $1",
            policy_id
        )
        .execute(&self.pool)
        .await;

        Ok(())
    }

    #[instrument]
    async fn assign_policy_to_user(&self, user_id: &str, policy_id: &str) -> RepoResult<()> {
        sqlx::query!(
            "INSERT INTO user_abac_policies (user_id, policy_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
            user_id,
            policy_id
        )
        .execute(&self.pool)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to assign policy to user");
            e
        })?;
        Ok(())
    }

    #[instrument]
    async fn assign_policy_to_role(&self, role_id: &str, policy_id: &str) -> RepoResult<()> {
        sqlx::query!(
            "INSERT INTO role_abac_policies (role_id, policy_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
            role_id,
            policy_id
        )
        .execute(&self.pool)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to assign policy to role");
            e
        })?;
        Ok(())
    }

    #[instrument]
    async fn get_policies_for_user(&self, user_id: &str) -> RepoResult<Vec<AbacPolicy>> {
        let rows = sqlx::query!(
            r#"
            SELECT p.id, p.name, p.effect, p.conditions_json, p.priority, p.conflict_resolution
            FROM abac_policies p
            INNER JOIN user_abac_policies uap ON uap.policy_id = p.id
            WHERE uap.user_id = $1
            ORDER BY p.priority DESC
            "#,
            user_id
        )
        .fetch_all(&self.pool)
        .await?;

        let mut policies = Vec::new();
        for row in rows {
            let conditions: Vec<crate::domain::abac_policy::AbacCondition> =
                serde_json::from_str(&row.conditions_json).map_err(|e| {
                    error!(error = %e, "Failed to deserialize conditions");
                    sqlx::Error::RowNotFound
                })?;

            policies.push(AbacPolicy {
                id: row.id,
                name: row.name,
                effect: match row.effect.as_str() {
                    "allow" => crate::domain::abac_policy::AbacEffect::Allow,
                    "deny" => crate::domain::abac_policy::AbacEffect::Deny,
                    _ => crate::domain::abac_policy::AbacEffect::Deny,
                },
                conditions,
                priority: row.priority,
                conflict_resolution: row.conflict_resolution.as_ref().map(|s| match s.as_str() {
                    "deny_overrides" => {
                        crate::domain::abac_policy::ConflictResolutionStrategy::DenyOverrides
                    }
                    "allow_overrides" => {
                        crate::domain::abac_policy::ConflictResolutionStrategy::AllowOverrides
                    }
                    "priority_wins" => {
                        crate::domain::abac_policy::ConflictResolutionStrategy::PriorityWins
                    }
                    "first_match" => {
                        crate::domain::abac_policy::ConflictResolutionStrategy::FirstMatch
                    }
                    _ => crate::domain::abac_policy::ConflictResolutionStrategy::DenyOverrides, // Default
                }),
            });
        }

        Ok(policies)
    }

    #[instrument]
    async fn get_policies_for_role(&self, role_id: &str) -> RepoResult<Vec<AbacPolicy>> {
        let rows = sqlx::query!(
            r#"
            SELECT p.id, p.name, p.effect, p.conditions_json, p.priority, p.conflict_resolution
            FROM abac_policies p
            INNER JOIN role_abac_policies rap ON rap.policy_id = p.id
            WHERE rap.role_id = $1
            ORDER BY p.priority DESC
            "#,
            role_id
        )
        .fetch_all(&self.pool)
        .await?;

        let mut policies = Vec::new();
        for row in rows {
            let conditions: Vec<crate::domain::abac_policy::AbacCondition> =
                serde_json::from_str(&row.conditions_json).map_err(|e| {
                    error!(error = %e, "Failed to deserialize conditions");
                    sqlx::Error::RowNotFound
                })?;

            policies.push(AbacPolicy {
                id: row.id,
                name: row.name,
                effect: match row.effect.as_str() {
                    "allow" => crate::domain::abac_policy::AbacEffect::Allow,
                    "deny" => crate::domain::abac_policy::AbacEffect::Deny,
                    _ => crate::domain::abac_policy::AbacEffect::Deny,
                },
                conditions,
                priority: row.priority,
                conflict_resolution: row.conflict_resolution.as_ref().map(|s| match s.as_str() {
                    "deny_overrides" => {
                        crate::domain::abac_policy::ConflictResolutionStrategy::DenyOverrides
                    }
                    "allow_overrides" => {
                        crate::domain::abac_policy::ConflictResolutionStrategy::AllowOverrides
                    }
                    "priority_wins" => {
                        crate::domain::abac_policy::ConflictResolutionStrategy::PriorityWins
                    }
                    "first_match" => {
                        crate::domain::abac_policy::ConflictResolutionStrategy::FirstMatch
                    }
                    _ => crate::domain::abac_policy::ConflictResolutionStrategy::DenyOverrides, // Default
                }),
            });
        }

        Ok(policies)
    }
}
