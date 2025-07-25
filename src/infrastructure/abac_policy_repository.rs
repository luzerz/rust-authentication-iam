use crate::domain::abac_policy::AbacPolicy;
use super::AbacPolicyRepository;
use super::RepoResult;
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Mutex;

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
        Ok(ids.into_iter().filter_map(|id| policies.get(&id).cloned()).collect())
    }
    async fn get_policies_for_role(&self, role_id: &str) -> RepoResult<Vec<AbacPolicy>> {
        let role_policies = self.role_policies.lock().unwrap();
        let policies = self.policies.lock().unwrap();
        let ids = role_policies.get(role_id).cloned().unwrap_or_default();
        Ok(ids.into_iter().filter_map(|id| policies.get(&id).cloned()).collect())
    }
} 