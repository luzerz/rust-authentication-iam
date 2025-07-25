/// Query to get a user by ID
pub struct GetUserByIdQuery {
    pub user_id: String,
}

/// Query to get roles for a user
pub struct GetRolesForUserQuery {
    pub user_id: String,
}
