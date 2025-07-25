/// Command to log in a user
pub struct LoginUserCommand {
    pub email: String,
    pub password: String,
}

/// Command to change a user's password
pub struct ChangePasswordCommand {
    pub user_id: String,
    pub current_password: String,
    pub new_password: String,
}

/// Command to reset a user's password
pub struct ResetPasswordCommand {
    pub reset_token: String,
    pub new_password: String,
}

/// Command to assign roles to a user
pub struct AssignRolesCommand {
    pub user_id: String,
    pub role_ids: Vec<String>,
}
