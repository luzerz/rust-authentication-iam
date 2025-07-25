use sqlx::{PgPool, Row};

#[tokio::test]
async fn test_database_connectivity() {
    // Skip if no database connection available
    let database_url = std::env::var("DATABASE_URL").ok();
    if database_url.is_none() {
        eprintln!("Skipping database connectivity test - no DATABASE_URL");
        return;
    }

    let pool = PgPool::connect(&database_url.unwrap()).await.unwrap();

    // Test basic connectivity
    let result = sqlx::query("SELECT 1 as test_value")
        .fetch_one(&pool)
        .await
        .unwrap();
    let test_value: i32 = result.get("test_value");
    assert_eq!(test_value, 1);

    // Test that required tables exist
    let tables = sqlx::query(
        "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'",
    )
    .fetch_all(&pool)
    .await
    .unwrap();

    let table_names: Vec<String> = tables
        .iter()
        .map(|row| row.get::<String, _>("table_name"))
        .collect();

    println!("Available tables: {:?}", table_names);

    // Check for required tables
    assert!(
        table_names.contains(&"users".to_string()),
        "users table not found"
    );
    assert!(
        table_names.contains(&"roles".to_string()),
        "roles table not found"
    );
    assert!(
        table_names.contains(&"permissions".to_string()),
        "permissions table not found"
    );
    assert!(
        table_names.contains(&"user_roles".to_string()),
        "user_roles table not found"
    );
    assert!(
        table_names.contains(&"role_permissions".to_string()),
        "role_permissions table not found"
    );
    assert!(
        table_names.contains(&"refresh_tokens".to_string()),
        "refresh_tokens table not found"
    );

    // Test that seed data exists
    let user_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(&pool)
        .await
        .unwrap();
    println!("User count: {}", user_count);

    let role_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM roles")
        .fetch_one(&pool)
        .await
        .unwrap();
    println!("Role count: {}", role_count);

    // Verify seed data from migration 003_seed_test_data.sql
    let test_user = sqlx::query("SELECT email FROM users WHERE id = 'user-1'")
        .fetch_optional(&pool)
        .await
        .unwrap();
    assert!(test_user.is_some(), "Seed user not found");

    let admin_role = sqlx::query("SELECT name FROM roles WHERE id = 'role-1'")
        .fetch_optional(&pool)
        .await
        .unwrap();
    assert!(admin_role.is_some(), "Admin role not found");

    println!("Database connectivity test passed successfully!");
}
