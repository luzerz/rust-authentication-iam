# SonarCloud Setup Guide

Quick setup guide for integrating SonarCloud with your authentication service.

## Prerequisites

- GitHub repository with CI/CD pipeline
- SonarCloud account (free tier available)

## Step-by-Step Setup

### 1. Create SonarCloud Account

1. Go to [SonarCloud](https://sonarcloud.io)
2. Sign up with your GitHub account
3. Create a new organization (or use existing)

### 2. Create SonarCloud Project

1. In SonarCloud, click "Create Project"
2. Choose "GitHub" as the repository provider
3. Select your authentication service repository
4. Choose "Use the global setting" for analysis method
5. Click "Create Project"

### 3. Get Project Information

After creating the project, note down:
- **Organization Key**: e.g., `luzerz`
- **Project Key**: e.g., `luzerz_rust-authentication-iam`

### 4. Generate Authentication Token

1. In SonarCloud, go to your account settings
2. Navigate to "Security" → "Tokens"
3. Generate a new token with a descriptive name
4. Copy the token (you won't see it again)

### 5. Add GitHub Secret

1. Go to your GitHub repository
2. Navigate to "Settings" → "Secrets and variables" → "Actions"
3. Click "New repository secret"
4. Name: `SONAR_TOKEN`
5. Value: Paste your SonarCloud token
6. Click "Add secret"

### 6. Update Configuration Files

The following files are already configured:

#### `.github/workflows/ci.yml`
- SonarCloud job added
- Database integration included
- Coverage reporting configured

#### `sonar-project.properties`
- Project metadata configured
- Coverage settings optimized
- Quality gates enabled

### 7. Test the Integration

1. Push a commit to trigger the CI pipeline
2. Check the "Actions" tab in GitHub
3. Verify the SonarCloud job completes successfully
4. Check your SonarCloud project dashboard

## Verification

### Check CI Pipeline
- All jobs should pass
- SonarCloud job should complete without errors
- Coverage reports should be generated

### Check SonarCloud Dashboard
- Project should appear in your SonarCloud organization
- Coverage data should be visible
- Quality gate status should be displayed

## Troubleshooting

### Common Issues

#### "SONAR_TOKEN not found"
- Verify the secret is added to GitHub repository
- Check the secret name matches exactly: `SONAR_TOKEN`

#### "Project not found"
- Verify organization and project keys in `sonar-project.properties`
- Ensure the project exists in SonarCloud

#### "Coverage report not found"
- Check that Tarpaulin generates coverage reports
- Verify the coverage file path in `sonar-project.properties`

#### "Quality gate failed"
- Check coverage threshold (currently set to 60%)
- Review code quality issues in SonarCloud dashboard

### Debug Commands

```bash
# Test SonarCloud configuration locally
sonar-scanner -Dsonar.projectKey=test

# Generate coverage report locally
cargo tarpaulin --out Xml --all --release

# Check database connection
pg_isready -h localhost -p 5433 -U test_user -d test_auth_db
```

## Next Steps

### Quality Gate Configuration
1. In SonarCloud, go to your project
2. Navigate to "Quality Gate"
3. Configure thresholds for:
   - Coverage percentage
   - Duplicated code percentage
   - Code smells
   - Security hotspots

### Team Setup
1. Invite team members to SonarCloud organization
2. Configure notification settings
3. Set up quality gate alerts

### Advanced Configuration
1. Customize analysis rules
2. Configure issue tracking
3. Set up branch analysis
4. Enable security scanning

## Benefits

### Code Quality
- Automated code review
- Bug detection
- Security vulnerability scanning
- Code smell identification

### Team Collaboration
- Shared quality standards
- Historical trend analysis
- Pull request quality gates
- Team performance metrics

### Continuous Improvement
- Coverage tracking over time
- Quality trend analysis
- Technical debt monitoring
- Performance optimization insights 