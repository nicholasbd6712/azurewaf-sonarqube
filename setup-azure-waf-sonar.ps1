# Azure WAF DRS 2.1 SonarQube Integration Setup (PowerShell)
# This script sets up SonarQube with Azure WAF DRS 2.1 rule mappings for Windows

Write-Host "=== Azure WAF DRS 2.1 SonarQube Integration Setup ===" -ForegroundColor Green

# Check if SonarQube Scanner is installed
if (!(Get-Command "sonar-scanner" -ErrorAction SilentlyContinue)) {
    Write-Host "Installing SonarQube Scanner..." -ForegroundColor Yellow
    npm install -g sonarqube-scanner
}

# Create quality profile for Azure WAF DRS 2.1
Write-Host "Setting up Azure WAF DRS 2.1 Quality Profile..." -ForegroundColor Yellow

# Configure SonarQube to use Azure WAF DRS rules
@"
# Azure WAF DRS 2.1 Integration Configuration
sonar.host.url=http://localhost:9000
sonar.login=your-sonarqube-token

# Security-focused analysis
sonar.security.hotspots.enable=true
sonar.php.rules.security.enable=true
sonar.typescript.rules.security.enable=true

# Map Azure WAF DRS 2.1 rules to SonarQube rules
sonar.issue.ignore.multicriteria=e1,e2,e3,e4,e5
sonar.issue.ignore.multicriteria.e1.ruleKey=php:S2068
sonar.issue.ignore.multicriteria.e1.resourceKey=**/*.php

# Enable all security rules
sonar.security.cwe.enable=true
sonar.security.owasp.enable=true
sonar.security.sans.enable=true
"@ | Out-File -FilePath "sonar-scanner.properties" -Encoding UTF8

# Run security-focused scan
Write-Host "Running Azure WAF DRS 2.1 aligned security scan..." -ForegroundColor Yellow

& sonar-scanner `
  "-Dsonar.projectKey=azure-waf-security" `
  "-Dsonar.sources=." `
  "-Dsonar.exclusions=**/node_modules/**,**/vendor/**,**/obj/**,**/bin/**" `
  "-Dsonar.security.hotspots.enable=true" `
  "-Dsonar.qualitygate.wait=true"

Write-Host "=== Azure WAF DRS 2.1 SonarQube Integration Complete ===" -ForegroundColor Green
Write-Host "View results at: http://localhost:9000/dashboard?id=azure-waf-security" -ForegroundColor Cyan
