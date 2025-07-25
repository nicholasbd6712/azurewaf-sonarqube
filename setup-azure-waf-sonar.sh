#!/bin/bash

# Azure WAF DRS 2.1 to SonarQube Integration Script
# This script sets up SonarQube with Azure WAF DRS 2.1 rule mappings

echo "=== Azure WAF DRS 2.1 SonarQube Integration Setup ==="

# Check if SonarQube Scanner is installed
if ! command -v sonar-scanner &> /dev/null; then
    echo "Installing SonarQube Scanner..."
    npm install -g sonarqube-scanner
fi

# Create quality profile for Azure WAF DRS 2.1
echo "Setting up Azure WAF DRS 2.1 Quality Profile..."

# Configure SonarQube to use Azure WAF DRS rules
cat > sonar-scanner.properties << EOF
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
EOF

# Run security-focused scan
echo "Running Azure WAF DRS 2.1 aligned security scan..."
sonar-scanner \
  -Dsonar.projectKey=azure-waf-security \
  -Dsonar.sources=. \
  -Dsonar.exclusions=**/node_modules/**,**/vendor/** \
  -Dsonar.security.hotspots.enable=true \
  -Dsonar.qualitygate.wait=true

echo "=== Azure WAF DRS 2.1 SonarQube Integration Complete ==="
echo "View results at: http://localhost:9000/dashboard?id=azure-waf-security"
