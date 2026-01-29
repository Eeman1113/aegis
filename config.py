"""Application configuration for Enterprise Security & Regression Testing Platform."""
import os

APP_NAME = "AEGIS"
APP_NAME_JP = "\u30a4\u30fc\u30b8\u30b9"
APP_TITLE = "AEGIS \u2014 Enterprise Security & Regression Testing"

# AWS configuration — override via environment variables or .env
AWS_REGION = os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
AWS_PROFILE = os.environ.get("AWS_PROFILE", None)

AWS_REGIONS = [
    "us-east-1", "us-east-2", "us-west-1", "us-west-2",
    "eu-west-1", "eu-west-2", "eu-central-1",
    "ap-southeast-1", "ap-southeast-2", "ap-northeast-1",
]

QUARTERS = ["Q1", "Q2", "Q3", "Q4"]
YEARS = [2024, 2025, 2026]

SEVERITY_LEVELS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]
SEVERITY_COLORS = {
    "CRITICAL": "#dc3545",
    "HIGH": "#fd7e14",
    "MEDIUM": "#ffc107",
    "LOW": "#28a745",
    "INFORMATIONAL": "#6c757d",
}

STATUS_COLORS = {
    "PASSED": "#28a745",
    "FAILED": "#dc3545",
    "WARNING": "#ffc107",
    "NOT_AVAILABLE": "#6c757d",
}

COMPLIANCE_FRAMEWORKS = ["SOC2", "CIS AWS Benchmark", "HIPAA", "PCI-DSS", "NIST 800-53"]

TEST_CATEGORIES = [
    "Authentication & Authorization",
    "Data Encryption (at-rest & in-transit)",
    "Network Security & Segmentation",
    "IAM Policy & Least Privilege",
    "Logging & Monitoring",
    "Incident Response",
    "Backup & Disaster Recovery",
    "API Security",
    "Container & Runtime Security",
    "Compliance Controls",
]

DB_PATH = os.environ.get("REGRESSION_DB_PATH", "regression_tests.db")
