"""
Cloud-specific configuration fields for attack range templates.

Defines required/optional fields per provider and fixed option lists for dropdowns
(locations, regions, zones). Used by the API and app when building from a template.
"""

from typing import Any, Dict, List

# AWS regions (common subset; Terraform supports any valid AWS region)
AWS_REGIONS = [
    "eu-central-1",
    "eu-west-1",
    "eu-west-2",
    "eu-north-1",
    "us-east-1",
    "us-east-2",
    "us-west-1",
    "us-west-2",
    "ap-southeast-1",
    "ap-southeast-2",
    "ap-northeast-1",
    "ap-northeast-2",
    "sa-east-1",
]

# Azure locations (display names as used in templates and Terraform)
AZURE_LOCATIONS = [
    "East US",
    "East US 2",
    "West US",
    "West US 2",
    "West US 3",
    "West Europe",
    "North Europe",
    "Central US",
    "South Central US",
    "UK South",
    "France Central",
    "Germany West Central",
    "Switzerland North",
    "Southeast Asia",
    "East Asia",
    "Australia East",
    "Canada Central",
    "Brazil South",
]

# GCP regions and zones (region -> list of zones for dependent dropdown)
# Format: list of (region, zone) for flat zone list, or we expose region and zone separately
GCP_REGIONS = [
    "europe-west1",
    "europe-west2",
    "europe-west3",
    "europe-west4",
    "europe-north1",
    "europe-central2",
    "us-central1",
    "us-east1",
    "us-east4",
    "us-west1",
    "us-west2",
    "us-west3",
    "us-west4",
    "asia-southeast1",
    "asia-northeast1",
    "australia-southeast1",
]

GCP_ZONES_BY_REGION: Dict[str, List[str]] = {
    "europe-west1": ["europe-west1-b", "europe-west1-c", "europe-west1-d"],
    "europe-west2": ["europe-west2-a", "europe-west2-b", "europe-west2-c"],
    "europe-west3": ["europe-west3-a", "europe-west3-b", "europe-west3-c"],
    "europe-west4": ["europe-west4-a", "europe-west4-b", "europe-west4-c"],
    "europe-north1": ["europe-north1-a", "europe-north1-b", "europe-north1-c"],
    "europe-central2": ["europe-central2-a", "europe-central2-b", "europe-central2-c"],
    "us-central1": ["us-central1-a", "us-central1-b", "us-central1-c", "us-central1-f"],
    "us-east1": ["us-east1-b", "us-east1-c", "us-east1-d"],
    "us-east4": ["us-east4-a", "us-east4-b", "us-east4-c"],
    "us-west1": ["us-west1-a", "us-west1-b", "us-west1-c"],
    "us-west2": ["us-west2-a", "us-west2-b", "us-west2-c"],
    "us-west3": ["us-west3-a", "us-west3-b", "us-west3-c"],
    "us-west4": ["us-west4-a", "us-west4-b", "us-west4-c"],
    "asia-southeast1": ["asia-southeast1-a", "asia-southeast1-b", "asia-southeast1-c"],
    "asia-northeast1": ["asia-northeast1-a", "asia-northeast1-b", "asia-northeast1-c"],
    "australia-southeast1": ["australia-southeast1-a", "australia-southeast1-b", "australia-southeast1-c"],
}


def _aws_schema() -> Dict[str, Any]:
    return {
        "region": {
            "label": "Region",
            "type": "select",
            "options": AWS_REGIONS,
            "required": True,
        },
    }


def _azure_schema() -> Dict[str, Any]:
    return {
        "location": {
            "label": "Location",
            "type": "select",
            "options": AZURE_LOCATIONS,
            "required": True,
        },
        "subscription_id": {
            "label": "Subscription ID",
            "type": "text",
            "required": True,
        },
    }


def _gcp_schema() -> Dict[str, Any]:
    return {
        "project_id": {
            "label": "Project ID",
            "type": "text",
            "required": True,
        },
        "region": {
            "label": "Region",
            "type": "select",
            "options": GCP_REGIONS,
            "required": True,
        },
        "zone": {
            "label": "Zone",
            "type": "select",
            "options_from_region": True,
            "required": True,
        },
    }


def _ludus_schema() -> Dict[str, Any]:
    return {
        "ludus_url": {
            "label": "Ludus API URL",
            "type": "text",
            "required": False,
            "placeholder": "https://198.51.100.1:8080",
            "help_text": "Ludus server API URL (defaults to https://198.51.100.1:8080)",
        },
    }


def get_cloud_fields_schema(provider: str) -> Dict[str, Any]:
    """Return the cloud-specific fields schema for a provider (for dropdowns and labels)."""
    provider = (provider or "").lower()
    if provider == "aws":
        return _aws_schema()
    if provider == "azure":
        return _azure_schema()
    if provider == "gcp":
        return _gcp_schema()
    if provider == "ludus":
        return _ludus_schema()
    return {}


def get_gcp_zones_for_region(region: str) -> List[str]:
    """Return list of zones for a GCP region (for dependent dropdown)."""
    return GCP_ZONES_BY_REGION.get(region, [])
