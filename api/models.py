"""Pydantic models for API request and response validation."""

from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    """Health check response."""
    status: str = Field(..., description="API health status")
    version: str = Field(..., description="API version")


class BuildRequest(BaseModel):
    """Request model for building an attack range."""
    template: Optional[str] = Field(None, description="Template name or path (e.g., 'aws/splunk_minimal_aws', 'splunk_minimal_aws.yml') - Required for new builds")
    attack_range_id: Optional[str] = Field(None, description="Attack range ID to continue building (for phase 2 after VPN connection)")
    cloud_overrides: Optional[Dict[str, Dict[str, Any]]] = Field(
        None,
        description="Cloud-specific values to inject into config when copying template to configs (e.g. {\"azure\": {\"location\": \"West Europe\", \"subscription_id\": \"xxx\"}})"
    )
    general_overrides: Optional[Dict[str, Any]] = Field(
        None,
        description="General config values to inject (e.g. {\"ip_whitelist\": \"1.2.3.4/32\", \"attack_range_password\": \"...\"})"
    )

    class Config:
        json_schema_extra = {
            "examples": [
                {
                    "template": "aws/splunk_minimal_aws"
                },
                {
                    "template": "azure/splunk_es_azure",
                    "cloud_overrides": {"azure": {"location": "West Europe", "subscription_id": "your-subscription-id"}}
                },
                {
                    "attack_range_id": "550e8400-e29b-41d4-a716-446655440000"
                }
            ]
        }


class BuildResponse(BaseModel):
    """Response model for build operation."""
    status: str = Field(..., description="Build operation status")
    message: str = Field(..., description="Status message")
    attack_range_id: str = Field(..., description="Attack range ID (use this to continue build after VPN connection and check status)")
    phase: str = Field(..., description="Build phase (vpn or lab)")


class DestroyRequest(BaseModel):
    """Request model for destroying an attack range."""
    attack_range_id: str = Field(..., description="Attack range ID to destroy")

    class Config:
        json_schema_extra = {
            "example": {
                "attack_range_id": "550e8400-e29b-41d4-a716-446655440000"
            }
        }


class DestroyResponse(BaseModel):
    """Response model for destroy operation."""
    status: str = Field(..., description="Destroy operation status")
    message: str = Field(..., description="Status message")


class OperationStatusResponse(BaseModel):
    """Response model for operation status."""
    type: str = Field(..., description="Operation type (build or destroy)")
    status: str = Field(..., description="Operation status (queued, build_vpn, wait_for_vpn, build_lab, running, completed, failed, error)")
    created_time: str = Field(..., description="Time when operation was created")
    start_time: Optional[str] = Field(None, description="Time when operation started")
    end_time: Optional[str] = Field(None, description="Time when operation ended")
    attack_range_id: Optional[str] = Field(None, description="Attack range ID")
    attack_range_name: Optional[str] = Field(None, description="Attack range name (from general.attack_range_name)")
    template_name: Optional[str] = Field(None, description="Template name used for this attack range")
    router_public_ip: Optional[str] = Field(None, description="Router public IP address")
    wireguard_config: Optional[str] = Field(None, description="WireGuard VPN configuration (available during wait_for_vpn status)")
    wireguard_config_path: Optional[str] = Field(None, description="Path to WireGuard config file")
    sharing: Optional[Dict[str, str]] = Field(None, description="Shared WireGuard configs: name -> config (from general.sharing)")
    result: Optional[Dict[str, Any]] = Field(None, description="Operation result (for completed operations)")
    error: Optional[str] = Field(None, description="Error message (for failed operations)")
    error_phase: Optional[str] = Field(None, description="Build phase where error occurred")
    traceback: Optional[str] = Field(None, description="Error traceback (for failed operations)")


class ServerInfo(BaseModel):
    """Server information from template architecture."""
    name: str = Field(..., description="Server name")
    instance_type: Optional[str] = Field(None, description="Cloud instance type")
    ip_last_octet: Optional[int] = Field(None, description="Last octet of IP address")
    os_type: Optional[str] = Field(None, description="Operating system type (linux/windows)")
    roles: Optional[List[str]] = Field(None, description="List of Ansible roles")
    zeek: Optional[bool] = Field(None, description="Whether Zeek is installed")
    zeek_monitor: Optional[bool] = Field(None, description="Whether server is monitored by Zeek")


class TemplateInfo(BaseModel):
    """Template information."""
    name: str = Field(..., description="Template filename")
    provider: str = Field(..., description="Cloud provider (aws, azure, gcp)")
    path: str = Field(..., description="Full path to template file")
    description: Optional[str] = Field(None, description="Template description from general section")
    architecture: Optional[List[ServerInfo]] = Field(None, description="List of servers in the template architecture")


class TemplateListResponse(BaseModel):
    """Response model for template list."""
    templates: List[TemplateInfo] = Field(..., description="List of available templates")


class TemplateContentResponse(BaseModel):
    """Response model for template content."""
    name: str = Field(..., description="Template filename")
    provider: str = Field(..., description="Cloud provider")
    content: Dict[str, Any] = Field(..., description="Template configuration content")


class ConfigInfo(BaseModel):
    """Saved configuration information."""
    attack_range_id: str = Field(..., description="Attack range ID (filename without extension)")
    path: str = Field(..., description="Full path to config file")
    modified_time: Optional[str] = Field(None, description="Last modified timestamp")


class ConfigListResponse(BaseModel):
    """Response model for config list."""
    configs: List[ConfigInfo] = Field(..., description="List of saved configurations")


class ConfigContentResponse(BaseModel):
    """Response model for config content."""
    attack_range_id: str = Field(..., description="Attack range ID")
    content: Dict[str, Any] = Field(..., description="Configuration content")


class ErrorResponse(BaseModel):
    """Error response model."""
    status: str = Field("error", description="Status indicator")
    message: str = Field(..., description="Error message")
    details: Optional[str] = Field(None, description="Additional error details")


# Path parameter models
class AttackRangeIdPath(BaseModel):
    """Path parameter for attack range ID."""
    attack_range_id: str = Field(..., description="Attack range ID")


class TemplatePath(BaseModel):
    """Path parameters for template."""
    provider: str = Field(..., description="Cloud provider (aws, azure, gcp)")
    name: str = Field(..., description="Template name")


class CloudFieldsProviderPath(BaseModel):
    """Path parameter for cloud-fields endpoint (provider only)."""
    provider: str = Field(..., description="Cloud provider (aws, azure, gcp)")


class ConfigIdPath(BaseModel):
    """Path parameter for config ID."""
    config_id: str = Field(..., description="Configuration ID")


class AttackRangeListResponse(BaseModel):
    """Response model for attack range list."""
    attack_ranges: List[OperationStatusResponse] = Field(..., description="List of attack ranges with their status")


class ProviderAvailability(BaseModel):
    """Provider CLI availability information."""
    provider: str = Field(..., description="Cloud provider name (aws, azure, gcp, ludus)")
    available: bool = Field(..., description="Whether the CLI is installed and available")
    cli_command: str = Field(..., description="CLI command name (aws, az, gcloud)")
    error_message: Optional[str] = Field(None, description="Error message if CLI is not available")


class ProviderCheckResponse(BaseModel):
    """Response model for provider CLI check."""
    providers: List[ProviderAvailability] = Field(..., description="List of provider availability status")


class SimulateRequest(BaseModel):
    """Request model for running Atomic Red Team simulation."""
    attack_range_id: str = Field(..., description="Attack range ID")
    target: str = Field(..., description="Target server name (must match a server name in attack_range config)")
    techniques: List[str] = Field(..., description="List of MITRE ATT&CK technique IDs (e.g., ['T1003.001', 'T1059.003'])")

    class Config:
        json_schema_extra = {
            "example": {
                "attack_range_id": "550e8400-e29b-41d4-a716-446655440000",
                "target": "windows_server",
                "techniques": ["T1003.001", "T1059.003"]
            }
        }


class SimulateResponse(BaseModel):
    """Response model for simulation operation."""
    status: str = Field(..., description="Simulation status")
    message: str = Field(..., description="Status message")
    attack_range_id: str = Field(..., description="Attack range ID")
    target: str = Field(..., description="Target server name")
    techniques: List[str] = Field(..., description="List of techniques that were executed")
    execution_output: Optional[Dict[str, Any]] = Field(None, description="Execution output from Atomic Red Team tests")


class ShareRequest(BaseModel):
    """Request model for sharing an attack range (generate new WireGuard config)."""
    attack_range_id: str = Field(..., description="Attack range ID")
    name: str = Field(..., description="Share name (e.g. 'alice') — used as the new WireGuard client name")

    class Config:
        json_schema_extra = {
            "example": {
                "attack_range_id": "550e8400-e29b-41d4-a716-446655440000",
                "name": "alice"
            }
        }


class ShareResponse(BaseModel):
    """Response model for share operation."""
    name: str = Field(..., description="Share name")
    config: str = Field(..., description="WireGuard configuration for the shared client")
    message: str = Field(..., description="Status message")


class UpdateNameRequest(BaseModel):
    """Request model for updating attack range name."""
    attack_range_id: str = Field(..., description="Attack range ID")
    attack_range_name: str = Field(..., description="New attack range name")

    class Config:
        json_schema_extra = {
            "example": {
                "attack_range_id": "550e8400-e29b-41d4-a716-446655440000",
                "attack_range_name": "My Attack Range"
            }
        }


class UpdateNameResponse(BaseModel):
    """Response model for update name operation."""
    status: str = Field(..., description="Operation status")
    message: str = Field(..., description="Status message")
    attack_range_id: str = Field(..., description="Attack range ID")
    attack_range_name: str = Field(..., description="Updated attack range name")


class ImportLudusRequest(BaseModel):
    """Request model for importing an already-deployed Ludus range."""
    template: Optional[str] = Field(None, description="Template name (optional; if omitted Ludus is queried for the range config)")
    ludus_url: Optional[str] = Field(None, description="Ludus API URL (e.g. https://198.51.100.1:8080)")
    attack_range_password: Optional[str] = Field(None, description="Attack range password (default: changeme123!)")

    class Config:
        json_schema_extra = {
            "examples": [
                {"template": "ludus/splunk_minimal_ludus"},
                {"ludus_url": "https://10.0.0.5:8080"},
                {}
            ]
        }


class ImportLudusResponse(BaseModel):
    """Response model for Ludus import operation."""
    status: str = Field(..., description="Operation status")
    message: str = Field(..., description="Status message")
    attack_range_id: str = Field(..., description="Imported attack range ID")
    ludus_url: Optional[str] = Field(None, description="Ludus API URL")
    wireguard_config: Optional[str] = Field(None, description="WireGuard configuration (if retrieved)")
