"""
Backend manager for Attack Range.

This module handles Terraform remote backend setup, including creation and cleanup
of cloud storage resources for state management.
"""

import os
import sys
import logging
from typing import Tuple


class BackendManager:
    """Manages Terraform remote backend operations."""

    def __init__(self, terraform_dir: str, config: dict, config_path: str, cloud_provider, logger: logging.Logger):
        """
        Initialize the backend manager.

        :param terraform_dir: Directory containing Terraform configuration
        :param config: Configuration dictionary
        :param config_path: Path to config file (for backend.tf comments)
        :param cloud_provider: Cloud provider instance (AWSProvider, AzureProvider, or GCPProvider)
        :param logger: Logger instance
        """
        self.terraform_dir = terraform_dir
        self.config = config
        self.config_path = config_path
        self.cloud_provider = cloud_provider
        self.logger = logger
        self.cloud_provider_name = config.get("general", {}).get("cloud_provider", "aws").lower()

    def setup_remote_backend(self) -> bool:
        """
        Check if remote backend exists, otherwise create it.
        For AWS: S3 bucket (with S3 native locking)
        For Azure: Storage Account + Container
        For GCP: GCS bucket
        Uses attack_range_id for naming the backend resources.

        Returns:
            bool: True if backend resources were just created (fresh setup), False if they already existed
        """
        attack_range_id = self.config.get("general", {}).get("attack_range_id")
        if not attack_range_id:
            self.logger.error("attack_range_id not found in config. Cannot setup remote backend.")
            sys.exit(1)

        backend_was_created = False

        if self.cloud_provider_name == "ludus":
            # Ludus does not use a remote Terraform backend
            self.logger.info("Ludus: no remote backend required -- skipping")
            return False

        if self.cloud_provider_name == "gcp":
            backend_name = f"terraform-state-{attack_range_id}"
            bucket_name = self.cloud_provider.sanitize_name(backend_name)
            project_id = self.cloud_provider.get_project_id(required=True)
            region = self.cloud_provider.get_region(required=True)

            self.logger.info(f"Setting up GCP remote backend: bucket={bucket_name}")

            # Check and create GCS bucket if needed
            if not self.cloud_provider.check_gcs_bucket(bucket_name, project_id):
                self.logger.info(f"GCS bucket '{bucket_name}' does not exist. Creating it...")
                self.cloud_provider.create_gcs_bucket(bucket_name, project_id, region)
                backend_was_created = True
            else:
                self.logger.info(f"GCS bucket '{bucket_name}' already exists")

            # Update backend configuration in backend.tf
            self._update_backend_config_gcp(bucket_name, project_id, attack_range_id)

            self.logger.info("GCP remote backend setup completed successfully")
            return backend_was_created

        elif self.cloud_provider_name == "azure":
            backend_name = f"terraformstate{attack_range_id.replace('-', '')}"
            storage_account_name = self.cloud_provider.sanitize_name(backend_name)
            container_name = "tfstate"
            resource_group_name = f"rg-terraform-state-{attack_range_id}"
            location = self.cloud_provider.get_region(required=True)

            self.logger.info(f"Setting up Azure remote backend: storage_account={storage_account_name}, container={container_name}")

            # Check and create storage account if needed
            if not self.cloud_provider.check_storage_account(storage_account_name, resource_group_name):
                self.logger.info(f"Azure Storage Account '{storage_account_name}' does not exist. Creating it...")
                self.cloud_provider.create_storage_account(storage_account_name, resource_group_name, location)
                backend_was_created = True
            else:
                self.logger.info(f"Azure Storage Account '{storage_account_name}' already exists")

            # Check and create container if needed
            if not self.cloud_provider.check_storage_container(storage_account_name, container_name, resource_group_name):
                self.logger.info(f"Azure Storage Container '{container_name}' does not exist. Creating it...")
                self.cloud_provider.create_storage_container(storage_account_name, container_name, resource_group_name)
                backend_was_created = True
            else:
                self.logger.info(f"Azure Storage Container '{container_name}' already exists")

            # Update backend configuration in backend.tf
            self._update_backend_config_azure(storage_account_name, container_name, resource_group_name, location, attack_range_id)

            self.logger.info("Azure remote backend setup completed successfully")
            return backend_was_created

        else:  # aws
            backend_name = f"terraform-state-{attack_range_id}"
            bucket_name = self.cloud_provider.sanitize_name(backend_name)
            region = self.cloud_provider.get_region(required=True)

            self.logger.info(f"Setting up remote backend: bucket={bucket_name}")

            # Check and create S3 bucket if needed
            if not self.cloud_provider.check_s3_bucket(bucket_name, region):
                self.logger.info(f"S3 bucket '{bucket_name}' does not exist. Creating it...")
                self.cloud_provider.create_s3_bucket(bucket_name, region)
                backend_was_created = True
            else:
                self.logger.info(f"S3 bucket '{bucket_name}' already exists")

            # Update backend configuration in backend.tf
            self._update_backend_config_aws(bucket_name, region, attack_range_id)

            self.logger.info("Remote backend setup completed successfully")
            return backend_was_created

    def cleanup_remote_backend(self) -> None:
        """
        Clean up remote backend resources (S3 bucket for AWS,
        Storage Account for Azure, GCS bucket for GCP).
        Uses attack_range_id for naming the backend resources.
        """
        attack_range_id = self.config.get("general", {}).get("attack_range_id")
        if not attack_range_id:
            self.logger.warning("attack_range_id not found in config. Cannot cleanup remote backend.")
            return

        if self.cloud_provider_name == "ludus":
            self.logger.info("Ludus: no remote backend to clean up")
            return

        if self.cloud_provider_name == "gcp":
            backend_name = f"terraform-state-{attack_range_id}"
            bucket_name = self.cloud_provider.sanitize_name(backend_name)
            project_id = self.cloud_provider.get_project_id(required=False)

            if not project_id:
                self.logger.warning("GCP project_id not found in config. Cannot cleanup remote backend.")
                return

            self.logger.info(f"Cleaning up GCP remote backend: bucket={bucket_name}")
            self.cloud_provider.delete_gcs_bucket(bucket_name, project_id)
            self.logger.info("GCP remote backend cleanup completed successfully")

        elif self.cloud_provider_name == "azure":
            backend_name = f"terraformstate{attack_range_id.replace('-', '')}"
            storage_account_name = self.cloud_provider.sanitize_name(backend_name)
            resource_group_name = f"rg-terraform-state-{attack_range_id}"
            location = self.cloud_provider.get_region(required=False)

            if not location:
                self.logger.warning("Azure location not found in config. Cannot cleanup remote backend.")
                return

            self.logger.info(f"Cleaning up Azure remote backend: storage_account={storage_account_name}")
            self.cloud_provider.delete_backend(backend_name, location)
            self.logger.info("Azure remote backend cleanup completed successfully")

        else:  # aws
            backend_name = f"terraform-state-{attack_range_id}"
            bucket_name = self.cloud_provider.sanitize_name(backend_name)
            region = self.cloud_provider.get_region(required=False)

            if not region:
                self.logger.warning("AWS region not found in config. Cannot cleanup remote backend.")
                return

            self.logger.info(f"Cleaning up remote backend: bucket={bucket_name}")
            self.cloud_provider.delete_s3_bucket(bucket_name, region)
            self.logger.info("Remote backend cleanup completed successfully")

    def _update_backend_config_aws(self, bucket_name: str, region: str, attack_range_id: str) -> None:
        """
        Update or create backend.tf file with S3 backend configuration.

        :param bucket_name: Name of the S3 bucket for state storage
        :param region: AWS region
        :param attack_range_id: Attack range ID
        """
        backend_tf_path = os.path.join(self.terraform_dir, "backend.tf")

        # Build comment header with config file info if available
        config_source = "template/config file"
        if self.config_path:
            config_source = os.path.basename(self.config_path)

        backend_params = {
            'bucket_name': bucket_name,
            'region': region,
            'attack_range_id': attack_range_id,
            'config_source': config_source
        }

        self.cloud_provider.update_backend_config(backend_params, backend_tf_path)

    def _update_backend_config_azure(self, storage_account_name: str, container_name: str, resource_group_name: str, location: str, attack_range_id: str) -> None:
        """
        Update or create backend.tf file with Azure backend configuration.

        :param storage_account_name: Name of the Azure Storage Account for state storage
        :param container_name: Name of the Azure Storage Container
        :param resource_group_name: Name of the resource group
        :param location: Azure location
        :param attack_range_id: Attack range ID
        """
        backend_tf_path = os.path.join(self.terraform_dir, "backend.tf")

        # Build comment header with config file info if available
        config_source = "template/config file"
        if self.config_path:
            config_source = os.path.basename(self.config_path)

        backend_params = {
            'storage_account_name': storage_account_name,
            'container_name': container_name,
            'resource_group_name': resource_group_name,
            'location': location,
            'attack_range_id': attack_range_id,
            'config_source': config_source
        }

        self.cloud_provider.update_backend_config(backend_params, backend_tf_path)

    def _update_backend_config_gcp(self, bucket_name: str, project_id: str, attack_range_id: str) -> None:
        """
        Update or create backend.tf file with GCP backend configuration.

        :param bucket_name: Name of the GCS bucket for state storage
        :param project_id: GCP project ID
        :param attack_range_id: Attack range ID
        """
        backend_tf_path = os.path.join(self.terraform_dir, "backend.tf")

        # Build comment header with config file info if available
        config_source = "template/config file"
        if self.config_path:
            config_source = os.path.basename(self.config_path)

        backend_params = {
            'bucket_name': bucket_name,
            'project_id': project_id,
            'attack_range_id': attack_range_id,
            'config_source': config_source
        }

        self.cloud_provider.update_backend_config(backend_params, backend_tf_path)
