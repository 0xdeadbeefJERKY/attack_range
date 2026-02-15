"""
Tests for Ludus provider and backend manager integration.

Tests the LudusProvider class methods and verifies that the backend manager
correctly handles the Ludus no-op backend flow.
"""

import sys
from unittest.mock import MagicMock, patch

sys.modules["ansible_runner"] = MagicMock()
sys.modules["python_vagrant"] = MagicMock()

import logging
import os
import pytest

from attack_range.cloud_providers.ludus_provider import LudusProvider
from attack_range.managers.backend_manager import BackendManager


@pytest.fixture
def mock_logger():
    """Create a logger for testing."""
    logger = logging.getLogger("test_ludus")
    logger.setLevel(logging.DEBUG)
    return logger


@pytest.fixture
def ludus_config():
    """Sample Ludus config for testing."""
    return {
        "general": {
            "cloud_provider": "ludus",
            "attack_range_id": "test-range-ludus-123",
            "attack_range_password": "changeme123!",
            "attack_range_name": "ar",
        },
        "ludus": {
            "ludus_url": "https://198.51.100.1:8080",
            "vlan": 20,
        },
        "attack_range": [
            {
                "name": "splunk",
                "template": "debian-12-x64-server-template",
                "ram_gb": 16,
                "cpus": 8,
                "ip_last_octet": 10,
                "linux": True,
                "user_name": "debian",
                "roles": [
                    {
                        "role": "p4t12ick.ludus_ar_splunk",
                        "vars": {"ludus_ar_splunk_password": "changeme123!"},
                    }
                ],
            },
            {
                "name": "win",
                "template": "win2022-server-x64-template",
                "ram_gb": 8,
                "cpus": 4,
                "ip_last_octet": 11,
                "windows": True,
                "user_name": "localuser",
                "roles": [
                    {
                        "role": "p4t12ick.ludus_ar_windows",
                        "vars": {
                            "ludus_ar_windows_password": "changeme123!",
                            "ludus_ar_windows_splunk_ip": "10.0.2.10",
                        },
                    }
                ],
            },
        ],
    }


@pytest.fixture
def ludus_provider(ludus_config, mock_logger):
    """Create a LudusProvider instance for testing."""
    return LudusProvider(ludus_config, mock_logger)


@pytest.fixture
def ludus_backend_context(ludus_config, mock_logger, tmp_path):
    """Create a Ludus provider + backend manager test context."""
    provider = LudusProvider(ludus_config, mock_logger)
    manager = BackendManager(
        terraform_dir=str(tmp_path),
        config=ludus_config,
        config_path=str(tmp_path / "config.yml"),
        cloud_provider=provider,
        logger=mock_logger,
    )
    return {
        "provider": provider,
        "manager": manager,
        "tmp_path": tmp_path,
    }


class TestLudusProvider:
    """Tests for the LudusProvider class."""

    def test_get_region_returns_ludus_url(self, ludus_provider):
        """get_region should return the Ludus API URL."""
        region = ludus_provider.get_region()
        assert region == "https://198.51.100.1:8080"

    def test_get_region_default(self, mock_logger):
        """get_region should return default URL when not configured."""
        provider = LudusProvider({"general": {"cloud_provider": "ludus"}}, mock_logger)
        region = provider.get_region()
        assert region == "https://198.51.100.1:8080"

    def test_check_backend_exists_always_true(self, ludus_provider):
        """check_backend_exists should always return True for Ludus."""
        assert ludus_provider.check_backend_exists("any-name") is True

    def test_create_backend_noop(self, ludus_provider):
        """create_backend should be a no-op for Ludus."""
        ludus_provider.create_backend("test-backend", "us-east-1")
        # Should not raise

    def test_delete_backend_noop(self, ludus_provider):
        """delete_backend should be a no-op for Ludus."""
        ludus_provider.delete_backend("test-backend", "us-east-1")
        # Should not raise

    def test_sanitize_name(self, ludus_provider):
        """sanitize_name should produce valid lowercase names."""
        assert ludus_provider.sanitize_name("My_Range-123") == "my-range-123"
        assert ludus_provider.sanitize_name("TEST") == "test"
        assert ludus_provider.sanitize_name("a--b__c") == "a-b-c"
        assert ludus_provider.sanitize_name("") == "ludus"

    def test_import_ssh_key_noop(self, ludus_provider):
        """import_ssh_key should be a no-op for Ludus."""
        ludus_provider.import_ssh_key("key-name", "ssh-rsa AAAA...", "region")
        # Should not raise

    def test_delete_ssh_key_noop(self, ludus_provider):
        """delete_ssh_key should be a no-op for Ludus."""
        ludus_provider.delete_ssh_key("key-name", "region")
        # Should not raise

    def test_update_backend_config_writes_local_backend(self, ludus_provider, tmp_path):
        """update_backend_config should write a local backend.tf."""
        backend_file = tmp_path / "backend.tf"
        ludus_provider.update_backend_config(
            {"attack_range_id": "test-123", "config_source": "test.yml"},
            str(backend_file),
        )
        content = backend_file.read_text()
        assert 'backend "local"' in content
        assert "test-123" in content

    def test_get_ludus_url(self, ludus_provider):
        """get_ludus_url should return the configured URL."""
        assert ludus_provider.get_ludus_url() == "https://198.51.100.1:8080"


class TestLudusConfigConversion:
    """Tests for converting attack_range config to Ludus range config."""

    def test_convert_basic(self, ludus_provider, ludus_config):
        """Should convert attack_range config to Ludus range format."""
        result = ludus_provider.convert_to_ludus_config(ludus_config)
        assert "ludus" in result
        assert len(result["ludus"]) == 2

    def test_convert_linux_server(self, ludus_provider, ludus_config):
        """Linux servers should have linux: true in Ludus config."""
        result = ludus_provider.convert_to_ludus_config(ludus_config)
        splunk_vm = result["ludus"][0]
        assert splunk_vm["linux"] is True
        assert "windows" not in splunk_vm
        assert splunk_vm["template"] == "debian-12-x64-server-template"
        assert splunk_vm["ram_gb"] == 16
        assert splunk_vm["cpus"] == 8
        assert splunk_vm["ip_last_octet"] == 10
        assert splunk_vm["vlan"] == 20

    def test_convert_windows_server(self, ludus_provider, ludus_config):
        """Windows servers should have windows: {sysprep: true} in Ludus config."""
        result = ludus_provider.convert_to_ludus_config(ludus_config)
        win_vm = result["ludus"][1]
        assert win_vm["windows"] == {"sysprep": True}
        assert "linux" not in win_vm
        assert win_vm["template"] == "win2022-server-x64-template"

    def test_convert_roles(self, ludus_provider, ludus_config):
        """Roles should be extracted as lowercase names with vars."""
        result = ludus_provider.convert_to_ludus_config(ludus_config)
        splunk_vm = result["ludus"][0]
        assert "p4t12ick.ludus_ar_splunk" in splunk_vm["roles"]
        assert splunk_vm["role_vars"]["ludus_ar_splunk_password"] == "changeme123!"

    def test_convert_vm_name(self, ludus_provider, ludus_config):
        """VM names should use {{ range_id }} prefix."""
        result = ludus_provider.convert_to_ludus_config(ludus_config)
        splunk_vm = result["ludus"][0]
        assert splunk_vm["vm_name"] == "{{ range_id }}-splunk"
        assert splunk_vm["hostname"] == "{{ range_id }}-splunk"

    def test_convert_default_template(self, ludus_provider, mock_logger):
        """Should use default templates when not specified."""
        config = {
            "ludus": {"vlan": 20},
            "attack_range": [
                {"name": "test-linux", "ip_last_octet": 10, "linux": True},
                {"name": "test-win", "ip_last_octet": 11, "windows": True},
            ],
        }
        result = ludus_provider.convert_to_ludus_config(config)
        assert result["ludus"][0]["template"] == "debian-12-x64-server-template"
        assert result["ludus"][1]["template"] == "win2022-server-x64-template"


class TestLudusBackendManager:
    """Tests for BackendManager with Ludus provider."""

    def test_setup_remote_backend_returns_false(self, ludus_backend_context):
        """setup_remote_backend should return False (no backend created) for Ludus."""
        manager = ludus_backend_context["manager"]
        result = manager.setup_remote_backend()
        assert result is False

    def test_cleanup_remote_backend_noop(self, ludus_backend_context):
        """cleanup_remote_backend should be a no-op for Ludus."""
        manager = ludus_backend_context["manager"]
        manager.cleanup_remote_backend()
        # Should not raise


class TestLudusCliMethods:
    """Tests for Ludus CLI interaction methods (mocked)."""

    @patch("attack_range.cloud_providers.ludus_provider.subprocess.run")
    def test_get_range_status_success(self, mock_run, ludus_provider):
        """get_range_status should parse SUCCESS from JSON output."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='{"result": {"status": "SUCCESS"}}',
        )
        status = ludus_provider.get_range_status()
        assert status == "SUCCESS"

    @patch("attack_range.cloud_providers.ludus_provider.subprocess.run")
    def test_get_range_status_deploying(self, mock_run, ludus_provider):
        """get_range_status should parse DEPLOYING status."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='{"result": {"status": "DEPLOYING"}}',
        )
        status = ludus_provider.get_range_status()
        assert status == "DEPLOYING"

    @patch("attack_range.cloud_providers.ludus_provider.subprocess.run")
    def test_get_range_status_failure(self, mock_run, ludus_provider):
        """get_range_status should return UNKNOWN on CLI failure."""
        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="error")
        status = ludus_provider.get_range_status()
        assert status == "UNKNOWN"

    @patch("attack_range.cloud_providers.ludus_provider.subprocess.run")
    def test_get_wireguard_config(self, mock_run, ludus_provider):
        """get_wireguard_config should return config content."""
        wg_config = "[Interface]\nPrivateKey = abc123\nAddress = 198.51.100.2/24\n"
        mock_run.return_value = MagicMock(returncode=0, stdout=wg_config)
        result = ludus_provider.get_wireguard_config()
        assert result is not None
        assert "Interface" in result

    @patch("attack_range.cloud_providers.ludus_provider.subprocess.run")
    def test_get_wireguard_config_failure(self, mock_run, ludus_provider):
        """get_wireguard_config should return None on failure."""
        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="not found")
        result = ludus_provider.get_wireguard_config()
        assert result is None

    @patch("attack_range.cloud_providers.ludus_provider.subprocess.run")
    def test_deploy_range(self, mock_run, ludus_provider):
        """deploy_range should call ludus range deploy."""
        mock_run.return_value = MagicMock(returncode=0, stdout="Range deploy started")
        ludus_provider.deploy_range()
        # Verify the CLI was called with the correct args
        call_args = mock_run.call_args[0][0]
        assert "ludus" in call_args
        assert "range" in call_args
        assert "deploy" in call_args

    @patch("attack_range.cloud_providers.ludus_provider.subprocess.run")
    def test_destroy_range(self, mock_run, ludus_provider):
        """destroy_range should call ludus range rm."""
        mock_run.return_value = MagicMock(returncode=0, stdout="Range destroyed")
        ludus_provider.destroy_range()
        call_args = mock_run.call_args[0][0]
        assert "ludus" in call_args
        assert "range" in call_args
        assert "rm" in call_args

    @patch("attack_range.cloud_providers.ludus_provider.subprocess.run")
    def test_set_range_config(self, mock_run, ludus_provider):
        """set_range_config should write YAML and call ludus CLI."""
        mock_run.return_value = MagicMock(returncode=0, stdout="Config set")
        config = {"ludus": [{"vm_name": "test", "template": "test-template"}]}
        path = ludus_provider.set_range_config(config)
        assert os.path.exists(path)
        # Clean up
        os.unlink(path)

    @patch("attack_range.cloud_providers.ludus_provider.subprocess.run")
    def test_install_ansible_roles(self, mock_run, ludus_provider):
        """install_ansible_roles should call ludus ansible roles add."""
        mock_run.return_value = MagicMock(returncode=0, stdout="Role installed")
        ludus_provider.install_ansible_roles(["p4t12ick.ludus_ar_splunk"])
        call_args = mock_run.call_args[0][0]
        assert "ansible" in call_args
        assert "roles" in call_args
        assert "add" in call_args

    @patch("attack_range.cloud_providers.ludus_provider.subprocess.run")
    def test_wait_for_deployment_success(self, mock_run, ludus_provider):
        """wait_for_deployment should return when status is SUCCESS."""
        # First call: DEPLOYING, second call: SUCCESS
        mock_run.side_effect = [
            MagicMock(returncode=0, stdout='{"result": {"status": "DEPLOYING"}}'),
            MagicMock(returncode=0, stdout='{"result": {"status": "SUCCESS"}}'),
        ]
        ludus_provider.wait_for_deployment(timeout=60, poll_interval=0)

    @patch("attack_range.cloud_providers.ludus_provider.subprocess.run")
    def test_wait_for_deployment_error(self, mock_run, ludus_provider):
        """wait_for_deployment should raise on ERROR status."""
        mock_run.return_value = MagicMock(
            returncode=0, stdout='{"result": {"status": "ERROR"}}'
        )
        with pytest.raises(RuntimeError, match="failed"):
            ludus_provider.wait_for_deployment(timeout=10, poll_interval=0)

    @patch("attack_range.cloud_providers.ludus_provider.subprocess.run")
    def test_get_range_ips(self, mock_run, ludus_provider):
        """get_range_ips should parse VM IPs from status JSON."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='{"result": {"vms": [{"name": "splunk", "ip": "10.2.20.10"}]}}',
        )
        ips = ludus_provider.get_range_ips()
        assert ips.get("splunk") == "10.2.20.10"
