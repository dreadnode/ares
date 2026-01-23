"""Tests for remote command execution via AWS SSM."""

import os
from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import TokenRetrievalError

from ares.core.remote import (
    CommandResult,
    K8sExecutor,
    LocalExecutor,
    SSMExecutor,
    SSOTokenExpiredError,
    get_executor,
    reset_executor,
    run_remote,
    validate_sso_credentials,
)


class TestCommandResult:
    """Tests for CommandResult dataclass."""

    def test_command_result_creation(self):
        """Test creating a CommandResult."""
        result = CommandResult(
            stdout="output",
            stderr="",
            return_code=0,
            success=True,
        )
        assert result.stdout == "output"
        assert result.stderr == ""
        assert result.return_code == 0
        assert result.success is True

    def test_output_property_no_stderr(self):
        """Test output property with no stderr."""
        result = CommandResult(stdout="output", stderr="", return_code=0, success=True)
        assert result.output == "output"

    def test_output_property_with_stderr(self):
        """Test output property with stderr."""
        result = CommandResult(stdout="output", stderr="error", return_code=1, success=False)
        assert result.output == "output\nerror"


class TestSSOTokenExpiredError:
    """Tests for SSOTokenExpiredError exception."""

    def test_exception_message(self):
        """Test exception message."""
        error = SSOTokenExpiredError("Token expired")
        assert str(error) == "Token expired"

    def test_exception_inheritance(self):
        """Test exception inherits from Exception."""
        error = SSOTokenExpiredError("Test")
        assert isinstance(error, Exception)


class TestSSMExecutorInit:
    """Tests for SSMExecutor initialization."""

    def test_init_defaults(self):
        """Test initialization with defaults."""
        executor = SSMExecutor()
        assert executor.profile == "lab"
        assert executor.region == "us-west-1"
        assert executor._instance_id is None
        assert executor._ssm_client is None
        assert executor._ec2_client is None

    def test_init_with_instance_id(self):
        """Test initialization with instance ID."""
        executor = SSMExecutor(instance_id="i-1234567890")
        assert executor._instance_id == "i-1234567890"

    def test_init_with_custom_profile(self):
        """Test initialization with custom profile."""
        executor = SSMExecutor(profile="custom", region="us-east-1")
        assert executor.profile == "custom"
        assert executor.region == "us-east-1"

    def test_init_with_instance_name(self):
        """Test initialization with instance name."""
        executor = SSMExecutor(instance_name="my-kali-box")
        assert executor._instance_name == "my-kali-box"

    def test_init_uses_env_var(self):
        """Test initialization uses environment variable."""
        with patch.dict(os.environ, {"ARES_KALI_INSTANCE": "env-kali-box"}):
            executor = SSMExecutor()
            assert executor._instance_name == "env-kali-box"


class TestSSMExecutorCreateSession:
    """Tests for SSMExecutor._create_session method."""

    def test_create_session_success(self):
        """Test successful session creation."""
        executor = SSMExecutor()

        mock_session = MagicMock()
        mock_credentials = MagicMock()
        mock_session.get_credentials.return_value = mock_credentials

        with patch("ares.core.remote.boto3.Session", return_value=mock_session):
            session = executor._create_session()

        assert session == mock_session
        mock_credentials.get_frozen_credentials.assert_called_once()

    def test_create_session_no_credentials(self):
        """Test session creation with no credentials."""
        executor = SSMExecutor()

        mock_session = MagicMock()
        mock_session.get_credentials.return_value = None

        with (
            patch("ares.core.remote.boto3.Session", return_value=mock_session),
            pytest.raises(SSOTokenExpiredError),
        ):
            executor._create_session()

    def test_create_session_token_error(self):
        """Test session creation handles token retrieval error."""
        executor = SSMExecutor()

        mock_session = MagicMock()
        mock_session.get_credentials.side_effect = TokenRetrievalError(
            provider="sso", error_msg="expired"
        )

        with (
            patch("ares.core.remote.boto3.Session", return_value=mock_session),
            pytest.raises(SSOTokenExpiredError),
        ):
            executor._create_session()


class TestSSMExecutorInvalidateClients:
    """Tests for SSMExecutor._invalidate_clients method."""

    def test_invalidate_clears_all(self):
        """Test invalidate clears all cached clients."""
        executor = SSMExecutor(instance_id="i-1234")
        executor._ssm_client = MagicMock()
        executor._ec2_client = MagicMock()

        executor._invalidate_clients()

        assert executor._ssm_client is None
        assert executor._ec2_client is None
        assert executor._instance_id is None


class TestSSMExecutorClientProperties:
    """Tests for SSMExecutor client properties."""

    def test_ssm_client_lazy_load(self):
        """Test SSM client is lazy-loaded."""
        executor = SSMExecutor()
        mock_session = MagicMock()
        mock_client = MagicMock()
        mock_session.client.return_value = mock_client
        mock_credentials = MagicMock()
        mock_session.get_credentials.return_value = mock_credentials

        with patch("ares.core.remote.boto3.Session", return_value=mock_session):
            client = executor.ssm_client

        assert client == mock_client
        mock_session.client.assert_called_with("ssm")

    def test_ec2_client_lazy_load(self):
        """Test EC2 client is lazy-loaded."""
        executor = SSMExecutor()
        mock_session = MagicMock()
        mock_client = MagicMock()
        mock_session.client.return_value = mock_client
        mock_credentials = MagicMock()
        mock_session.get_credentials.return_value = mock_credentials

        with patch("ares.core.remote.boto3.Session", return_value=mock_session):
            client = executor.ec2_client

        assert client == mock_client
        mock_session.client.assert_called_with("ec2")


class TestSSMExecutorInstanceIdProperty:
    """Tests for SSMExecutor.instance_id property."""

    def test_instance_id_returns_preset(self):
        """Test instance_id returns preset value."""
        executor = SSMExecutor(instance_id="i-preset")
        assert executor.instance_id == "i-preset"

    def test_instance_id_resolves_from_name(self):
        """Test instance_id resolves from instance name."""
        executor = SSMExecutor(instance_name="my-kali")

        mock_session = MagicMock()
        mock_client = MagicMock()
        mock_client.describe_instances.return_value = {
            "Reservations": [{"Instances": [{"InstanceId": "i-resolved"}]}]
        }
        mock_session.client.return_value = mock_client
        mock_credentials = MagicMock()
        mock_session.get_credentials.return_value = mock_credentials

        with patch("ares.core.remote.boto3.Session", return_value=mock_session):
            instance_id = executor.instance_id

        assert instance_id == "i-resolved"


class TestSSMExecutorResolveInstanceId:
    """Tests for SSMExecutor._resolve_instance_id method."""

    def test_resolve_no_instances_found(self):
        """Test resolution when no instances found."""
        executor = SSMExecutor(instance_name="nonexistent")

        mock_session = MagicMock()
        mock_client = MagicMock()
        mock_client.describe_instances.return_value = {"Reservations": []}
        mock_session.client.return_value = mock_client
        mock_credentials = MagicMock()
        mock_session.get_credentials.return_value = mock_credentials

        with (
            patch("ares.core.remote.boto3.Session", return_value=mock_session),
            pytest.raises(RuntimeError, match="No running instance found"),
        ):
            executor._resolve_instance_id()


class TestSSMExecutorRunCommand:
    """Tests for SSMExecutor.run_command method."""

    def test_run_command_success(self):
        """Test successful command execution."""
        executor = SSMExecutor(instance_id="i-test")

        mock_session = MagicMock()
        mock_ssm = MagicMock()
        mock_ssm.send_command.return_value = {"Command": {"CommandId": "cmd-123"}}
        mock_ssm.get_command_invocation.return_value = {
            "Status": "Success",
            "StandardOutputContent": "output",
            "StandardErrorContent": "",
            "ResponseCode": 0,
        }
        mock_session.client.return_value = mock_ssm
        mock_credentials = MagicMock()
        mock_session.get_credentials.return_value = mock_credentials

        with patch("ares.core.remote.boto3.Session", return_value=mock_session):
            result = executor.run_command("echo test")

        assert result.stdout == "output"
        assert result.return_code == 0
        assert result.success is True

    def test_run_command_list_input(self):
        """Test command execution with list input."""
        executor = SSMExecutor(instance_id="i-test")

        mock_session = MagicMock()
        mock_ssm = MagicMock()
        mock_ssm.send_command.return_value = {"Command": {"CommandId": "cmd-123"}}
        mock_ssm.get_command_invocation.return_value = {
            "Status": "Success",
            "StandardOutputContent": "output",
            "StandardErrorContent": "",
            "ResponseCode": 0,
        }
        mock_session.client.return_value = mock_ssm
        mock_credentials = MagicMock()
        mock_session.get_credentials.return_value = mock_credentials

        with patch("ares.core.remote.boto3.Session", return_value=mock_session):
            result = executor.run_command(["echo", "test"])

        assert result.success is True


class TestSSMExecutorWaitForCommand:
    """Tests for SSMExecutor._wait_for_command method."""

    def test_wait_timeout(self):
        """Test command timeout."""
        executor = SSMExecutor(instance_id="i-test")

        mock_session = MagicMock()
        mock_ssm = MagicMock()
        mock_ssm.get_command_invocation.return_value = {"Status": "InProgress"}
        mock_session.client.return_value = mock_ssm
        mock_credentials = MagicMock()
        mock_session.get_credentials.return_value = mock_credentials

        with (
            patch("ares.core.remote.boto3.Session", return_value=mock_session),
            patch("ares.core.remote.time.time") as mock_time,
            patch("ares.core.remote.time.sleep"),
        ):
            # Simulate timeout
            mock_time.side_effect = [0, 0, 10]  # start, elapsed check, timeout check

            result = executor._wait_for_command("cmd-123", timeout_seconds=5)

        assert result.success is False
        assert "timed out" in result.stderr.lower()

    def test_wait_command_failed(self):
        """Test handling failed command."""
        executor = SSMExecutor(instance_id="i-test")

        mock_session = MagicMock()
        mock_ssm = MagicMock()
        mock_ssm.get_command_invocation.return_value = {
            "Status": "Failed",
            "StandardOutputContent": "",
            "StandardErrorContent": "error message",
            "ResponseCode": 1,
        }
        mock_session.client.return_value = mock_ssm
        mock_credentials = MagicMock()
        mock_session.get_credentials.return_value = mock_credentials

        with (
            patch("ares.core.remote.boto3.Session", return_value=mock_session),
            patch("ares.core.remote.time.time", return_value=0),
        ):
            result = executor._wait_for_command("cmd-123", timeout_seconds=300)

        assert result.success is False
        assert result.return_code == 1


class TestLocalExecutorRunCommand:
    """Tests for LocalExecutor.run_command method."""

    def test_run_command_success(self):
        """Test successful command execution."""
        executor = LocalExecutor()

        mock_result = MagicMock()
        mock_result.stdout = "output"
        mock_result.stderr = ""
        mock_result.returncode = 0

        with patch("ares.core.remote.subprocess.run", return_value=mock_result) as mock_run:
            result = executor.run_command("echo test", working_directory="/tmp")

        assert result.success is True
        assert result.stdout == "output"
        mock_run.assert_called_once()
        args, kwargs = mock_run.call_args
        assert args[0] == "echo test"
        assert kwargs["shell"] is True
        assert kwargs["cwd"] == "/tmp"

    def test_run_command_list_input(self):
        """Test command execution with list input."""
        executor = LocalExecutor()

        mock_result = MagicMock()
        mock_result.stdout = "output"
        mock_result.stderr = ""
        mock_result.returncode = 0

        with patch("ares.core.remote.subprocess.run", return_value=mock_result) as mock_run:
            result = executor.run_command(["echo", "test"], working_directory="/workdir")

        assert result.success is True
        args, kwargs = mock_run.call_args
        assert args[0] == "echo test"
        assert kwargs["cwd"] == "/workdir"


class TestGetExecutor:
    """Tests for get_executor function."""

    def test_get_executor_creates_new(self):
        """Test get_executor creates new executor."""
        reset_executor()  # Clear any existing
        executor = get_executor()
        assert isinstance(executor, SSMExecutor)

    def test_get_executor_returns_same(self):
        """Test get_executor returns same instance."""
        reset_executor()  # Clear any existing
        executor1 = get_executor()
        executor2 = get_executor()
        assert executor1 is executor2


class TestResetExecutor:
    """Tests for reset_executor function."""

    def test_reset_clears_global(self):
        """Test reset clears global executor."""
        reset_executor()
        # After reset, should create new
        executor1 = get_executor()
        reset_executor()
        executor2 = get_executor()
        # Should be different instances
        assert executor1 is not executor2


class TestValidateSSOCredentials:
    """Tests for validate_sso_credentials function."""

    def test_validate_success(self):
        """Test successful validation."""
        mock_session = MagicMock()
        mock_credentials = MagicMock()
        mock_session.get_credentials.return_value = mock_credentials

        with patch("ares.core.remote.boto3.Session", return_value=mock_session):
            result = validate_sso_credentials("lab")

        assert result is True

    def test_validate_no_credentials(self):
        """Test validation with no credentials."""
        mock_session = MagicMock()
        mock_session.get_credentials.return_value = None

        with (
            patch("ares.core.remote.boto3.Session", return_value=mock_session),
            pytest.raises(SSOTokenExpiredError),
        ):
            validate_sso_credentials("lab")

    def test_validate_token_error(self):
        """Test validation with token error."""
        mock_session = MagicMock()
        mock_session.get_credentials.side_effect = TokenRetrievalError(
            provider="sso", error_msg="expired"
        )

        with (
            patch("ares.core.remote.boto3.Session", return_value=mock_session),
            pytest.raises(SSOTokenExpiredError),
        ):
            validate_sso_credentials("lab")


class TestRunRemote:
    """Tests for run_remote convenience function."""

    def test_run_remote_delegates_to_executor(self):
        """Test run_remote delegates to executor."""
        reset_executor()

        mock_session = MagicMock()
        mock_ssm = MagicMock()
        mock_ec2 = MagicMock()

        # Set up EC2 to return instance
        mock_ec2.describe_instances.return_value = {
            "Reservations": [{"Instances": [{"InstanceId": "i-test"}]}]
        }

        mock_ssm.send_command.return_value = {"Command": {"CommandId": "cmd-123"}}
        mock_ssm.get_command_invocation.return_value = {
            "Status": "Success",
            "StandardOutputContent": "result",
            "StandardErrorContent": "",
            "ResponseCode": 0,
        }

        def get_client(service):
            if service == "ssm":
                return mock_ssm
            return mock_ec2

        mock_session.client.side_effect = get_client
        mock_credentials = MagicMock()
        mock_session.get_credentials.return_value = mock_credentials

        with patch("ares.core.remote.boto3.Session", return_value=mock_session):
            result = run_remote("echo test")

        assert result.stdout == "result"
        assert result.success is True

        # Clean up
        reset_executor()

    def test_run_remote_passes_target_role(self):
        """Test run_remote forwards target_role to executor."""
        executor = MagicMock()
        executor.run_command.return_value = CommandResult(
            stdout="ok",
            stderr="",
            return_code=0,
            success=True,
        )

        with patch("ares.core.remote.get_executor", return_value=executor):
            result = run_remote("echo test", target_role="cracker")

        assert result.success is True
        executor.run_command.assert_called_once_with(
            "echo test",
            300,
            "/tmp",
            target_role="cracker",
        )

    def test_run_remote_routes_cross_role_in_local_mode(self):
        """Cross-role calls in local mode should use K8sExecutor."""
        executor = MagicMock()
        executor.run_command.side_effect = AssertionError("Unexpected executor call")
        k8s_result = CommandResult(
            stdout="ok",
            stderr="",
            return_code=0,
            success=True,
        )

        with (
            patch("ares.core.remote.get_execution_mode", return_value="local"),
            patch("ares.core.remote.get_executor", return_value=executor),
            patch("ares.core.remote.K8sExecutor") as mock_k8s,
            patch.dict(os.environ, {"ARES_ROLE": "recon"}, clear=False),
        ):
            mock_k8s.return_value.run_command.return_value = k8s_result
            result = run_remote("echo test", target_role="lateral")

        assert result is k8s_result
        mock_k8s.return_value.run_command.assert_called_once_with(
            "echo test",
            300,
            "/tmp",
            target_role="lateral",
        )
        executor.run_command.assert_not_called()


class TestK8sExecutorInit:
    """Tests for K8sExecutor initialization."""

    def test_init_uses_redis_url_env(self):
        """Test initialization uses REDIS_URL when set."""
        with patch.dict(os.environ, {"REDIS_URL": "redis://custom:6380"}, clear=False):
            executor = K8sExecutor()
            assert executor._redis_url == "redis://custom:6380"

    def test_init_builds_url_from_components(self):
        """Test initialization builds URL from component env vars."""
        env = {
            "REDIS_SERVICE_HOST": "myredis",
            "REDIS_SERVICE_PORT": "6380",
        }
        with patch.dict(os.environ, env, clear=True):
            executor = K8sExecutor()
            assert executor._redis_url == "redis://myredis:6380"

    def test_init_builds_url_with_password(self):
        """Test initialization builds URL with password."""
        env = {
            "REDIS_PASSWORD": "secret",  # pragma: allowlist secret
            "REDIS_SERVICE_HOST": "myredis",
            "REDIS_SERVICE_PORT": "6380",
        }
        with patch.dict(os.environ, env, clear=True):
            executor = K8sExecutor()
            assert executor._redis_url == "redis://:secret@myredis:6380"

    def test_init_uses_defaults_when_no_env(self):
        """Test initialization uses defaults when env vars not set."""
        with patch.dict(os.environ, {}, clear=True):
            executor = K8sExecutor()
            assert executor._redis_url == "redis://redis:6379"


class TestK8sExecutorRouting:
    """Tests for K8sExecutor role routing."""

    def test_run_command_uses_env_role_when_set(self):
        """Test run_command routes to ARES_ROLE by default."""
        executor = K8sExecutor()
        calls: list[dict[str, str]] = []

        async def fake_dispatch(command, timeout_seconds, working_directory, target_role):
            calls.append(
                {
                    "command": command,
                    "timeout": str(timeout_seconds),
                    "working_directory": working_directory,
                    "target_role": target_role,
                }
            )
            return CommandResult(stdout="ok", stderr="", return_code=0, success=True)

        executor._dispatch_command = fake_dispatch  # type: ignore[method-assign]

        with patch.dict(os.environ, {"ARES_ROLE": "cracker"}, clear=False):
            result = executor.run_command(["echo", "test"])

        assert result.success is True
        assert calls[0]["target_role"] == "cracker"

    def test_run_command_defaults_to_recon_without_role(self):
        """Test run_command defaults to recon when no role set."""
        executor = K8sExecutor()
        calls: list[dict[str, str]] = []

        async def fake_dispatch(command, timeout_seconds, working_directory, target_role):
            calls.append(
                {
                    "command": command,
                    "timeout": str(timeout_seconds),
                    "working_directory": working_directory,
                    "target_role": target_role,
                }
            )
            return CommandResult(stdout="ok", stderr="", return_code=0, success=True)

        executor._dispatch_command = fake_dispatch  # type: ignore[method-assign]

        with patch.dict(os.environ, {}, clear=True):
            result = executor.run_command(["echo", "test"])

        assert result.success is True
        assert calls[0]["target_role"] == "recon"

    def test_run_command_explicit_role_overrides_env(self):
        """Test run_command honors explicit target_role."""
        executor = K8sExecutor()
        calls: list[dict[str, str]] = []

        async def fake_dispatch(command, timeout_seconds, working_directory, target_role):
            calls.append(
                {
                    "command": command,
                    "timeout": str(timeout_seconds),
                    "working_directory": working_directory,
                    "target_role": target_role,
                }
            )
            return CommandResult(stdout="ok", stderr="", return_code=0, success=True)

        executor._dispatch_command = fake_dispatch  # type: ignore[method-assign]

        with patch.dict(os.environ, {"ARES_ROLE": "cracker"}, clear=False):
            result = executor.run_command(["echo", "test"], target_role="lateral")

        assert result.success is True
        assert calls[0]["target_role"] == "lateral"

    def test_run_command_invalid_role_returns_error(self):
        """Test run_command fails fast when role is invalid."""
        executor = K8sExecutor()
        executor._dispatch_command = MagicMock()  # type: ignore[method-assign]

        with patch.dict(os.environ, {"ARES_ROLE": "worker"}, clear=False):
            result = executor.run_command(["echo", "test"])

        assert result.success is False
        assert "Invalid target role" in result.stderr
        executor._dispatch_command.assert_not_called()
