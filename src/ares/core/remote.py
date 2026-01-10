"""Remote command execution via AWS SSM.

This module provides functionality to execute commands on remote EC2 instances
(specifically the Kali attack box) using AWS Systems Manager (SSM).
"""

import os
import time
from dataclasses import dataclass
from typing import Any, NoReturn

import boto3
from botocore.exceptions import ClientError, SSOTokenLoadError, TokenRetrievalError
from loguru import logger


class SSOTokenExpiredError(Exception):
    """Raised when AWS SSO token has expired and needs refresh."""


@dataclass
class CommandResult:
    """Result of a remote command execution."""

    stdout: str
    stderr: str
    return_code: int
    success: bool

    @property
    def output(self) -> str:
        """Combined stdout and stderr output."""
        if self.stderr:
            return f"{self.stdout}\n{self.stderr}"
        return self.stdout


class SSMExecutor:
    """Execute commands on remote EC2 instances via AWS SSM.

    This class handles command execution on the Kali attack box using
    AWS Systems Manager send-command API.

    Attributes:
        instance_id: EC2 instance ID of the target (Kali box)
        profile: AWS profile name for authentication
        region: AWS region
    """

    def __init__(
        self,
        instance_id: str | None = None,
        instance_name: str | None = None,
        profile: str = "lab",
        region: str = "us-west-1",
    ):
        """Initialize the SSM executor.

        Args:
            instance_id: EC2 instance ID (if known)
            instance_name: EC2 instance Name tag to resolve to instance ID
            profile: AWS profile name
            region: AWS region
        """
        self.profile = profile
        self.region = region
        self._instance_id = instance_id
        self._instance_name = instance_name or os.environ.get(
            "ARES_KALI_INSTANCE", "staging-alpha-operator-range-kali"
        )
        self._ssm_client: Any = None
        self._ec2_client: Any = None

    def _create_session(self) -> boto3.Session:
        """Create a boto3 session, validating SSO token first."""
        try:
            session = boto3.Session(profile_name=self.profile, region_name=self.region)
            # Force credential resolution to catch SSO errors early
            credentials = session.get_credentials()
            if credentials is None:
                raise SSOTokenExpiredError(  # noqa: TRY301
                    f"No credentials available for profile '{self.profile}'. "
                    f"Run: aws sso login --profile {self.profile}"
                )
            # Try to actually use the credentials to validate them
            credentials.get_frozen_credentials()
            return session
        except (TokenRetrievalError, SSOTokenLoadError) as e:
            self._handle_sso_error(e)
        except Exception as e:
            if "token" in str(e).lower() and (
                "expired" in str(e).lower() or "sso" in str(e).lower()
            ):
                self._handle_sso_error(e)
            raise

    def _handle_sso_error(self, original_error: Exception) -> NoReturn:
        """Handle SSO token errors with helpful message and optional auto-refresh."""
        error_msg = (
            f"\n{'=' * 60}\n"
            f"AWS SSO TOKEN EXPIRED\n"
            f"{'=' * 60}\n"
            f"Your AWS SSO session has expired.\n\n"
            f"To fix this, run:\n"
            f"    aws sso login --profile {self.profile}\n\n"
            f"Original error: {original_error}\n"
            f"{'=' * 60}\n"
        )
        logger.error(error_msg)

        # Clear cached clients so next attempt will re-authenticate
        self._invalidate_clients()

        raise SSOTokenExpiredError(
            f"AWS SSO token expired for profile '{self.profile}'. "
            f"Run: aws sso login --profile {self.profile}"
        ) from original_error

    def _invalidate_clients(self) -> None:
        """Clear cached clients to force re-authentication on next use."""
        self._ssm_client = None
        self._ec2_client = None
        self._instance_id = None

    @property
    def ssm_client(self) -> Any:
        """Lazy-load SSM client with SSO token validation."""
        if self._ssm_client is None:
            session = self._create_session()
            self._ssm_client = session.client("ssm")
        return self._ssm_client

    @property
    def ec2_client(self) -> Any:
        """Lazy-load EC2 client with SSO token validation."""
        if self._ec2_client is None:
            session = self._create_session()
            self._ec2_client = session.client("ec2")
        return self._ec2_client

    @property
    def instance_id(self) -> str:
        """Resolve and return the instance ID."""
        if self._instance_id is None:
            self._instance_id = self._resolve_instance_id()
        return self._instance_id

    def _resolve_instance_id(self) -> str:
        """Resolve instance name to instance ID via EC2 API."""
        try:
            response = self.ec2_client.describe_instances(
                Filters=[
                    {"Name": "tag:Name", "Values": [self._instance_name]},
                    {"Name": "instance-state-name", "Values": ["running"]},
                ]
            )

            for reservation in response.get("Reservations", []):
                for instance in reservation.get("Instances", []):
                    instance_id = instance.get("InstanceId")
                    if instance_id:
                        logger.info(
                            f"Resolved Kali instance '{self._instance_name}' to {instance_id}"
                        )
                        return instance_id

            raise RuntimeError(f"No running instance found with name '{self._instance_name}'")  # noqa: TRY301

        except SSOTokenExpiredError:
            raise
        except (TokenRetrievalError, SSOTokenLoadError) as e:
            self._handle_sso_error(e)
        except ClientError as e:
            error_str = str(e).lower()
            if "token" in error_str and ("expired" in error_str or "sso" in error_str):
                self._handle_sso_error(e)
            raise RuntimeError(f"Failed to resolve instance ID: {e}") from e
        except Exception as e:
            error_str = str(e).lower()
            if "token" in error_str and ("expired" in error_str or "sso" in error_str):
                self._handle_sso_error(e)
            raise

    def run_command(
        self,
        command: str | list[str],
        timeout_seconds: int = 300,
        working_directory: str = "/tmp",  # noqa: S108  # nosec B108
    ) -> CommandResult:
        """Execute a command on the remote instance via SSM.

        Args:
            command: Command string or list of command parts
            timeout_seconds: Maximum time to wait for command completion
            working_directory: Directory to execute command in

        Returns:
            CommandResult with stdout, stderr, and return code
        """
        command_str = " ".join(command) if isinstance(command, list) else command

        # Wrap command to capture exit code and handle errors
        wrapped_command = f"""
cd {working_directory}
{command_str}
EXIT_CODE=$?
exit $EXIT_CODE
"""

        try:
            logger.debug(f"SSM executing: {command_str[:100]}...")

            response = self.ssm_client.send_command(
                InstanceIds=[self.instance_id],
                DocumentName="AWS-RunShellScript",
                Parameters={"commands": [wrapped_command]},
                TimeoutSeconds=timeout_seconds,
            )

            command_id = response["Command"]["CommandId"]
            logger.debug(f"SSM command ID: {command_id}")

            # Wait for command to complete
            return self._wait_for_command(command_id, timeout_seconds)

        except SSOTokenExpiredError:
            # Re-raise SSO errors without wrapping
            raise
        except (TokenRetrievalError, SSOTokenLoadError) as e:
            self._handle_sso_error(e)
        except ClientError as e:
            # Check if this is an SSO-related error
            error_str = str(e).lower()
            if "token" in error_str and ("expired" in error_str or "sso" in error_str):
                self._handle_sso_error(e)
            error_msg = f"SSM command failed: {e}"
            logger.error(error_msg)
            return CommandResult(
                stdout="",
                stderr=error_msg,
                return_code=1,
                success=False,
            )
        except Exception as e:
            # Catch any other SSO-related errors
            error_str = str(e).lower()
            if "token" in error_str and ("expired" in error_str or "sso" in error_str):
                self._handle_sso_error(e)
            raise

    def _wait_for_command(
        self,
        command_id: str,
        timeout_seconds: int,
    ) -> CommandResult:
        """Wait for SSM command to complete and return result."""
        start_time = time.time()
        poll_interval = 2  # seconds

        while True:
            elapsed = time.time() - start_time
            if elapsed > timeout_seconds:
                return CommandResult(
                    stdout="",
                    stderr=f"Command timed out after {timeout_seconds} seconds",
                    return_code=124,
                    success=False,
                )

            try:
                response = self.ssm_client.get_command_invocation(
                    CommandId=command_id,
                    InstanceId=self.instance_id,
                )

                status = response.get("Status", "")

                if status in ("Success", "Failed", "Cancelled", "TimedOut"):
                    stdout = response.get("StandardOutputContent", "")
                    stderr = response.get("StandardErrorContent", "")
                    return_code = response.get("ResponseCode", -1)

                    # Handle None return code
                    if return_code is None:
                        return_code = 0 if status == "Success" else 1

                    success = status == "Success" and return_code == 0

                    logger.debug(
                        f"SSM command completed: status={status}, return_code={return_code}"
                    )

                    return CommandResult(
                        stdout=stdout,
                        stderr=stderr,
                        return_code=return_code,
                        success=success,
                    )

                # Still pending, wait and retry
                time.sleep(poll_interval)

            except SSOTokenExpiredError:
                raise
            except (TokenRetrievalError, SSOTokenLoadError) as e:
                self._handle_sso_error(e)
            except ClientError as e:
                error_str = str(e).lower()
                if "token" in error_str and ("expired" in error_str or "sso" in error_str):
                    self._handle_sso_error(e)
                if "InvocationDoesNotExist" in str(e):
                    # Command not yet visible, wait and retry
                    time.sleep(poll_interval)
                    continue
                raise
            except Exception as e:
                error_str = str(e).lower()
                if "token" in error_str and ("expired" in error_str or "sso" in error_str):
                    self._handle_sso_error(e)
                raise


# Global executor instance (lazy-loaded)
_executor: SSMExecutor | None = None


def get_executor() -> SSMExecutor:
    """Get or create the global SSM executor instance."""
    global _executor
    if _executor is None:
        _executor = SSMExecutor()
    return _executor


def validate_sso_credentials(profile: str = "lab") -> bool:
    """Validate that SSO credentials are available and not expired.

    Call this at the start of an operation to fail fast if credentials
    are invalid, rather than failing mid-operation.

    Args:
        profile: AWS profile name to validate

    Returns:
        True if credentials are valid

    Raises:
        SSOTokenExpiredError: If SSO token is expired or invalid
    """
    try:
        session = boto3.Session(profile_name=profile)
        credentials = session.get_credentials()
        if credentials is None:
            raise SSOTokenExpiredError(  # noqa: TRY301
                f"No credentials available for profile '{profile}'. "
                f"Run: aws sso login --profile {profile}"
            )
        # Force credential resolution to validate token
        credentials.get_frozen_credentials()
        logger.debug(f"SSO credentials validated for profile '{profile}'")
        return True
    except (TokenRetrievalError, SSOTokenLoadError) as e:
        raise SSOTokenExpiredError(
            f"AWS SSO token expired for profile '{profile}'. Run: aws sso login --profile {profile}"
        ) from e
    except Exception as e:
        error_str = str(e).lower()
        if "token" in error_str and ("expired" in error_str or "sso" in error_str):
            raise SSOTokenExpiredError(
                f"AWS SSO token expired for profile '{profile}'. "
                f"Run: aws sso login --profile {profile}"
            ) from e
        raise


def reset_executor() -> None:
    """Reset the global executor instance.

    Call this after SSO token refresh to force re-authentication.
    """
    global _executor
    _executor = None
    logger.info("SSM executor reset - will re-authenticate on next use")


def run_remote(
    command: str | list[str],
    timeout_seconds: int = 300,
    working_directory: str = "/tmp",  # noqa: S108  # nosec B108
) -> CommandResult:
    """Execute a command on the remote Kali instance.

    This is a convenience function that uses the global executor.

    Args:
        command: Command string or list of command parts
        timeout_seconds: Maximum time to wait
        working_directory: Directory to execute in

    Returns:
        CommandResult with stdout, stderr, and return code

    Example:
        >>> result = run_remote("netexec smb 10.1.2.219 --shares")
        >>> print(result.stdout)
    """
    executor = get_executor()
    return executor.run_command(command, timeout_seconds, working_directory)
