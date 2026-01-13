"""Command execution for red team tools.

This module provides functionality to execute commands either:
- Via kubectl exec (in K8s orchestrator) - set ARES_EXECUTION_MODE=k8s
- Via subprocess (in K8s worker pods) - set ARES_EXECUTION_MODE=local
- Via AWS SSM (for local dev with EC2) - default
"""

import asyncio
import os
import shlex
import subprocess
import time
from dataclasses import dataclass
from typing import Any, NoReturn

import boto3
from botocore.exceptions import ClientError, SSOTokenLoadError, TokenRetrievalError
from loguru import logger

# Execution mode: "k8s" for kubectl exec, "local" for subprocess, "ssm" for EC2
EXECUTION_MODE = os.environ.get("ARES_EXECUTION_MODE", "ssm").lower()


class SSOTokenExpiredError(Exception):
    """Raised when AWS SSO token has expired and needs refresh."""


@dataclass
class CommandResult:
    """Result of command execution."""

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


class K8sExecutor:
    """Execute commands via Redis task queue on the enum worker pod.

    Uses Redis-based task dispatch instead of kubectl exec to avoid needing
    pods/exec RBAC permissions. The orchestrator submits commands to Redis,
    worker pods poll and execute locally, then return results via Redis.
    """

    def __init__(self):
        self._redis_url = os.environ.get("REDIS_URL", "redis://redis.ares.svc:6379")
        self._task_queue = None

    def _get_task_queue(self):
        """Lazy-load the RedisTaskQueue."""
        if self._task_queue is None:
            from ares.core.task_queue import RedisTaskQueue

            self._task_queue = RedisTaskQueue(self._redis_url)
        return self._task_queue

    def run_command(
        self,
        command: str | list[str],
        timeout_seconds: int = 300,
        working_directory: str = "/tmp",  # noqa: S108  # nosec B108
    ) -> CommandResult:
        """Execute a command via Redis task queue on the enum worker pod."""
        import concurrent.futures

        # Use shlex.join for proper shell quoting (handles parentheses, spaces, etc.)
        command_str = shlex.join(command) if isinstance(command, list) else command

        logger.debug(f"K8s executing via Redis queue: {command_str[:100]}...")

        def _run_in_thread():
            """Run the async task queue call in a new thread with its own event loop."""
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                return loop.run_until_complete(
                    self._dispatch_command(command_str, timeout_seconds, working_directory)
                )
            finally:
                loop.close()

        try:
            # Run in a separate thread to avoid event loop conflicts
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(_run_in_thread)
                return future.result(timeout=timeout_seconds + 30)

        except concurrent.futures.TimeoutError:
            logger.error("K8s execution timed out")
            return CommandResult(
                stdout="",
                stderr=f"Command timed out after {timeout_seconds}s",
                return_code=124,
                success=False,
            )
        except Exception as e:
            logger.error(f"K8s execution failed: {e}")
            return CommandResult(
                stdout="",
                stderr=str(e),
                return_code=1,
                success=False,
            )

    async def _dispatch_command(
        self,
        command: str,
        timeout_seconds: int,
        working_directory: str,
    ) -> CommandResult:
        """Dispatch command via Redis and wait for result."""
        task_queue = self._get_task_queue()
        await task_queue.connect()

        try:
            # Submit command task to enum worker
            task_id = await task_queue.submit_task(
                task_type="command",
                target_role="enum",
                payload={
                    "command": command,
                    "working_directory": working_directory,
                    "timeout_seconds": timeout_seconds,
                },
                source_agent="orchestrator",
            )

            logger.debug(f"Command task {task_id} submitted to enum worker")

            # Wait for result
            result = await task_queue.wait_for_result(task_id, timeout=float(timeout_seconds))

            if result is None:
                return CommandResult(
                    stdout="",
                    stderr=f"Command timed out after {timeout_seconds}s",
                    return_code=124,
                    success=False,
                )

            # Extract result
            if result.success:
                output = result.result or {}
                return CommandResult(
                    stdout=output.get("stdout", ""),
                    stderr=output.get("stderr", ""),
                    return_code=output.get("return_code", 0),
                    success=output.get("return_code", 0) == 0,
                )
            return CommandResult(
                stdout="",
                stderr=result.error or "Unknown error",
                return_code=1,
                success=False,
            )
        finally:
            await task_queue.disconnect()


class LocalExecutor:
    """Execute commands via subprocess.

    Used in K8s worker pods where tools are available in the shared process namespace.
    """

    def run_command(
        self,
        command: str | list[str],
        timeout_seconds: int = 300,
        working_directory: str = "/tmp",  # noqa: S108  # nosec B108
    ) -> CommandResult:
        """Execute a command via subprocess."""
        # Use shlex.join for proper shell quoting (handles parentheses, spaces, etc.)
        command_str = shlex.join(command) if isinstance(command, list) else command

        logger.debug(f"Executing locally: {command_str[:100]}...")

        try:
            result = subprocess.run(  # noqa: S602  # nosec B602
                command_str,
                shell=True,  # nosec B602
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                cwd=working_directory,
                check=False,
            )
            return CommandResult(
                stdout=result.stdout,
                stderr=result.stderr,
                return_code=result.returncode,
                success=result.returncode == 0,
            )
        except subprocess.TimeoutExpired:
            return CommandResult(
                stdout="",
                stderr=f"Command timed out after {timeout_seconds}s",
                return_code=124,
                success=False,
            )
        except Exception as e:
            return CommandResult(
                stdout="",
                stderr=str(e),
                return_code=1,
                success=False,
            )


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
        # Use shlex.join for proper shell quoting (handles parentheses, spaces, etc.)
        command_str = shlex.join(command) if isinstance(command, list) else command

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
_executor: SSMExecutor | K8sExecutor | LocalExecutor | None = None


def get_executor() -> SSMExecutor | K8sExecutor | LocalExecutor:
    """Get or create the global executor instance.

    Returns:
        - K8sExecutor when ARES_EXECUTION_MODE=k8s (kubectl exec to enum pod)
        - LocalExecutor when ARES_EXECUTION_MODE=local (subprocess in pod)
        - SSMExecutor otherwise (AWS SSM for EC2)
    """
    global _executor
    if _executor is None:
        if EXECUTION_MODE == "k8s":
            logger.info("Using K8s executor (kubectl exec to enum pod)")
            _executor = K8sExecutor()
        elif EXECUTION_MODE == "local":
            logger.info("Using local executor (subprocess)")
            _executor = LocalExecutor()
        else:
            logger.info("Using SSM executor (EC2)")
            _executor = SSMExecutor()
    return _executor


def validate_sso_credentials(profile: str = "lab") -> bool:
    """Validate that SSO credentials are available and not expired.

    Call this at the start of an operation to fail fast if credentials
    are invalid, rather than failing mid-operation.

    Skipped when ARES_EXECUTION_MODE=k8s or local.

    Args:
        profile: AWS profile name to validate

    Returns:
        True if credentials are valid

    Raises:
        SSOTokenExpiredError: If SSO token is expired or invalid
    """
    if EXECUTION_MODE in ("k8s", "local"):
        return True

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
