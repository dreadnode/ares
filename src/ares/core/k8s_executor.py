"""Kubernetes pod execution for multi-agent red team operations.

DEPRECATED: For task dispatch to worker pods, use RedisTaskQueue instead.

This module provides the KubernetesPodExecutor class for executing
commands in Kubernetes pods, handling ephemeral pod lifecycle gracefully.

For multi-agent task coordination, prefer:
    from ares.core.task_queue import RedisTaskQueue

    queue = RedisTaskQueue(redis_url)
    await queue.submit_task(task_type="crack", target_role="cracker", payload={...})

KubernetesPodExecutor is retained for:
- One-off debugging commands
- Log retrieval
- Pod health checks
- Direct command execution when needed
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

from loguru import logger

if TYPE_CHECKING:
    from kubernetes import client


class PodNotAvailableError(Exception):
    """Raised when no pod is available for a given role."""


class PodExecutionError(Exception):
    """Raised when command execution in a pod fails."""


class KubernetesPodExecutor:
    """
    Execute commands in Kubernetes pods.

    DEPRECATED for task dispatch: Use RedisTaskQueue for multi-agent task coordination.
    This class uses kubectl exec which is slow (WebSocket per command), fragile (breaks
    on pod restarts), and synchronous (blocks orchestrator).

    This class is kept for:
    - One-off debugging commands
    - Log retrieval
    - Pod health checks
    - Direct command execution when kubectl exec is appropriate

    For task dispatch, use instead:
        from ares.core.task_queue import RedisTaskQueue
        queue = RedisTaskQueue(redis_url)
        await queue.submit_task(...)

    Usage (for debugging/one-off commands):
        executor = KubernetesPodExecutor(namespace="attack-simulation")
        stdout, stderr, code = await executor.execute(
            role="cracker",
            command=["hashcat", "-m", "1000", "hash.txt"]
        )
    """

    def __init__(
        self,
        namespace: str = "default",
        kubeconfig: str | None = None,
        in_cluster: bool = False,
    ):
        """
        Initialize the Kubernetes pod executor.

        Args:
            namespace: Kubernetes namespace to operate in.
            kubeconfig: Path to kubeconfig file. If None, uses default.
            in_cluster: If True, use in-cluster configuration.
        """
        self.namespace = namespace
        self._kubeconfig = kubeconfig
        self._in_cluster = in_cluster
        self._pod_cache: dict[str, str] = {}  # role -> pod_name
        self._v1: client.CoreV1Api | None = None
        self._initialized = False

    async def _ensure_initialized(self) -> None:
        """Ensure Kubernetes client is initialized."""
        if self._initialized:
            return

        try:
            from kubernetes import client, config

            if self._in_cluster:
                config.load_incluster_config()
            elif self._kubeconfig:
                config.load_kube_config(config_file=self._kubeconfig)
            else:
                config.load_kube_config()

            self._v1 = client.CoreV1Api()
            self._initialized = True
            logger.info(f"Kubernetes client initialized for namespace: {self.namespace}")

        except ImportError as e:
            raise RuntimeError(
                "kubernetes package not installed. Install with: pip install kubernetes"
            ) from e
        except Exception as e:
            raise RuntimeError(f"Failed to initialize Kubernetes client: {e}") from e

    async def get_pod_for_role(self, role: str) -> str | None:
        """
        Find running pod for a given role.

        Handles pod restarts by re-discovering pods.

        Args:
            role: The agent role (enum, cracker, acl, privesc, lateral, poisoning).

        Returns:
            Pod name if found, None otherwise.
        """
        await self._ensure_initialized()
        assert self._v1 is not None  # noqa: S101

        # Check cache first
        if role in self._pod_cache:
            # Verify pod still exists and is running
            try:
                pod = self._v1.read_namespaced_pod(
                    name=self._pod_cache[role],
                    namespace=self.namespace,
                )
                if pod.status.phase == "Running":
                    return self._pod_cache[role]
            except Exception:
                # Pod no longer exists, clear cache
                del self._pod_cache[role]

        # Discover pod by label
        label_selector = f"ares.dreadnode.io/role={role}"

        try:
            pods = self._v1.list_namespaced_pod(
                namespace=self.namespace,
                label_selector=label_selector,
                field_selector="status.phase=Running",
            )

            if pods.items:
                pod_name = pods.items[0].metadata.name
                self._pod_cache[role] = pod_name
                logger.debug(f"Discovered pod for role {role}: {pod_name}")
                return pod_name

        except Exception as e:
            logger.error(f"Failed to discover pod for role {role}: {e}")

        return None

    async def execute(
        self,
        role: str,
        command: list[str] | str,
        container: str | None = None,
        timeout_seconds: int = 300,
        stdin_data: str | None = None,
    ) -> tuple[str, str, int]:
        """
        Execute command in pod for given role.

        Args:
            role: The agent role (enum, cracker, acl, privesc, lateral, poisoning).
            command: Command to execute as list of strings or shell command string.
            container: Container name to execute in (default: first container).
            timeout_seconds: Execution timeout in seconds.
            stdin_data: Optional data to send to stdin.

        Returns:
            Tuple of (stdout, stderr, return_code).

        Raises:
            PodNotAvailableError: If no pod is available for the role.
            PodExecutionError: If command execution fails.
        """
        await self._ensure_initialized()

        pod_name = await self.get_pod_for_role(role)
        if not pod_name:
            raise PodNotAvailableError(f"No running pod for role: {role}")

        # Convert string command to shell execution
        if isinstance(command, str):
            command = ["/bin/bash", "-c", command]

        try:
            return await self._execute_in_pod(
                pod_name=pod_name,
                command=command,
                container=container,
                timeout=timeout_seconds,
                stdin_data=stdin_data,
            )
        except Exception as e:
            # Pod may have restarted, clear cache and retry once
            if role in self._pod_cache:
                del self._pod_cache[role]
                logger.warning(f"Pod execution failed, retrying with fresh pod discovery: {e}")
                pod_name = await self.get_pod_for_role(role)
                if pod_name:
                    return await self._execute_in_pod(
                        pod_name=pod_name,
                        command=command,
                        container=container,
                        timeout=timeout_seconds,
                        stdin_data=stdin_data,
                    )
            raise PodExecutionError(f"Command execution failed: {e}") from e

    async def _execute_in_pod(
        self,
        pod_name: str,
        command: list[str],
        container: str | None,
        timeout: int,
        stdin_data: str | None = None,
    ) -> tuple[str, str, int]:
        """Execute command in a specific pod container."""
        from kubernetes.stream import stream

        assert self._v1 is not None  # noqa: S101
        v1 = self._v1

        try:
            # Run in thread pool since kubernetes client is sync
            loop = asyncio.get_event_loop()

            def _exec():
                exec_kwargs = {
                    "command": command,
                    "stderr": True,
                    "stdin": bool(stdin_data),
                    "stdout": True,
                    "tty": False,
                    "_preload_content": False,
                }
                if container:
                    exec_kwargs["container"] = container
                resp = stream(
                    v1.connect_get_namespaced_pod_exec,
                    pod_name,
                    self.namespace,
                    **exec_kwargs,
                )

                stdout_chunks = []
                stderr_chunks = []

                if stdin_data:
                    resp.write_stdin(stdin_data)

                while resp.is_open():
                    resp.update(timeout=timeout)
                    if resp.peek_stdout():
                        stdout_chunks.append(resp.read_stdout())
                    if resp.peek_stderr():
                        stderr_chunks.append(resp.read_stderr())

                stdout = "".join(stdout_chunks)
                stderr = "".join(stderr_chunks)
                return_code = resp.returncode or 0

                return stdout, stderr, return_code

            stdout, stderr, return_code = await asyncio.wait_for(
                loop.run_in_executor(None, _exec),
                timeout=timeout,
            )

            logger.debug(f"Command in {pod_name} completed with code {return_code}")
            return stdout, stderr, return_code

        except asyncio.TimeoutError as e:
            raise PodExecutionError(f"Command timed out after {timeout} seconds") from e
        except Exception as e:
            raise PodExecutionError(f"Command execution error: {e}") from e

    async def wait_for_pod(self, role: str, timeout: int = 60) -> bool:
        """
        Wait for pod to become ready.

        Args:
            role: The agent role to wait for.
            timeout: Maximum time to wait in seconds.

        Returns:
            True if pod became ready, False if timeout.
        """
        await self._ensure_initialized()

        start = asyncio.get_event_loop().time()

        while asyncio.get_event_loop().time() - start < timeout:
            pod_name = await self.get_pod_for_role(role)
            if pod_name:
                logger.info(f"Pod ready for role {role}: {pod_name}")
                return True
            await asyncio.sleep(2)

        logger.warning(f"Timeout waiting for pod with role {role}")
        return False

    async def wait_for_all_pods(
        self,
        roles: list[str],
        timeout: int = 120,
    ) -> dict[str, bool]:
        """
        Wait for all required pods to be ready.

        Args:
            roles: List of roles to wait for.
            timeout: Maximum time to wait in seconds.

        Returns:
            Dict mapping role to ready status.
        """
        results: dict[str, bool] = {}

        async def wait_for_role(role: str):
            ready = await self.wait_for_pod(role, timeout)
            results[role] = ready
            return ready

        await asyncio.gather(*[wait_for_role(r) for r in roles])

        ready_count = sum(1 for r in results.values() if r)
        logger.info(f"Pods ready: {ready_count}/{len(roles)}")

        return results

    async def get_pod_logs(
        self,
        role: str,
        tail_lines: int = 100,
        since_seconds: int | None = None,
    ) -> str:
        """
        Get logs from a pod.

        Args:
            role: The agent role.
            tail_lines: Number of lines to retrieve from end.
            since_seconds: Only return logs newer than this many seconds.

        Returns:
            Pod logs as string.
        """
        await self._ensure_initialized()
        assert self._v1 is not None  # noqa: S101

        pod_name = await self.get_pod_for_role(role)
        if not pod_name:
            raise PodNotAvailableError(f"No running pod for role: {role}")

        try:
            return self._v1.read_namespaced_pod_log(
                name=pod_name,
                namespace=self.namespace,
                tail_lines=tail_lines,
                since_seconds=since_seconds,
            )
        except Exception as e:
            logger.error(f"Failed to get logs for {role}: {e}")
            raise PodExecutionError(f"Failed to get pod logs: {e}") from e

    async def copy_to_pod(
        self,
        role: str,
        local_path: str,
        remote_path: str,
    ) -> bool:
        """
        Copy file to pod.

        Args:
            role: The agent role.
            local_path: Local file path.
            remote_path: Remote path in pod.

        Returns:
            True if successful.
        """
        await self._ensure_initialized()

        pod_name = await self.get_pod_for_role(role)
        if not pod_name:
            raise PodNotAvailableError(f"No running pod for role: {role}")

        try:
            # Read local file
            with open(local_path, "rb") as f:  # noqa: ASYNC230
                data = f.read()

            # Use base64 encoding to handle binary data
            import base64

            encoded = base64.b64encode(data).decode()

            # Write to pod using echo and base64 decode
            command = [
                "/bin/sh",
                "-c",
                f"echo '{encoded}' | base64 -d > {remote_path}",
            ]

            _stdout, stderr, code = await self.execute(role, command)

            if code != 0:
                logger.error(f"Failed to copy to pod: {stderr}")
                return False

            logger.debug(f"Copied {local_path} to {pod_name}:{remote_path}")
            return True

        except Exception as e:
            logger.error(f"Failed to copy file to pod: {e}")
            return False

    async def copy_from_pod(
        self,
        role: str,
        remote_path: str,
        local_path: str,
    ) -> bool:
        """
        Copy file from pod.

        Args:
            role: The agent role.
            remote_path: Remote path in pod.
            local_path: Local file path.

        Returns:
            True if successful.
        """
        await self._ensure_initialized()

        try:
            # Read file from pod using base64 encoding
            command = [
                "/bin/sh",
                "-c",
                f"base64 {remote_path}",
            ]

            stdout, stderr, code = await self.execute(role, command)

            if code != 0:
                logger.error(f"Failed to read from pod: {stderr}")
                return False

            # Decode and write locally
            import base64

            data = base64.b64decode(stdout.strip())

            with open(local_path, "wb") as f:  # noqa: ASYNC230
                f.write(data)

            logger.debug(f"Copied {remote_path} to {local_path}")
            return True

        except Exception as e:
            logger.error(f"Failed to copy file from pod: {e}")
            return False

    def clear_cache(self) -> None:
        """Clear the pod name cache."""
        self._pod_cache.clear()
        logger.debug("Pod cache cleared")

    async def list_pods_by_role(self) -> dict[str, list[str]]:
        """
        List all Ares pods grouped by role.

        Returns:
            Dict mapping role to list of pod names.
        """
        await self._ensure_initialized()
        assert self._v1 is not None  # noqa: S101

        result: dict[str, list[str]] = {}
        label_selector = "ares.dreadnode.io/component=red-team"

        try:
            pods = self._v1.list_namespaced_pod(
                namespace=self.namespace,
                label_selector=label_selector,
            )

            for pod in pods.items:
                role = pod.metadata.labels.get("ares.dreadnode.io/role", "unknown")
                if role not in result:
                    result[role] = []
                result[role].append(pod.metadata.name)

        except Exception as e:
            logger.error(f"Failed to list pods: {e}")

        return result


__all__ = [
    "KubernetesPodExecutor",
    "PodExecutionError",
    "PodNotAvailableError",
]
