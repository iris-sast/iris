import os
import tarfile
import io
from typing import Dict, List, Optional, Tuple

import docker
from docker.errors import APIError, ImageNotFound


def get_client() -> docker.DockerClient:
    docker_host = os.environ.get("DOCKER_HOST")
    if docker_host:
        return docker.DockerClient(base_url=docker_host)
    return docker.from_env()


def pull_image(image: str) -> None:
    client = get_client()
    try:
        client.images.pull(image)
    except ImageNotFound:
        raise
    except APIError as e:
        raise RuntimeError(f"Failed to pull image {image}: {e}")


def ensure_image(image: str) -> None:
    client = get_client()
    try:
        client.images.get(image)
        return
    except ImageNotFound:
        pull_image(image)


def create_container(image: str,
                     name: Optional[str] = None,
                     command: Optional[List[str]] = None,
                     environment: Optional[Dict[str, str]] = None,
                     working_dir: Optional[str] = None,
                     volumes: Optional[Dict[str, Dict[str, str]]] = None,
                     user: Optional[str] = None) -> docker.models.containers.Container:
    client = get_client()
    ensure_image(image)
    return client.containers.create(
        image=image,
        name=name,
        command=command,
        environment=environment or {},
        working_dir=working_dir,
        volumes=volumes or {},
        user=user,
        tty=True,
        stdin_open=True,
    )


def run_container(image: str,
                  command: Optional[List[str]] = None,
                  environment: Optional[Dict[str, str]] = None,
                  working_dir: Optional[str] = None,
                  volumes: Optional[Dict[str, Dict[str, str]]] = None,
                  name: Optional[str] = None,
                  user: Optional[str] = None,
                  stream_logs: bool = True) -> Tuple[int, str]:
    container = create_container(
        image=image,
        name=name,
        command=command,
        environment=environment,
        working_dir=working_dir,
        volumes=volumes,
        user=user,
    )
    try:
        container.start()
        if stream_logs:
            logs_iter = container.logs(stream=True, follow=True)
            output_chunks: List[bytes] = []
            for chunk in logs_iter:
                try:
                    print(chunk.decode(errors="ignore"), end="")
                except Exception:
                    pass
                output_chunks.append(chunk)
            output = b"".join(output_chunks).decode(errors="ignore")
        else:
            output = container.logs(stdout=True, stderr=True).decode(errors="ignore")
        exit_code = container.wait().get("StatusCode", 1)
        return exit_code, output
    finally:
        try:
            container.remove(force=True)
        except Exception:
            pass


def exec_in_container(container: docker.models.containers.Container,
                      cmd: List[str],
                      workdir: Optional[str] = None,
                      environment: Optional[Dict[str, str]] = None,
                      stream: bool = True) -> Tuple[int, str]:
    exec_id = container.client.api.exec_create(
        container.id,
        cmd,
        workdir=workdir,
        environment=environment,
        stdout=True,
        stderr=True,
    )
    output = ""
    if stream:
        for chunk in container.client.api.exec_start(exec_id, stream=True):
            s = chunk.decode(errors="ignore")
            print(s, end="")
            output += s
    else:
        output = container.client.api.exec_start(exec_id, stream=False).decode(errors="ignore")
    inspect = container.client.api.exec_inspect(exec_id)
    return inspect.get("ExitCode", 1), output


def copy_from_container(container: docker.models.containers.Container, path: str, dest: str) -> None:
    bits, stat = container.get_archive(path)
    file_obj = io.BytesIO()
    for chunk in bits:
        file_obj.write(chunk)
    file_obj.seek(0)
    with tarfile.open(fileobj=file_obj) as tar:
        tar.extractall(dest)


def parse_project_image(project_slug: str, registry_repo: str = "irissast/cwe-bench-java-containers-v2") -> str:
    return f"{registry_repo}:{project_slug}"


def copy_dir_to_container(container: docker.models.containers.Container, src_dir: str, dest_dir: str) -> None:
    if not os.path.isdir(src_dir):
        raise FileNotFoundError(f"Source directory not found: {src_dir}")

    tar_stream = io.BytesIO()
    with tarfile.open(fileobj=tar_stream, mode='w') as tar:
        # Add contents of src_dir under dest_dir path inside container
        src_dir = os.path.abspath(src_dir)
        for root, dirs, files in os.walk(src_dir):
            for name in dirs + files:
                full_path = os.path.join(root, name)
                arcname = os.path.join(dest_dir.lstrip('/'), os.path.relpath(full_path, start=src_dir))
                tar.add(full_path, arcname=arcname, recursive=False)
    tar_stream.seek(0)
    container.put_archive(path='/', data=tar_stream.read())
