# Copyright 2025 The Sigstore Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""OCI registry client using oras-py for authentication."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
from typing import Any

import oras.provider
import requests


# OCI Distribution Spec media types
OCI_MANIFEST_MEDIA_TYPE = "application/vnd.oci.image.manifest.v1+json"
OCI_INDEX_MEDIA_TYPE = "application/vnd.oci.image.index.v1+json"

# Media types for model signing signature artifacts
MODEL_SIGNING_ARTIFACT_TYPE = "application/vnd.model-signing.signature.v0.1"
MODEL_SIGNING_CONFIG_MEDIA_TYPE = (
    "application/vnd.model-signing.signature.v0.1.config+json"
)
MODEL_SIGNING_LAYER_MEDIA_TYPE = "application/vnd.dev.sigstore.bundle.v0.3+json"


@dataclass
class ImageReference:
    """Parsed OCI image reference.

    Format: registry/repository:tag or registry/repository@sha256:digest
    """

    registry: str
    repository: str
    tag: str | None
    digest: str | None

    @classmethod
    def parse(cls, reference: str) -> ImageReference:
        """Parse an image reference string."""
        if "/" not in reference:
            raise ValueError(f"Invalid reference '{reference}': missing /")

        digest = None
        if "@" in reference:
            reference, digest = reference.rsplit("@", 1)
            if not re.match(r"^sha256:[a-f0-9]{64}$", digest):
                raise ValueError(f"Invalid digest format: {digest}")

        tag = None
        if ":" in reference and not digest:
            parts = reference.rsplit(":", 1)
            if "/" not in parts[1]:
                reference, tag = parts

        parts = reference.split("/", 1)
        if len(parts) != 2 or not parts[1]:
            raise ValueError(f"Invalid image reference '{reference}'")

        registry, repository = parts[0], parts[1]

        if not tag and not digest:
            raise ValueError(
                f"Image reference must have :tag or @digest: {reference}"
            )

        return cls(registry, repository, tag, digest)

    def __str__(self) -> str:
        result = f"{self.registry}/{self.repository}"
        if self.digest:
            result += f"@{self.digest}"
        elif self.tag:
            result += f":{self.tag}"
        return result

    @property
    def reference(self) -> str:
        if self.digest:
            return self.digest
        return self.tag or "latest"

    def with_digest(self, digest: str) -> ImageReference:
        return ImageReference(
            registry=self.registry,
            repository=self.repository,
            tag=None,
            digest=digest,
        )

    def with_tag(self, tag: str) -> ImageReference:
        return ImageReference(
            registry=self.registry,
            repository=self.repository,
            tag=tag,
            digest=None,
        )


def is_image_reference(value: str) -> bool:
    """Check if a string looks like an OCI image reference."""
    if not value or value.startswith(("/", ".", "~")):
        return False
    if value.endswith(".json"):
        return False
    if "/" not in value or (":" not in value and "@" not in value):
        return False
    try:
        ImageReference.parse(value)
        return True
    except ValueError:
        return False


class OrasClient:
    """OCI registry client using oras-py for authentication."""

    def __init__(self, *, insecure: bool = False, tls_verify: bool = True):
        self._insecure = insecure
        self._tls_verify = tls_verify

    def _auth_registry(
        self, image_ref: ImageReference
    ) -> oras.provider.Registry:
        """Get an authenticated oras Registry instance."""
        reg = oras.provider.Registry(
            hostname=image_ref.registry,
            insecure=self._insecure,
            tls_verify=self._tls_verify,
        )
        reg.auth.load_configs(reg.get_container(str(image_ref)))
        return reg

    def _base_url(self, image_ref: ImageReference) -> str:
        """Get the base URL for a registry."""
        registry = image_ref.registry
        if registry in ("docker.io", "index.docker.io"):
            registry = "registry-1.docker.io"
        return f"{'http' if self._insecure else 'https'}://{registry}"

    def get_manifest(
        self, image_ref: ImageReference
    ) -> tuple[dict[str, Any], str]:
        """Get a manifest from the registry."""
        reg = self._auth_registry(image_ref)
        manifest = reg.get_manifest(str(image_ref))
        manifest_bytes = json.dumps(manifest, separators=(",", ":")).encode()
        digest = f"sha256:{hashlib.sha256(manifest_bytes).hexdigest()}"
        return manifest, digest

    def resolve_digest(self, image_ref: ImageReference) -> str:
        """Resolve an image reference to its digest."""
        if image_ref.digest:
            return image_ref.digest
        _, digest = self.get_manifest(image_ref)
        return digest

    def push_blob(
        self, image_ref: ImageReference, blob_bytes: bytes, media_type: str
    ) -> str:
        """Push a blob to the registry."""
        digest = f"sha256:{hashlib.sha256(blob_bytes).hexdigest()}"
        base_url = self._base_url(image_ref)
        reg = self._auth_registry(image_ref)

        check_url = f"{base_url}/v2/{image_ref.repository}/blobs/{digest}"
        try:
            if reg.do_request(check_url, "HEAD").status_code == 200:
                return digest
        except requests.HTTPError:
            pass

        upload_url = f"{base_url}/v2/{image_ref.repository}/blobs/uploads/"
        response = reg.do_request(upload_url, "POST")
        location = response.headers.get("Location")
        if not location:
            raise ValueError("Registry did not return upload location")
        if location.startswith("/"):
            location = f"{base_url}{location}"
        sep = "&" if "?" in location else "?"
        location = f"{location}{sep}digest={digest}"

        headers = {"Content-Type": media_type}
        reg.do_request(location, "PUT", data=blob_bytes, headers=headers)
        return digest

    def push_manifest(
        self,
        image_ref: ImageReference,
        manifest: dict[str, Any],
        media_type: str = OCI_MANIFEST_MEDIA_TYPE,
    ) -> str:
        """Push a manifest to the registry."""
        manifest_bytes = json.dumps(manifest, separators=(",", ":")).encode()
        digest = f"sha256:{hashlib.sha256(manifest_bytes).hexdigest()}"
        base = self._base_url(image_ref)
        repo = image_ref.repository
        url = f"{base}/v2/{repo}/manifests/{image_ref.reference}"
        headers = {"Content-Type": media_type}
        self._auth_registry(image_ref).do_request(
            url, "PUT", data=manifest_bytes, headers=headers
        )
        return digest

    def push_signature(
        self,
        image_ref: ImageReference,
        signature_bytes: bytes,
        subject_digest: str,
        subject_size: int,
    ) -> str:
        """Push a signature using OCI 1.1 Referrers API."""
        layer_digest = self.push_blob(
            image_ref, signature_bytes, MODEL_SIGNING_LAYER_MEDIA_TYPE
        )

        config_bytes = b"{}"
        config_digest = self.push_blob(
            image_ref, config_bytes, MODEL_SIGNING_CONFIG_MEDIA_TYPE
        )

        manifest = {
            "schemaVersion": 2,
            "mediaType": OCI_MANIFEST_MEDIA_TYPE,
            "artifactType": MODEL_SIGNING_ARTIFACT_TYPE,
            "config": {
                "mediaType": MODEL_SIGNING_CONFIG_MEDIA_TYPE,
                "digest": config_digest,
                "size": len(config_bytes),
            },
            "layers": [
                {
                    "mediaType": MODEL_SIGNING_LAYER_MEDIA_TYPE,
                    "digest": layer_digest,
                    "size": len(signature_bytes),
                }
            ],
            "subject": {
                "mediaType": OCI_MANIFEST_MEDIA_TYPE,
                "digest": subject_digest,
                "size": subject_size,
            },
        }

        manifest_digest = _calculate_manifest_digest(manifest)
        return self.push_manifest(
            image_ref.with_digest(manifest_digest), manifest
        )

    def push_signature_tag(
        self, image_ref: ImageReference, signature_bytes: bytes, tag: str
    ) -> str:
        """Push a signature with a specific tag."""
        layer_digest = self.push_blob(
            image_ref, signature_bytes, MODEL_SIGNING_LAYER_MEDIA_TYPE
        )

        config_bytes = b"{}"
        config_media_type = "application/vnd.oci.image.config.v1+json"
        config_digest = self.push_blob(
            image_ref, config_bytes, config_media_type
        )

        manifest = {
            "schemaVersion": 2,
            "mediaType": OCI_MANIFEST_MEDIA_TYPE,
            "config": {
                "mediaType": config_media_type,
                "digest": config_digest,
                "size": len(config_bytes),
            },
            "layers": [
                {
                    "mediaType": MODEL_SIGNING_LAYER_MEDIA_TYPE,
                    "digest": layer_digest,
                    "size": len(signature_bytes),
                }
            ],
            "annotations": {
                "dev.sigstore.model-signing.artifact-type": (
                    MODEL_SIGNING_ARTIFACT_TYPE
                )
            },
        }

        return self.push_manifest(image_ref.with_tag(tag), manifest)

    def get_referrers(
        self, image_ref: ImageReference, artifact_type: str | None = None
    ) -> list[dict[str, Any]]:
        """Get referrers for an image (OCI 1.1)."""
        digest = image_ref.digest or self.resolve_digest(image_ref)
        base = self._base_url(image_ref)
        url = f"{base}/v2/{image_ref.repository}/referrers/{digest}"
        try:
            response = self._auth_registry(image_ref).do_request(
                url, "GET", headers={"Accept": OCI_INDEX_MEDIA_TYPE}
            )
            if response.status_code != 200:
                return []
            manifests = response.json().get("manifests", [])
            if artifact_type:
                manifests = [
                    m
                    for m in manifests
                    if m.get("artifactType") == artifact_type
                ]
            return manifests
        except requests.HTTPError as e:
            if e.response is not None and e.response.status_code == 404:
                return []
            raise

    def pull_blob(self, image_ref: ImageReference, digest: str) -> bytes:
        """Pull a blob from the registry."""
        reg = self._auth_registry(image_ref)
        return reg.get_blob(str(image_ref), digest).content


def _calculate_manifest_digest(manifest: dict) -> str:
    """Calculate the sha256 digest of a manifest."""
    content = json.dumps(manifest, separators=(",", ":")).encode("utf-8")
    return f"sha256:{hashlib.sha256(content).hexdigest()}"
