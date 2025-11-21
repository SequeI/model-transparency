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

"""Signature attachment strategies for OCI registries.

Provides two modes for attaching signatures to images:
1. Referrers API (OCI 1.1) - Creates artifact referencing the signed image
2. Tag-based - Uses a tag derived from the image digest (legacy/fallback)
"""

from __future__ import annotations

import enum
import json
from typing import TYPE_CHECKING

from model_signing._oci import registry as oci_registry


if TYPE_CHECKING:
    from model_signing._oci.registry import ImageReference
    from model_signing._oci.registry import OrasClient


class AttachmentMode(enum.Enum):
    """Signature attachment mode."""

    REFERRERS = "referrers"
    TAG = "tag"


class ReferrersAttachment:
    """Signature attachment using OCI 1.1 Referrers API."""

    def attach(
        self,
        client: OrasClient,
        image_ref: ImageReference,
        signature_bundle: bytes,
        image_digest: str,
        subject_manifest_size: int = 0,
    ) -> str:
        return client.push_signature(
            image_ref,
            signature_bundle,
            subject_digest=image_digest,
            subject_size=subject_manifest_size,
        )

    def fetch(
        self,
        client: OrasClient,
        image_ref: ImageReference,
        image_digest: str,
        signature_type: str | None = None,
    ) -> bytes | None:
        referrers = client.get_referrers(
            image_ref.with_digest(image_digest),
            artifact_type=oci_registry.MODEL_SIGNING_ARTIFACT_TYPE,
        )
        if not referrers:
            return None

        for sig_ref in reversed(referrers):
            sig_digest = sig_ref.get("digest")
            if not sig_digest:
                continue
            sig_bytes = self._fetch_layer(client, image_ref, sig_digest)
            if sig_bytes and self._matches_type(sig_bytes, signature_type):
                return sig_bytes
        return None

    def _fetch_layer(
        self, client: OrasClient, image_ref: ImageReference, sig_digest: str
    ) -> bytes | None:
        """Fetch first layer blob from a signature artifact manifest."""
        try:
            manifest, _ = client.get_manifest(image_ref.with_digest(sig_digest))
            layers = manifest.get("layers", [])
            if not layers or not layers[0].get("digest"):
                return None
            return client.pull_blob(image_ref, layers[0]["digest"])
        except Exception:
            return None

    def _matches_type(self, sig_bytes: bytes, sig_type: str | None) -> bool:
        """Check if signature matches expected type (sigstore/key)."""
        if sig_type is None:
            return True
        try:
            vm = json.loads(sig_bytes).get("verificationMaterial", {})
            if sig_type == "sigstore":
                return "certificate" in vm
            if sig_type == "key":
                return "publicKey" in vm
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass
        return False


class TagAttachment:
    """Signature attachment using tag-based convention (sha256-xxx.sig)."""

    def _digest_to_tag(self, digest: str) -> str:
        return digest.replace(":", "-") + ".sig"

    def attach(
        self,
        client: OrasClient,
        image_ref: ImageReference,
        signature_bundle: bytes,
        image_digest: str,
        subject_manifest_size: int = 0,  # noqa: ARG002
    ) -> str:
        sig_tag = self._digest_to_tag(image_digest)
        return client.push_signature_tag(image_ref, signature_bundle, sig_tag)

    def fetch(
        self,
        client: OrasClient,
        image_ref: ImageReference,
        image_digest: str,
        signature_type: str | None = None,  # noqa: ARG002
    ) -> bytes | None:
        sig_tag = self._digest_to_tag(image_digest)
        try:
            manifest, _ = client.get_manifest(image_ref.with_tag(sig_tag))
            layers = manifest.get("layers", [])
            if not layers or not layers[0].get("digest"):
                return None
            return client.pull_blob(image_ref, layers[0]["digest"])
        except Exception:
            return None


def get_attachment_strategy(
    mode: AttachmentMode,
) -> ReferrersAttachment | TagAttachment:
    """Get the attachment strategy for the given mode."""
    if mode == AttachmentMode.REFERRERS:
        return ReferrersAttachment()
    return TagAttachment()


def try_fetch_signature(
    client: OrasClient,
    image_ref: ImageReference,
    image_digest: str,
    signature_type: str | None = None,
) -> tuple[bytes, AttachmentMode] | None:
    """Try to fetch a signature using referrers first, then tag-based."""
    ref_strategy = ReferrersAttachment()
    sig = ref_strategy.fetch(client, image_ref, image_digest, signature_type)
    if sig:
        return sig, AttachmentMode.REFERRERS

    tag_strategy = TagAttachment()
    sig = tag_strategy.fetch(client, image_ref, image_digest, signature_type)
    if sig:
        return sig, AttachmentMode.TAG

    return None
