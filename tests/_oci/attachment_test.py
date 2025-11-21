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

"""Tests for OCI signature attachment strategies."""

import hashlib
import json

from model_signing._oci import attachment
from model_signing._oci import registry


class TestGetAttachmentStrategy:
    def test_get_referrers_strategy(self):
        strategy = attachment.get_attachment_strategy(
            attachment.AttachmentMode.REFERRERS
        )
        assert isinstance(strategy, attachment.ReferrersAttachment)

    def test_get_tag_strategy(self):
        strategy = attachment.get_attachment_strategy(
            attachment.AttachmentMode.TAG
        )
        assert isinstance(strategy, attachment.TagAttachment)


class TestTagAttachment:
    def test_digest_to_tag(self):
        strategy = attachment.TagAttachment()
        tag = strategy._digest_to_tag("sha256:abc123def456")
        assert tag == "sha256-abc123def456.sig"


class MockOrasClient(registry.OrasClient):
    def __init__(self):
        self.blobs: dict[str, bytes] = {}
        self.manifests: dict[str, dict] = {}
        self.referrers: dict[str, list[dict]] = {}
        self.signatures: dict[str, bytes] = {}

    def push_signature(
        self,
        image_ref: registry.ImageReference,
        signature_bytes: bytes,
        subject_digest: str,
        subject_size: int,
    ) -> str:
        sig_digest = f"sha256:{hashlib.sha256(signature_bytes).hexdigest()}"
        self.blobs[sig_digest] = signature_bytes
        if subject_digest not in self.referrers:
            self.referrers[subject_digest] = []
        self.referrers[subject_digest].append(
            {
                "digest": sig_digest,
                "artifactType": registry.MODEL_SIGNING_ARTIFACT_TYPE,
            }
        )
        manifest = {
            "layers": [{"digest": sig_digest}],
            "subject": {"digest": subject_digest, "size": subject_size},
        }
        self.manifests[sig_digest] = manifest
        return sig_digest

    def push_signature_tag(
        self,
        image_ref: registry.ImageReference,
        signature_bytes: bytes,
        tag: str,
    ) -> str:
        sig_digest = f"sha256:{hashlib.sha256(signature_bytes).hexdigest()}"
        self.blobs[sig_digest] = signature_bytes
        manifest = {"layers": [{"digest": sig_digest}]}
        self.manifests[tag] = manifest
        return sig_digest

    def get_manifest(
        self, image_ref: registry.ImageReference
    ) -> tuple[dict, str]:
        key = image_ref.tag if image_ref.tag else image_ref.digest
        if key in self.manifests:
            manifest = self.manifests[key]
            content = json.dumps(manifest, separators=(",", ":")).encode()
            digest = f"sha256:{hashlib.sha256(content).hexdigest()}"
            return manifest, digest
        raise Exception(f"Manifest not found: {key}")

    def pull_blob(
        self, image_ref: registry.ImageReference, digest: str
    ) -> bytes:
        if digest in self.blobs:
            return self.blobs[digest]
        raise Exception(f"Blob not found: {digest}")

    def get_referrers(
        self,
        image_ref: registry.ImageReference,
        artifact_type: str | None = None,
    ) -> list[dict]:
        digest = image_ref.digest
        refs = self.referrers.get(digest, [])
        if artifact_type:
            refs = [r for r in refs if r.get("artifactType") == artifact_type]
        return refs


class TestReferrersAttachmentIntegration:
    def test_attach_and_fetch(self):
        client = MockOrasClient()
        strategy = attachment.ReferrersAttachment()
        image_ref = registry.ImageReference.parse("quay.io/user/model:latest")
        image_digest = "sha256:imageabc123"
        signature_bundle = b'{"bundle": "data"}'

        sig_digest = strategy.attach(
            client, image_ref, signature_bundle, image_digest
        )
        assert sig_digest.startswith("sha256:")
        assert image_digest in client.referrers
        assert len(client.referrers[image_digest]) == 1

        fetched = strategy.fetch(client, image_ref, image_digest)
        assert fetched == signature_bundle


class TestTagAttachmentIntegration:
    def test_attach_and_fetch(self):
        client = MockOrasClient()
        strategy = attachment.TagAttachment()
        image_ref = registry.ImageReference.parse("quay.io/user/model:latest")
        image_digest = "sha256:imageabc123"
        signature_bundle = b'{"bundle": "data"}'

        sig_digest = strategy.attach(
            client, image_ref, signature_bundle, image_digest
        )
        assert sig_digest.startswith("sha256:")
        expected_tag = "sha256-imageabc123.sig"
        assert expected_tag in client.manifests

        fetched = strategy.fetch(client, image_ref, image_digest)
        assert fetched == signature_bundle

    def test_fetch_not_found_returns_none(self):
        client = MockOrasClient()
        strategy = attachment.TagAttachment()
        image_ref = registry.ImageReference.parse("quay.io/user/model:latest")

        fetched = strategy.fetch(client, image_ref, "sha256:nonexistent")
        assert fetched is None


class TestTryFetchSignature:
    def test_tries_referrers_first(self):
        client = MockOrasClient()
        image_ref = registry.ImageReference.parse("quay.io/user/model:latest")
        image_digest = "sha256:testimage"
        signature_bundle = b'{"from": "referrers"}'

        referrers_strategy = attachment.ReferrersAttachment()
        referrers_strategy.attach(
            client, image_ref, signature_bundle, image_digest
        )

        result = attachment.try_fetch_signature(client, image_ref, image_digest)
        assert result is not None
        sig_bytes, mode = result
        assert sig_bytes == signature_bundle
        assert mode == attachment.AttachmentMode.REFERRERS

    def test_falls_back_to_tag(self):
        client = MockOrasClient()
        image_ref = registry.ImageReference.parse("quay.io/user/model:latest")
        image_digest = "sha256:testimage"
        signature_bundle = b'{"from": "tag"}'

        tag_strategy = attachment.TagAttachment()
        tag_strategy.attach(client, image_ref, signature_bundle, image_digest)

        result = attachment.try_fetch_signature(client, image_ref, image_digest)
        assert result is not None
        sig_bytes, mode = result
        assert sig_bytes == signature_bundle
        assert mode == attachment.AttachmentMode.TAG

    def test_returns_none_when_not_found(self):
        client = MockOrasClient()
        image_ref = registry.ImageReference.parse("quay.io/user/model:latest")

        result = attachment.try_fetch_signature(
            client, image_ref, "sha256:nosig"
        )
        assert result is None


class TestReferrersAttachmentWithSize:
    def test_attach_with_subject_manifest_size(self):
        client = MockOrasClient()
        strategy = attachment.ReferrersAttachment()
        image_ref = registry.ImageReference.parse("quay.io/user/model:latest")
        image_digest = "sha256:imageabc123"
        signature_bundle = b'{"bundle": "data"}'
        manifest_size = 1234

        sig_digest = strategy.attach(
            client,
            image_ref,
            signature_bundle,
            image_digest,
            subject_manifest_size=manifest_size,
        )
        assert sig_digest.startswith("sha256:")

        referrer = client.referrers[image_digest][0]
        ref_digest = referrer["digest"]
        manifest = client.manifests[ref_digest]
        assert manifest["subject"]["size"] == manifest_size


class TestReferrersFetchEdgeCases:
    def test_fetch_skips_referrer_without_digest(self):
        client = MockOrasClient()
        strategy = attachment.ReferrersAttachment()
        image_ref = registry.ImageReference.parse("quay.io/user/model:latest")
        image_digest = "sha256:imageabc123"

        client.referrers[image_digest] = [
            {"artifactType": registry.MODEL_SIGNING_ARTIFACT_TYPE}
        ]

        result = strategy.fetch(client, image_ref, image_digest)
        assert result is None

    def test_fetch_skips_manifest_without_layers(self):
        client = MockOrasClient()
        strategy = attachment.ReferrersAttachment()
        image_ref = registry.ImageReference.parse("quay.io/user/model:latest")
        image_digest = "sha256:imageabc123"

        ref_digest = "sha256:ref123"
        artifact_type = registry.MODEL_SIGNING_ARTIFACT_TYPE
        client.referrers[image_digest] = [
            {"digest": ref_digest, "artifactType": artifact_type}
        ]
        client.manifests[ref_digest] = {"layers": []}

        result = strategy.fetch(client, image_ref, image_digest)
        assert result is None

    def test_fetch_skips_layer_without_digest(self):
        client = MockOrasClient()
        strategy = attachment.ReferrersAttachment()
        image_ref = registry.ImageReference.parse("quay.io/user/model:latest")
        image_digest = "sha256:imageabc123"

        ref_digest = "sha256:ref123"
        artifact_type = registry.MODEL_SIGNING_ARTIFACT_TYPE
        client.referrers[image_digest] = [
            {"digest": ref_digest, "artifactType": artifact_type}
        ]
        client.manifests[ref_digest] = {"layers": [{"mediaType": "test"}]}

        result = strategy.fetch(client, image_ref, image_digest)
        assert result is None

    def test_fetch_skips_missing_blob(self):
        client = MockOrasClient()
        strategy = attachment.ReferrersAttachment()
        image_ref = registry.ImageReference.parse("quay.io/user/model:latest")
        image_digest = "sha256:imageabc123"

        ref_digest = "sha256:ref123"
        layer_digest = "sha256:nonexistent"
        artifact_type = registry.MODEL_SIGNING_ARTIFACT_TYPE
        client.referrers[image_digest] = [
            {"digest": ref_digest, "artifactType": artifact_type}
        ]
        client.manifests[ref_digest] = {"layers": [{"digest": layer_digest}]}

        result = strategy.fetch(client, image_ref, image_digest)
        assert result is None


class TestSignatureTypeFiltering:
    def test_fetch_filters_by_sigstore_type(self):
        client = MockOrasClient()
        strategy = attachment.ReferrersAttachment()
        image_ref = registry.ImageReference.parse("quay.io/user/model:latest")
        image_digest = "sha256:imageabc123"

        sigstore_sig = b'{"verificationMaterial": {"certificate": "cert"}}'
        ref_digest = "sha256:ref123"
        layer_digest = "sha256:layer123"
        client.referrers[image_digest] = [
            {
                "digest": ref_digest,
                "artifactType": registry.MODEL_SIGNING_ARTIFACT_TYPE,
            }
        ]
        client.manifests[ref_digest] = {"layers": [{"digest": layer_digest}]}
        client.blobs[layer_digest] = sigstore_sig

        result = strategy.fetch(
            client, image_ref, image_digest, signature_type="sigstore"
        )
        assert result == sigstore_sig

    def test_fetch_filters_by_key_type(self):
        client = MockOrasClient()
        strategy = attachment.ReferrersAttachment()
        image_ref = registry.ImageReference.parse("quay.io/user/model:latest")
        image_digest = "sha256:imageabc123"

        key_sig = b'{"verificationMaterial": {"publicKey": {"hint": "x"}}}'
        ref_digest = "sha256:ref123"
        layer_digest = "sha256:layer123"
        client.referrers[image_digest] = [
            {
                "digest": ref_digest,
                "artifactType": registry.MODEL_SIGNING_ARTIFACT_TYPE,
            }
        ]
        client.manifests[ref_digest] = {"layers": [{"digest": layer_digest}]}
        client.blobs[layer_digest] = key_sig

        result = strategy.fetch(
            client, image_ref, image_digest, signature_type="key"
        )
        assert result == key_sig

    def test_fetch_skips_wrong_type(self):
        client = MockOrasClient()
        strategy = attachment.ReferrersAttachment()
        image_ref = registry.ImageReference.parse("quay.io/user/model:latest")
        image_digest = "sha256:imageabc123"

        sigstore_sig = b'{"verificationMaterial": {"certificate": "cert"}}'
        ref_digest = "sha256:ref123"
        layer_digest = "sha256:layer123"
        client.referrers[image_digest] = [
            {
                "digest": ref_digest,
                "artifactType": registry.MODEL_SIGNING_ARTIFACT_TYPE,
            }
        ]
        client.manifests[ref_digest] = {"layers": [{"digest": layer_digest}]}
        client.blobs[layer_digest] = sigstore_sig

        result = strategy.fetch(
            client, image_ref, image_digest, signature_type="key"
        )
        assert result is None

    def test_fetch_handles_invalid_json(self):
        client = MockOrasClient()
        strategy = attachment.ReferrersAttachment()
        image_ref = registry.ImageReference.parse("quay.io/user/model:latest")
        image_digest = "sha256:imageabc123"

        ref_digest = "sha256:ref123"
        layer_digest = "sha256:layer123"
        client.referrers[image_digest] = [
            {
                "digest": ref_digest,
                "artifactType": registry.MODEL_SIGNING_ARTIFACT_TYPE,
            }
        ]
        client.manifests[ref_digest] = {"layers": [{"digest": layer_digest}]}
        client.blobs[layer_digest] = b"not valid json {{{"

        result = strategy.fetch(
            client, image_ref, image_digest, signature_type="sigstore"
        )
        assert result is None

    def test_fetch_returns_none_when_type_not_found(self):
        client = MockOrasClient()
        strategy = attachment.ReferrersAttachment()
        image_ref = registry.ImageReference.parse("quay.io/user/model:latest")
        image_digest = "sha256:imageabc123"

        result = strategy.fetch(
            client, image_ref, image_digest, signature_type="sigstore"
        )
        assert result is None


class TestTagAttachmentFetchEdgeCases:
    def test_fetch_returns_none_for_empty_layers(self):
        client = MockOrasClient()
        strategy = attachment.TagAttachment()
        image_ref = registry.ImageReference.parse("quay.io/user/model:latest")
        image_digest = "sha256:imageabc123"

        sig_tag = "sha256-imageabc123.sig"
        client.manifests[sig_tag] = {"layers": []}

        result = strategy.fetch(client, image_ref, image_digest)
        assert result is None

    def test_fetch_returns_none_for_layer_without_digest(self):
        client = MockOrasClient()
        strategy = attachment.TagAttachment()
        image_ref = registry.ImageReference.parse("quay.io/user/model:latest")
        image_digest = "sha256:imageabc123"

        sig_tag = "sha256-imageabc123.sig"
        client.manifests[sig_tag] = {"layers": [{"mediaType": "test"}]}

        result = strategy.fetch(client, image_ref, image_digest)
        assert result is None
