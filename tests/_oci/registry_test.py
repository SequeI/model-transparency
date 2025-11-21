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

"""Tests for OCI registry client."""

from unittest import mock

import pytest
import requests

from model_signing._oci import registry
from model_signing._oci.registry import ImageReference
from model_signing._oci.registry import OrasClient
from model_signing._oci.registry import is_image_reference


class TestImageReference:
    def test_parse_full_reference_with_tag(self):
        ref = ImageReference.parse("quay.io/user/model:latest")
        assert ref.registry == "quay.io"
        assert ref.repository == "user/model"
        assert ref.tag == "latest"
        assert ref.digest is None

    def test_parse_full_reference_with_digest(self):
        digest = "sha256:" + "a" * 64
        ref = ImageReference.parse(f"ghcr.io/org/model@{digest}")
        assert ref.registry == "ghcr.io"
        assert ref.repository == "org/model"
        assert ref.tag is None
        assert ref.digest == digest

    def test_parse_nested_repository(self):
        ref = ImageReference.parse("registry.example.com/org/team/model:v1.0")
        assert ref.registry == "registry.example.com"
        assert ref.repository == "org/team/model"
        assert ref.tag == "v1.0"

    def test_parse_registry_with_port(self):
        ref = ImageReference.parse("localhost:5000/mymodel:test")
        assert ref.registry == "localhost:5000"
        assert ref.repository == "mymodel"
        assert ref.tag == "test"

    def test_parse_requires_slash(self):
        with pytest.raises(ValueError, match="missing /"):
            ImageReference.parse("ubuntu:latest")

    def test_parse_requires_tag_or_digest(self):
        with pytest.raises(ValueError, match="must have :tag or @digest"):
            ImageReference.parse("quay.io/user/model")

    def test_parse_invalid_digest_format(self):
        with pytest.raises(ValueError, match="Invalid digest format"):
            ImageReference.parse("quay.io/user/model@invalid-digest")

    def test_parse_invalid_short_digest(self):
        with pytest.raises(ValueError, match="Invalid digest format"):
            ImageReference.parse("quay.io/user/model@sha256:abc")

    def test_parse_empty_repository_raises(self):
        with pytest.raises(ValueError, match="Invalid"):
            ImageReference.parse("quay.io/:tag")

    def test_str_with_tag(self):
        ref = ImageReference.parse("quay.io/user/model:v1")
        assert str(ref) == "quay.io/user/model:v1"

    def test_str_with_digest(self):
        digest = "sha256:" + "a" * 64
        ref = ImageReference.parse(f"quay.io/user/model@{digest}")
        assert str(ref) == f"quay.io/user/model@{digest}"

    def test_reference_property_with_tag(self):
        ref = ImageReference.parse("quay.io/user/model:v1")
        assert ref.reference == "v1"

    def test_reference_property_with_digest(self):
        digest = "sha256:" + "a" * 64
        ref = ImageReference.parse(f"quay.io/user/model@{digest}")
        assert ref.reference == digest

    def test_with_digest(self):
        ref = ImageReference.parse("quay.io/user/model:v1")
        new_ref = ref.with_digest("sha256:newdigest")
        assert new_ref.digest == "sha256:newdigest"
        assert new_ref.tag is None
        assert new_ref.registry == ref.registry
        assert new_ref.repository == ref.repository

    def test_with_tag(self):
        digest = "sha256:" + "a" * 64
        ref = ImageReference.parse(f"quay.io/user/model@{digest}")
        new_ref = ref.with_tag("newtag")
        assert new_ref.tag == "newtag"
        assert new_ref.digest is None
        assert new_ref.registry == ref.registry
        assert new_ref.repository == ref.repository


class TestIsImageReference:
    def test_full_image_reference(self):
        assert is_image_reference("quay.io/user/model:latest") is True

    def test_image_with_digest(self):
        digest = "sha256:" + "a" * 64
        assert is_image_reference(f"ghcr.io/org/model@{digest}") is True

    def test_local_path_with_slash(self):
        assert is_image_reference("/path/to/model") is False

    def test_relative_path(self):
        assert is_image_reference("./model") is False

    def test_home_relative_path(self):
        assert is_image_reference("~/models/mymodel") is False

    def test_json_file(self):
        assert is_image_reference("manifest.json") is False

    def test_empty_string(self):
        assert is_image_reference("") is False

    def test_registry_without_tag_or_digest(self):
        assert is_image_reference("quay.io/user/model") is False

    def test_simple_name_without_slash(self):
        assert is_image_reference("model:v1") is False

    def test_registry_with_port(self):
        assert is_image_reference("localhost:5000/myimage:latest") is True


class TestOrasClient:
    @mock.patch("oras.provider.Registry")
    def test_get_manifest(self, mock_registry_class):
        mock_reg = mock.MagicMock()
        mock_registry_class.return_value = mock_reg
        mock_reg.get_manifest.return_value = {"schemaVersion": 2}

        client = OrasClient()
        ref = ImageReference.parse("quay.io/user/model:latest")
        manifest, digest = client.get_manifest(ref)

        assert manifest == {"schemaVersion": 2}
        assert digest.startswith("sha256:")
        mock_reg.auth.load_configs.assert_called_once()

    @mock.patch("oras.provider.Registry")
    def test_resolve_digest_with_existing_digest(self, mock_registry_class):
        client = OrasClient()
        digest = "sha256:" + "a" * 64
        ref = ImageReference.parse(f"quay.io/user/model@{digest}")

        result = client.resolve_digest(ref)
        assert result == digest
        mock_registry_class.assert_not_called()

    @mock.patch("oras.provider.Registry")
    def test_resolve_digest_fetches_manifest(self, mock_registry_class):
        mock_reg = mock.MagicMock()
        mock_registry_class.return_value = mock_reg
        mock_reg.get_manifest.return_value = {"schemaVersion": 2}

        client = OrasClient()
        ref = ImageReference.parse("quay.io/user/model:latest")
        result = client.resolve_digest(ref)

        assert result.startswith("sha256:")
        mock_reg.get_manifest.assert_called_once()

    @mock.patch("oras.provider.Registry")
    def test_push_blob_already_exists(self, mock_registry_class):
        mock_reg = mock.MagicMock()
        mock_registry_class.return_value = mock_reg
        mock_response = mock.MagicMock()
        mock_response.status_code = 200
        mock_reg.do_request.return_value = mock_response

        client = OrasClient()
        ref = ImageReference.parse("quay.io/user/model:latest")
        digest = client.push_blob(ref, b"test data", "application/octet-stream")

        assert digest.startswith("sha256:")
        mock_reg.do_request.assert_called_once()

    @mock.patch("oras.provider.Registry")
    def test_push_blob_uploads_new(self, mock_registry_class):
        mock_reg = mock.MagicMock()
        mock_registry_class.return_value = mock_reg
        head_response = mock.MagicMock()
        head_response.status_code = 404
        post_response = mock.MagicMock()
        post_response.headers = {"Location": "/upload/path?upload_id=123"}
        put_response = mock.MagicMock()
        mock_reg.do_request.side_effect = [
            requests.HTTPError(),
            post_response,
            put_response,
        ]

        client = OrasClient()
        ref = ImageReference.parse("quay.io/user/model:latest")
        digest = client.push_blob(ref, b"test data", "application/octet-stream")

        assert digest.startswith("sha256:")
        assert mock_reg.do_request.call_count == 3

    @mock.patch("oras.provider.Registry")
    def test_push_blob_no_location_raises(self, mock_registry_class):
        mock_reg = mock.MagicMock()
        mock_registry_class.return_value = mock_reg
        post_response = mock.MagicMock()
        post_response.headers = {}
        mock_reg.do_request.side_effect = [requests.HTTPError(), post_response]

        client = OrasClient()
        ref = ImageReference.parse("quay.io/user/model:latest")

        with pytest.raises(ValueError, match="upload location"):
            client.push_blob(ref, b"test", "application/octet-stream")

    @mock.patch("oras.provider.Registry")
    def test_push_manifest(self, mock_registry_class):
        mock_reg = mock.MagicMock()
        mock_registry_class.return_value = mock_reg

        client = OrasClient()
        ref = ImageReference.parse("quay.io/user/model:latest")
        digest = client.push_manifest(ref, {"schemaVersion": 2})

        assert digest.startswith("sha256:")
        mock_reg.do_request.assert_called_once()

    @mock.patch("oras.provider.Registry")
    def test_push_signature(self, mock_registry_class):
        mock_reg = mock.MagicMock()
        mock_registry_class.return_value = mock_reg
        mock_response = mock.MagicMock()
        mock_response.status_code = 200
        mock_reg.do_request.return_value = mock_response

        client = OrasClient()
        ref = ImageReference.parse("quay.io/user/model:latest")
        digest = client.push_signature(
            ref, b'{"sig": "data"}', "sha256:abc", 100
        )

        assert digest.startswith("sha256:")

    @mock.patch("oras.provider.Registry")
    def test_push_signature_tag(self, mock_registry_class):
        mock_reg = mock.MagicMock()
        mock_registry_class.return_value = mock_reg
        mock_response = mock.MagicMock()
        mock_response.status_code = 200
        mock_reg.do_request.return_value = mock_response

        client = OrasClient()
        ref = ImageReference.parse("quay.io/user/model:latest")
        digest = client.push_signature_tag(ref, b'{"sig": "data"}', "v1.sig")

        assert digest.startswith("sha256:")

    @mock.patch("oras.provider.Registry")
    def test_get_referrers(self, mock_registry_class):
        mock_reg = mock.MagicMock()
        mock_registry_class.return_value = mock_reg
        mock_response = mock.MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "manifests": [{"digest": "sha256:abc", "artifactType": "test"}]
        }
        mock_reg.do_request.return_value = mock_response

        client = OrasClient()
        digest = "sha256:" + "a" * 64
        ref = ImageReference.parse(f"quay.io/user/model@{digest}")
        result = client.get_referrers(ref)

        assert len(result) == 1
        assert result[0]["digest"] == "sha256:abc"

    @mock.patch("oras.provider.Registry")
    def test_get_referrers_filters_by_type(self, mock_registry_class):
        mock_reg = mock.MagicMock()
        mock_registry_class.return_value = mock_reg
        mock_response = mock.MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "manifests": [
                {"digest": "sha256:abc", "artifactType": "type1"},
                {"digest": "sha256:def", "artifactType": "type2"},
            ]
        }
        mock_reg.do_request.return_value = mock_response

        client = OrasClient()
        digest = "sha256:" + "a" * 64
        ref = ImageReference.parse(f"quay.io/user/model@{digest}")
        result = client.get_referrers(ref, artifact_type="type1")

        assert len(result) == 1
        assert result[0]["digest"] == "sha256:abc"

    @mock.patch("oras.provider.Registry")
    def test_get_referrers_returns_empty_on_404(self, mock_registry_class):
        mock_reg = mock.MagicMock()
        mock_registry_class.return_value = mock_reg
        error = requests.HTTPError()
        error.response = mock.MagicMock()
        error.response.status_code = 404
        mock_reg.do_request.side_effect = error

        client = OrasClient()
        digest = "sha256:" + "a" * 64
        ref = ImageReference.parse(f"quay.io/user/model@{digest}")
        result = client.get_referrers(ref)

        assert result == []

    @mock.patch("oras.provider.Registry")
    def test_get_referrers_returns_empty_on_non_200(self, mock_registry_class):
        mock_reg = mock.MagicMock()
        mock_registry_class.return_value = mock_reg
        mock_response = mock.MagicMock()
        mock_response.status_code = 500
        mock_reg.do_request.return_value = mock_response

        client = OrasClient()
        digest = "sha256:" + "a" * 64
        ref = ImageReference.parse(f"quay.io/user/model@{digest}")
        result = client.get_referrers(ref)

        assert result == []

    @mock.patch("oras.provider.Registry")
    def test_pull_blob(self, mock_registry_class):
        mock_reg = mock.MagicMock()
        mock_registry_class.return_value = mock_reg
        mock_blob_response = mock.MagicMock()
        mock_blob_response.content = b"blob data"
        mock_reg.get_blob.return_value = mock_blob_response

        client = OrasClient()
        ref = ImageReference.parse("quay.io/user/model:latest")
        result = client.pull_blob(ref, "sha256:abc")

        assert result == b"blob data"

    def test_base_url_https(self):
        client = OrasClient()
        ref = ImageReference.parse("quay.io/user/model:latest")
        url = client._base_url(ref)
        assert url == "https://quay.io"

    def test_base_url_http_insecure(self):
        client = OrasClient(insecure=True)
        ref = ImageReference.parse("quay.io/user/model:latest")
        url = client._base_url(ref)
        assert url == "http://quay.io"

    def test_base_url_docker_hub(self):
        client = OrasClient()
        ref = ImageReference(
            registry="docker.io",
            repository="library/ubuntu",
            tag="latest",
            digest=None,
        )
        url = client._base_url(ref)
        assert url == "https://registry-1.docker.io"


class TestCalculateManifestDigest:
    def test_calculates_correct_digest(self):
        manifest = {"schemaVersion": 2, "mediaType": "test"}
        digest = registry._calculate_manifest_digest(manifest)
        assert digest.startswith("sha256:")
        assert len(digest) == 71  # "sha256:" + 64 hex chars


class TestIsImageReferenceEdgeCases:
    def test_invalid_digest_format_returns_false(self):
        assert is_image_reference("quay.io/user/model@invalid") is False


class TestOrasClientEdgeCases:
    @mock.patch("oras.provider.Registry")
    def test_get_referrers_raises_on_non_404_error(self, mock_registry_class):
        mock_reg = mock.MagicMock()
        mock_registry_class.return_value = mock_reg
        error = requests.HTTPError()
        error.response = mock.MagicMock()
        error.response.status_code = 500
        mock_reg.do_request.side_effect = error

        client = OrasClient()
        digest = "sha256:" + "a" * 64
        ref = ImageReference.parse(f"quay.io/user/model@{digest}")

        with pytest.raises(requests.HTTPError):
            client.get_referrers(ref)
