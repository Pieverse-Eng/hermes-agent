"""Direct tests for ``agent.image_gen_provider.save_url_image``."""

from __future__ import annotations

import sys

import pytest

from tools.safe_http import SafeHttpError, SafeHttpResponse


PNG_1PX = bytes.fromhex(
    "89504e470d0a1a0a0000000d49484452000000010000000108020000009077"
    "53de00000010494441547801635c0e000000feff03000006000557bfabd400"
    "00000049454e44ae426082"
)


@pytest.fixture
def safe_image_fetch(tmp_path, monkeypatch):
    """Isolate the cache and replace only the already-tested network boundary."""
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / ".hermes"))
    (tmp_path / ".hermes").mkdir()
    for mod in list(sys.modules):
        if mod.startswith("hermes_constants") or mod.startswith(
            "agent.image_gen_provider"
        ):
            sys.modules.pop(mod, None)

    def fake_request(method, url, **kwargs):
        assert method == "GET"
        if url.endswith("/404"):
            return SafeHttpResponse(404, {}, b"", url, 0)
        if url.endswith("/oversize"):
            raise SafeHttpError("RESPONSE_TOO_LARGE", "Response exceeds the byte limit")
        if url.endswith("/empty"):
            return SafeHttpResponse(200, {"content-type": "image/png"}, b"", url, 0)
        if url.endswith("/jpeg-type"):
            return SafeHttpResponse(
                200,
                {"content-type": "image/jpeg"},
                PNG_1PX,
                url,
                0,
            )
        if "/octet-stream" in url:
            return SafeHttpResponse(
                200,
                {"content-type": "application/octet-stream"},
                PNG_1PX,
                url,
                0,
            )
        return SafeHttpResponse(
            200,
            {"content-type": "image/png"},
            PNG_1PX,
            url,
            0,
        )

    monkeypatch.setattr("tools.safe_http.safe_http_request", fake_request)
    return "https://media.example"


class TestSaveUrlImage:
    def test_writes_real_bytes_to_hermes_home_cache(self, safe_image_fetch):
        from agent.image_gen_provider import save_url_image

        path = save_url_image(f"{safe_image_fetch}/image.png", prefix="xai_test")

        assert path.exists()
        assert path.read_bytes() == PNG_1PX
        assert "cache/images" in str(path)
        assert path.suffix == ".png"

    def test_image_magic_wins_over_mismatched_content_type(self, safe_image_fetch):
        from agent.image_gen_provider import save_url_image

        path = save_url_image(f"{safe_image_fetch}/jpeg-type", prefix="xai_test")
        assert path.suffix == ".png"

    def test_octet_stream_uses_image_magic_not_url_suffix(self, safe_image_fetch):
        from agent.image_gen_provider import save_url_image

        path = save_url_image(
            f"{safe_image_fetch}/octet-stream?name=not-trusted.jpg",
            prefix="xai_test",
        )
        assert path.suffix == ".png"

    def test_404_raises(self, safe_image_fetch):
        from agent.image_gen_provider import save_url_image

        with pytest.raises(SafeHttpError, match="HTTP 404"):
            save_url_image(f"{safe_image_fetch}/404")

    def test_empty_body_raises_without_writing_file(self, safe_image_fetch):
        from agent.image_gen_provider import _images_cache_dir, save_url_image

        before = set(_images_cache_dir().glob("*"))
        with pytest.raises(ValueError, match="not a supported raster image"):
            save_url_image(f"{safe_image_fetch}/empty")
        assert set(_images_cache_dir().glob("*")) == before

    def test_oversize_raises_without_writing_file(self, safe_image_fetch):
        from agent.image_gen_provider import _images_cache_dir, save_url_image

        before = set(_images_cache_dir().glob("*"))
        with pytest.raises(SafeHttpError) as excinfo:
            save_url_image(f"{safe_image_fetch}/oversize", max_bytes=1024 * 1024)
        assert excinfo.value.code == "RESPONSE_TOO_LARGE"
        assert set(_images_cache_dir().glob("*")) == before

    def test_unique_filenames_avoid_collision(self, safe_image_fetch):
        from agent.image_gen_provider import save_url_image

        path1 = save_url_image(f"{safe_image_fetch}/image.png", prefix="xai_collision")
        path2 = save_url_image(f"{safe_image_fetch}/image.png", prefix="xai_collision")
        assert path1 != path2
