from pathlib import Path

import pytest

pytest.importorskip("PIL")
from PIL import Image

from aegismeta.plugins.image_exif_extractor import ImageExifExtractor


def test_image_extractor_reads(tmp_path: Path) -> None:
    path = tmp_path / "image.jpg"
    img = Image.new("RGB", (10, 10), color="red")
    img.save(path)
    extractor = ImageExifExtractor()
    assert extractor.supports(path)
    result = extractor.extract(path)
    assert result is not None
    assert isinstance(result.metadata, list)
