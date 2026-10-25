from django.conf import settings
from django.core.files.storage import FileSystemStorage
from django.utils.deconstruct import deconstructible


@deconstructible
class PrivateArtifactStorage(FileSystemStorage):
    """Local private storage with no public URL mapping."""

    def __init__(self, *args, **kwargs):
        kwargs.setdefault("location", settings.PRIVATE_ARTIFACT_ROOT)
        kwargs.setdefault("base_url", None)
        kwargs.setdefault("file_permissions_mode", 0o600)
        kwargs.setdefault("directory_permissions_mode", 0o700)
        super().__init__(*args, **kwargs)

    def url(self, name):
        raise ValueError("Private artifacts have no public URL")
