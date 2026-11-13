from django.conf import settings
from django.core.files.storage import FileSystemStorage
from django.utils.deconstruct import deconstructible


@deconstructible
class PrivateArtifactStorage(FileSystemStorage):
    """Private local or S3-compatible storage with no public URL mapping."""

    def __init__(self, *args, **kwargs):
        kwargs.setdefault("location", settings.PRIVATE_ARTIFACT_ROOT)
        kwargs.setdefault("base_url", None)
        kwargs.setdefault("file_permissions_mode", 0o600)
        kwargs.setdefault("directory_permissions_mode", 0o700)
        super().__init__(*args, **kwargs)
        self._s3_storage = None
        if settings.PRIVATE_ARTIFACT_STORAGE_BACKEND == "s3":
            from storages.backends.s3 import S3Storage

            self._s3_storage = S3Storage(
                bucket_name=settings.PRIVATE_ARTIFACT_S3_BUCKET,
                endpoint_url=settings.PRIVATE_ARTIFACT_S3_ENDPOINT,
                access_key=settings.PRIVATE_ARTIFACT_S3_ACCESS_KEY,
                secret_key=settings.PRIVATE_ARTIFACT_S3_SECRET_KEY,
                region_name=settings.PRIVATE_ARTIFACT_S3_REGION,
                addressing_style="path",
                default_acl=None,
                querystring_auth=True,
                file_overwrite=False,
            )

    def _open(self, name, mode="rb"):
        if self._s3_storage:
            return self._s3_storage._open(name, mode)
        return super()._open(name, mode)

    def _save(self, name, content):
        if self._s3_storage:
            return self._s3_storage._save(name, content)
        return super()._save(name, content)

    def delete(self, name):
        if self._s3_storage:
            return self._s3_storage.delete(name)
        return super().delete(name)

    def exists(self, name):
        if self._s3_storage:
            return self._s3_storage.exists(name)
        return super().exists(name)

    def listdir(self, path):
        if self._s3_storage:
            return self._s3_storage.listdir(path)
        return super().listdir(path)

    def size(self, name):
        if self._s3_storage:
            return self._s3_storage.size(name)
        return super().size(name)

    def path(self, name):
        if self._s3_storage:
            raise NotImplementedError("S3 artifact objects do not have a local filesystem path")
        return super().path(name)

    def get_accessed_time(self, name):
        if self._s3_storage:
            return self._s3_storage.get_accessed_time(name)
        return super().get_accessed_time(name)

    def get_created_time(self, name):
        if self._s3_storage:
            return self._s3_storage.get_created_time(name)
        return super().get_created_time(name)

    def get_modified_time(self, name):
        if self._s3_storage:
            return self._s3_storage.get_modified_time(name)
        return super().get_modified_time(name)

    def url(self, name):
        raise ValueError("Private artifacts have no public URL")
