"""
SentinelRAG — File Storage Service.

Handles secure disk storage for uploaded PDF files outside the web root.
Enforces safe random storage keys, path traversal prevention, magic bytes verification,
and streaming SHA-256 calculation.
"""
from __future__ import annotations

import hashlib
import os
import uuid
from pathlib import Path
from typing import BinaryIO, Optional, Tuple

from fastapi import UploadFile

from app.core.config import get_settings
from app.core.logging import get_logger

logger = get_logger(__name__)

PDF_MAGIC_BYTES = b"%PDF-"


class StorageValidationError(Exception):
    """Raised when file validation fails during upload."""
    def __init__(self, message: str, code: str = "VALIDATION_FAILED"):
        super().__init__(message)
        self.message = message
        self.code = code


class FileStorageService:
    """Manages secure local storage for uploaded documents."""

    def __init__(self, upload_dir: Optional[str] = None):
        self.settings = get_settings()
        self.upload_dir = Path(upload_dir or self.settings.UPLOAD_DIR).resolve()
        self._ensure_dir()

    def _ensure_dir(self) -> None:
        """Create upload directory if not present."""
        self.upload_dir.mkdir(parents=True, exist_ok=True)

    def _resolve_safe_path(self, storage_key: str) -> Path:
        """
        Resolve storage path and ensure it remains strictly inside upload_dir.
        Guards against path traversal attacks.
        """
        safe_name = os.path.basename(storage_key)
        target = (self.upload_dir / safe_name).resolve()
        if not str(target).startswith(str(self.upload_dir)):
            raise StorageValidationError("Path traversal attempt detected", "PATH_TRAVERSAL")
        return target

    async def save_upload_file(self, upload_file: UploadFile) -> Tuple[str, int, str]:
        """
        Validate and stream an uploaded file to secure storage.

        Verifies:
          - File extension is .pdf
          - Declared MIME type is application/pdf
          - File header starts with %PDF- (magic bytes)
          - File size does not exceed MAX_UPLOAD_MB

        Returns:
            Tuple[storage_key, file_size_bytes, sha256_hash]
        """
        # 1. Validate filename & extension
        filename = upload_file.filename or ""
        if not filename.lower().endswith(".pdf"):
            raise StorageValidationError("Only PDF files are supported", "INVALID_FILE_TYPE")

        # 2. Validate declared MIME type
        content_type = upload_file.content_type or ""
        if content_type.lower() not in {"application/pdf", "application/x-pdf"}:
            raise StorageValidationError(
                f"Invalid MIME type '{content_type}'. Must be 'application/pdf'",
                "INVALID_MIME_TYPE",
            )

        storage_key = f"{uuid.uuid4().hex}.pdf"
        target_path = self._resolve_safe_path(storage_key)

        max_bytes = self.settings.MAX_UPLOAD_MB * 1024 * 1024
        sha256 = hashlib.sha256()
        total_size = 0
        chunk_size = 64 * 1024  # 64 KB chunks

        # Read first chunk to verify magic bytes before writing
        first_chunk = await upload_file.read(chunk_size)
        if not first_chunk:
            raise StorageValidationError("Uploaded file is empty", "EMPTY_FILE")

        if not first_chunk.startswith(PDF_MAGIC_BYTES):
            raise StorageValidationError(
                "Invalid file header: file is not a valid PDF document",
                "INVALID_PDF_SIGNATURE",
            )

        try:
            with open(target_path, "wb") as f:
                f.write(first_chunk)
                total_size += len(first_chunk)
                sha256.update(first_chunk)

                while True:
                    chunk = await upload_file.read(chunk_size)
                    if not chunk:
                        break
                    total_size += len(chunk)
                    if total_size > max_bytes:
                        raise StorageValidationError(
                            f"File size exceeds maximum allowed limit of {self.settings.MAX_UPLOAD_MB} MB",
                            "FILE_TOO_LARGE",
                        )
                    sha256.update(chunk)
                    f.write(chunk)
        except Exception:
            # Clean up partial file on failure
            if target_path.exists():
                target_path.unlink()
            raise

        logger.info(
            "File saved to storage successfully",
            extra={"storage_key": storage_key, "size_bytes": total_size},
        )
        return storage_key, total_size, sha256.hexdigest()

    def get_file_path(self, storage_key: str) -> Path:
        """Get absolute path to a stored file, verifying path safety."""
        target = self._resolve_safe_path(storage_key)
        if not target.exists():
            raise FileNotFoundError(f"Storage file '{storage_key}' not found")
        return target

    def delete_file(self, storage_key: str) -> bool:
        """Delete stored file from disk."""
        try:
            target = self._resolve_safe_path(storage_key)
            if target.exists():
                target.unlink()
                logger.info("File deleted from storage", extra={"storage_key": storage_key})
                return True
            return False
        except Exception as exc:  # noqa: BLE001
            logger.warning("Error deleting file from storage", extra={"storage_key": storage_key, "error": str(exc)})
            return False


storage_service = FileStorageService()

