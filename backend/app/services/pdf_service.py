"""
SentinelRAG — PDF Extraction Service.

Uses PyMuPDF to extract text from PDF documents page by page while tracking
page numbers, character counts, and rejecting password-protected or empty/corrupted files.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Union

import pymupdf

from app.core.logging import get_logger

logger = get_logger(__name__)


class PDFExtractionError(Exception):
    """Raised when PDF extraction or validation fails."""
    pass


class PDFService:
    """Service for extracting structured text from PDF files."""

    @staticmethod
    def extract_text_by_page(file_path: Union[str, Path]) -> list[dict[str, Any]]:
        """
        Extract text from a PDF file page by page.

        Returns:
            list[dict]: [
                {"page_number": int, "text": str, "char_count": int},
                ...
            ]

        Raises:
            PDFExtractionError: If PDF is encrypted, corrupted, or has no extractable text.
        """
        path = Path(file_path)
        if not path.is_file():
            raise PDFExtractionError(f"File not found: {path.name}")

        try:
            doc = pymupdf.open(str(path))
        except Exception as exc:
            logger.warning("Failed to open PDF file", extra={"file": path.name, "error": str(exc)})
            raise PDFExtractionError(f"Corrupted or invalid PDF file: {exc}") from exc

        try:
            if doc.is_encrypted:
                raise PDFExtractionError("PDF is encrypted or password-protected and cannot be processed.")

            page_count = len(doc)
            if page_count == 0:
                raise PDFExtractionError("PDF has no pages.")

            extracted_pages: list[dict[str, Any]] = []
            total_chars = 0

            for page_idx in range(page_count):
                page = doc[page_idx]
                page_text = page.get_text("text") or ""
                # Strip excessive surrounding whitespace per page
                cleaned_text = page_text.strip()
                char_count = len(cleaned_text)
                total_chars += char_count

                extracted_pages.append({
                    "page_number": page_idx + 1,  # 1-indexed
                    "text": cleaned_text,
                    "char_count": char_count,
                })

            if total_chars == 0:
                raise PDFExtractionError(
                    "PDF contains no extractable text (scanned or image-only PDFs are not supported)."
                )

            logger.info(
                "Successfully extracted text from PDF",
                extra={
                    "file": path.name,
                    "pages": page_count,
                    "total_chars": total_chars,
                },
            )
            return extracted_pages

        finally:
            doc.close()


pdf_service = PDFService()

