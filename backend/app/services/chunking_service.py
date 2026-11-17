"""
SentinelRAG — Text Chunking Service.

Chunks document pages into overlapping segments while preserving page boundaries,
sentence boundaries, and document metadata. Uses deterministic chunk IDs.
"""
from __future__ import annotations

import re
from typing import Any, Optional

from app.core.config import get_settings
from app.core.logging import get_logger

logger = get_logger(__name__)


class ChunkingService:
    """Chunks extracted PDF text by page with sliding window and sentence boundary awareness."""

    def __init__(
        self,
        chunk_size_tokens: Optional[int] = None,
        chunk_overlap_tokens: Optional[int] = None,
    ):
        settings = get_settings()
        self.chunk_size_tokens = chunk_size_tokens or getattr(settings, "CHUNK_SIZE_TOKENS", 800)
        self.chunk_overlap_tokens = chunk_overlap_tokens or getattr(settings, "CHUNK_OVERLAP_TOKENS", 150)
        # Approximate 1 token ~= 4 characters for English text
        self.max_chars = self.chunk_size_tokens * 4
        self.overlap_chars = self.chunk_overlap_tokens * 4
        self.step_chars = max(self.max_chars - self.overlap_chars, self.overlap_chars)

    def _split_into_sentences(self, text: str) -> list[str]:
        """Split text into sentences or paragraphs while retaining punctuation."""
        # Split on sentence terminals followed by whitespace, or paragraph double-newlines
        paragraphs = text.split("\n\n")
        sentences: list[str] = []
        for p in paragraphs:
            p = p.strip()
            if not p:
                continue
            # Regex splits by sentence boundary
            raw_sents = re.split(r"(?<=[.!?])\s+", p)
            for s in raw_sents:
                s = s.strip()
                if s:
                    sentences.append(s)
        return sentences

    def chunk_page_text(self, page_number: int, text: str) -> list[str]:
        """
        Split a single page's text into chunks respecting chunk_size and overlap.
        Preserves sentence boundaries when practical.
        """
        text = text.strip()
        if not text:
            return []

        # If page text is smaller than maximum chunk size, keep as single chunk
        if len(text) <= self.max_chars:
            return [text]

        sentences = self._split_into_sentences(text)
        if not sentences:
            # Fallback to character slicing if sentence split didn't yield items
            sentences = [text]

        chunks: list[str] = []
        current_chunk_sents: list[str] = []
        current_length = 0

        for sent in sentences:
            sent_len = len(sent)

            # If a single sentence exceeds max_chars, split it by characters
            if sent_len > self.max_chars:
                if current_chunk_sents:
                    chunks.append(" ".join(current_chunk_sents))
                    current_chunk_sents = []
                    current_length = 0
                for i in range(0, sent_len, self.step_chars):
                    chunks.append(sent[i : i + self.max_chars])
                continue

            if current_length + sent_len + 1 > self.max_chars:
                # Emit current chunk
                if current_chunk_sents:
                    chunk_text = " ".join(current_chunk_sents)
                    chunks.append(chunk_text)

                    # Build overlap from trailing sentences
                    overlap_sents: list[str] = []
                    overlap_len = 0
                    for s in reversed(current_chunk_sents):
                        if overlap_len + len(s) + 1 <= self.overlap_chars:
                            overlap_sents.insert(0, s)
                            overlap_len += len(s) + 1
                        else:
                            break
                    current_chunk_sents = overlap_sents
                    current_length = overlap_len

            current_chunk_sents.append(sent)
            current_length += sent_len + 1

        if current_chunk_sents:
            final_text = " ".join(current_chunk_sents)
            if not chunks or final_text != chunks[-1]:
                chunks.append(final_text)

        return chunks

    def chunk_document_pages(
        self,
        document_id: str,
        owner_id: str,
        source_filename: str,
        pages: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """
        Produce structured chunks for all pages in a document.

        Returns:
            list[dict]: [
                {
                    "chunk_id": f"{document_id}_p{page_num}_c{chunk_idx}",
                    "document_id": document_id,
                    "owner_id": owner_id,
                    "page_number": page_num,
                    "chunk_index": chunk_idx,
                    "text": str,
                    "source_filename": source_filename,
                    "char_count": int,
                },
                ...
            ]
        """
        all_chunks: list[dict[str, Any]] = []

        for page in pages:
            page_num = int(page.get("page_number", 1))
            page_text = page.get("text", "")
            page_chunks = self.chunk_page_text(page_num, page_text)

            for chunk_idx, chunk_text in enumerate(page_chunks):
                chunk_id = f"{document_id}_p{page_num}_c{chunk_idx}"
                all_chunks.append({
                    "chunk_id": chunk_id,
                    "document_id": document_id,
                    "owner_id": owner_id,
                    "page_number": page_num,
                    "chunk_index": chunk_idx,
                    "text": chunk_text,
                    "source_filename": source_filename,
                    "char_count": len(chunk_text),
                })

        logger.info(
            "Document chunking completed",
            extra={
                "document_id": document_id,
                "total_pages": len(pages),
                "total_chunks": len(all_chunks),
            },
        )
        return all_chunks


chunking_service = ChunkingService()

