"""
SentinelRAG — Chat & RAG AI Agent API Endpoints.

Endpoints:
  POST   /api/v1/chat/conversations                   — Create a new conversation
  GET    /api/v1/chat/conversations                   — List user's conversations
  GET    /api/v1/chat/conversations/{conversation_id} — Get conversation details and message history
  POST   /api/v1/chat/conversations/{conversation_id}/messages — Submit question, execute RAG, return grounded answer
  DELETE /api/v1/chat/conversations/{conversation_id} — Delete conversation and messages
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from app.api.dependencies import get_current_active_user
from app.db.conversations_repo import conversations_repo
from app.models.user import UserInDB
from app.schemas.chat import (
    ChatAnswerResponse,
    ConversationCreateRequest,
    ConversationDetailResponse,
    ConversationListResponse,
    ConversationResponse,
    MessageCreateRequest,
    MessageResponse,
)
from app.services.rag_service import ConversationNotFoundError, rag_service
from app.utils.correlation import get_correlation_id

router = APIRouter(prefix="/chat", tags=["Chat & RAG"])


def _envelope(data: dict | list, correlation_id: str) -> dict:
    """Format success response according to standard API envelope."""
    return {"data": data, "meta": {"correlation_id": correlation_id}}


@router.post("/conversations", status_code=status.HTTP_201_CREATED)
async def create_conversation(
    request: Request,
    payload: Optional[ConversationCreateRequest] = None,
    current_user: UserInDB = Depends(get_current_active_user),
) -> dict:
    """Create a new conversation session for the authenticated user."""
    correlation_id = get_correlation_id(request)
    title = payload.title if payload else None
    conv = await conversations_repo.create_conversation(
        owner_id=current_user.id,
        title=title,
    )
    return _envelope(conv.to_public_dict(), correlation_id)


@router.get("/conversations")
async def list_conversations(
    request: Request,
    limit: int = Query(default=50, ge=1, le=100),
    skip: int = Query(default=0, ge=0),
    current_user: UserInDB = Depends(get_current_active_user),
) -> dict:
    """List all conversations belonging to the authenticated user."""
    correlation_id = get_correlation_id(request)
    convs, total = await conversations_repo.list_conversations(
        owner_id=current_user.id,
        limit=limit,
        skip=skip,
    )
    return _envelope(
        {
            "conversations": [c.to_public_dict() for c in convs],
            "total": total,
        },
        correlation_id,
    )


@router.get("/conversations/{conversation_id}")
async def get_conversation(
    conversation_id: str,
    request: Request,
    current_user: UserInDB = Depends(get_current_active_user),
) -> dict:
    """
    Retrieve conversation details and chronological message history.
    Enforces tenant isolation: returns 404 if not found or owned by a different user.
    """
    correlation_id = get_correlation_id(request)
    conv = await conversations_repo.get_conversation(
        conversation_id=conversation_id,
        owner_id=current_user.id,
    )
    if not conv:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Conversation not found")

    messages = await conversations_repo.list_messages(
        conversation_id=conversation_id,
        owner_id=current_user.id,
    )

    return _envelope(
        {
            "conversation": conv.to_public_dict(),
            "messages": [m.to_public_dict() for m in messages],
        },
        correlation_id,
    )


@router.post("/conversations/{conversation_id}/messages")
async def send_message(
    conversation_id: str,
    payload: MessageCreateRequest,
    request: Request,
    current_user: UserInDB = Depends(get_current_active_user),
) -> dict:
    """
    Submit a user question to the RAG AI agent.
    Retrieves authorized chunks, constructs bounded prompt, queries Gemini,
    validates citations, and persists messages.
    """
    correlation_id = get_correlation_id(request)
    try:
        result = await rag_service.answer_question(
            conversation_id=conversation_id,
            owner_id=current_user.id,
            question=payload.content,
            correlation_id=correlation_id,
        )
        return _envelope(result, correlation_id)
    except ConversationNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Conversation not found")
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred processing the chat request: {exc}",
        ) from exc


@router.delete("/conversations/{conversation_id}")
async def delete_conversation(
    conversation_id: str,
    request: Request,
    current_user: UserInDB = Depends(get_current_active_user),
) -> dict:
    """
    Delete a conversation and all its persisted messages.
    Enforces tenant isolation: returns 404 if not found or owned by a different user.
    """
    correlation_id = get_correlation_id(request)
    deleted = await conversations_repo.delete_conversation(
        conversation_id=conversation_id,
        owner_id=current_user.id,
    )
    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Conversation not found")

    return _envelope(
        {
            "conversation_id": conversation_id,
            "deleted": True,
            "message": "Conversation deleted successfully",
        },
        correlation_id,
    )

