import React, { useState, useEffect, useRef } from 'react';
import {
  MessageSquare,
  Plus,
  Send,
  Trash2,
  ShieldCheck,
  ShieldAlert,
  FileText,
  ChevronDown,
  ChevronUp,
  Sparkles,
  RefreshCw,
  AlertCircle,
  X,
} from 'lucide-react';
import { chatApi } from '../services/api';
import type { Conversation, ChatMessage } from '../types';

export function ChatPage() {
  const [conversations, setConversations] = useState<Conversation[]>([]);
  const [activeConversationId, setActiveConversationId] = useState<string | null>(null);
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [inputText, setInputText] = useState('');

  const [isLoadingConvs, setIsLoadingConvs] = useState(true);
  const [isLoadingMessages, setIsLoadingMessages] = useState(false);
  const [isSending, setIsSending] = useState(false);

  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [expandedCitations, setExpandedCitations] = useState<Record<string, boolean>>({});

  // Delete modal state
  const [convToDelete, setConvToDelete] = useState<Conversation | null>(null);
  const [isDeleting, setIsDeleting] = useState(false);

  const messagesEndRef = useRef<HTMLDivElement>(null);
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  // Auto-scroll to bottom of messages
  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages, isSending]);

  // Load conversations list
  const loadConversations = async (autoSelectFirst = false) => {
    setIsLoadingConvs(true);
    try {
      const res = await chatApi.listConversations();
      const list = res.data.conversations || [];
      setConversations(list);

      if (autoSelectFirst && list.length > 0 && !activeConversationId) {
        selectConversation(list[0].id);
      }
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to load conversations.');
    } finally {
      setIsLoadingConvs(false);
    }
  };

  useEffect(() => {
    loadConversations(true);
  }, []);

  // Select a conversation and load its messages
  const selectConversation = async (convId: string) => {
    if (activeConversationId === convId && messages.length > 0) return;
    setActiveConversationId(convId);
    setIsLoadingMessages(true);
    setErrorMsg(null);
    try {
      const res = await chatApi.getConversation(convId);
      setMessages(res.data.messages || []);
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to load conversation history.');
    } finally {
      setIsLoadingMessages(false);
    }
  };

  // Create new conversation
  const handleCreateNewConversation = async () => {
    setErrorMsg(null);
    try {
      const res = await chatApi.createConversation();
      const newConv = res.data;
      setConversations((prev) => [newConv, ...prev]);
      setActiveConversationId(newConv.id);
      setMessages([]);
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to create new conversation.');
    }
  };

  // Send message
  const handleSendMessage = async (customPrompt?: string) => {
    const textToSend = (customPrompt || inputText).trim();
    if (!textToSend || isSending) return;

    let targetConvId = activeConversationId;

    // If no active conversation, create one first
    if (!targetConvId) {
      try {
        const newConvRes = await chatApi.createConversation();
        targetConvId = newConvRes.data.id;
        setConversations((prev) => [newConvRes.data, ...prev]);
        setActiveConversationId(targetConvId);
      } catch (err: any) {
        setErrorMsg('Could not initialize conversation.');
        return;
      }
    }

    // Optimistically show user message
    const tempUserMsg: ChatMessage = {
      id: `temp_${Date.now()}`,
      conversation_id: targetConvId,
      role: 'user',
      content: textToSend,
      citations: [],
      created_at: new Date().toISOString(),
      validation_status: 'validated',
    };

    setMessages((prev) => [...prev, tempUserMsg]);
    setInputText('');
    setIsSending(true);
    setErrorMsg(null);

    try {
      const res = await chatApi.sendMessage(targetConvId, textToSend);
      const answerData = res.data;
      // Append real assistant message
      setMessages((prev) => [...prev, answerData.message]);
      // Refresh conversations to reflect updated title
      await loadConversations(false);
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to retrieve response from AI agent.');
    } finally {
      setIsSending(false);
    }
  };

  // Handle textarea enter key
  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSendMessage();
    }
  };

  // Delete conversation
  const confirmDeleteConversation = async () => {
    if (!convToDelete) return;
    setIsDeleting(true);
    setErrorMsg(null);
    try {
      await chatApi.deleteConversation(convToDelete.id);
      setConversations((prev) => prev.filter((c) => c.id !== convToDelete.id));
      if (activeConversationId === convToDelete.id) {
        setActiveConversationId(null);
        setMessages([]);
      }
      setConvToDelete(null);
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to delete conversation.');
    } finally {
      setIsDeleting(false);
    }
  };

  const toggleCitations = (msgId: string) => {
    setExpandedCitations((prev) => ({
      ...prev,
      [msgId]: !prev[msgId],
    }));
  };

  const formatDate = (isoString: string): string => {
    try {
      const d = new Date(isoString);
      return new Intl.DateTimeFormat('en-US', {
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
      }).format(d);
    } catch {
      return isoString;
    }
  };

  const activeConv = conversations.find((c) => c.id === activeConversationId);

  return (
    <div className="flex h-[calc(100vh-8rem)] rounded-2xl border border-zinc-800/80 bg-zinc-900/60 overflow-hidden backdrop-blur-sm">
      {/* ---------------- Left Panel: Conversations History ---------------- */}
      <div className="w-72 shrink-0 border-r border-zinc-800 flex flex-col bg-zinc-950/40">
        <div className="p-3.5 border-b border-zinc-800">
          <button
            onClick={handleCreateNewConversation}
            className="w-full inline-flex items-center justify-center gap-2 px-3.5 py-2 rounded-xl text-xs font-semibold bg-indigo-600 hover:bg-indigo-500 text-white transition-all shadow-sm"
          >
            <Plus className="w-4 h-4" />
            New Chat
          </button>
        </div>

        {/* Conversations List */}
        <div className="flex-1 overflow-y-auto p-2 space-y-1">
          {isLoadingConvs ? (
            <div className="p-6 text-center text-xs text-zinc-500 flex items-center justify-center gap-2">
              <RefreshCw className="w-3.5 h-3.5 animate-spin text-indigo-400" />
              Loading chats...
            </div>
          ) : conversations.length === 0 ? (
            <div className="p-6 text-center text-xs text-zinc-500">
              <MessageSquare className="w-6 h-6 mx-auto mb-2 opacity-30 text-zinc-400" />
              No conversations yet. Start a new chat!
            </div>
          ) : (
            conversations.map((c) => {
              const isActive = c.id === activeConversationId;
              return (
                <div
                  key={c.id}
                  onClick={() => selectConversation(c.id)}
                  className={`group relative flex items-center justify-between p-2.5 rounded-xl cursor-pointer text-xs transition-all ${
                    isActive
                      ? 'bg-zinc-800/90 text-white font-medium border border-zinc-700/60'
                      : 'text-zinc-400 hover:bg-zinc-900 hover:text-zinc-200'
                  }`}
                >
                  <div className="flex items-center gap-2 min-w-0 pr-6">
                    <MessageSquare className={`w-3.5 h-3.5 shrink-0 ${isActive ? 'text-indigo-400' : 'text-zinc-500'}`} />
                    <span className="truncate">{c.title || 'Untitled Conversation'}</span>
                  </div>
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      setConvToDelete(c);
                    }}
                    title="Delete Conversation"
                    className="opacity-0 group-hover:opacity-100 p-1 rounded hover:bg-zinc-800 text-zinc-500 hover:text-rose-400 transition-opacity"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                </div>
              );
            })
          )}
        </div>
      </div>

      {/* ---------------- Main Chat Area ---------------- */}
      <div className="flex-1 flex flex-col bg-zinc-900/30">
        {/* Top Header */}
        <div className="h-14 px-5 border-b border-zinc-800 flex items-center justify-between bg-zinc-950/20">
          <div className="flex items-center gap-2.5">
            <h2 className="text-sm font-semibold text-white truncate max-w-md">
              {activeConv ? activeConv.title : 'New Chat'}
            </h2>
            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
              <ShieldCheck className="w-3 h-3" /> Grounded RAG
            </span>
          </div>
          {activeConv && (
            <button
              onClick={() => setConvToDelete(activeConv)}
              title="Delete this conversation"
              className="p-1.5 rounded-lg text-zinc-500 hover:text-rose-400 hover:bg-zinc-800/80 transition-colors"
            >
              <Trash2 className="w-4 h-4" />
            </button>
          )}
        </div>

        {/* Global Error Banner */}
        {errorMsg && (
          <div className="flex items-center justify-between px-4 py-2 bg-rose-500/10 border-b border-rose-500/20 text-rose-300 text-xs">
            <div className="flex items-center gap-2">
              <AlertCircle className="w-4 h-4 text-rose-400 shrink-0" />
              <span>{errorMsg}</span>
            </div>
            <button onClick={() => setErrorMsg(null)} className="text-rose-400 hover:text-rose-200">
              <X className="w-3.5 h-3.5" />
            </button>
          </div>
        )}

        {/* Messages Stream */}
        <div className="flex-1 overflow-y-auto p-6 space-y-5">
          {isLoadingMessages ? (
            <div className="h-full flex items-center justify-center text-xs text-zinc-500 gap-2">
              <RefreshCw className="w-4 h-4 animate-spin text-indigo-400" />
              Loading message history...
            </div>
          ) : messages.length === 0 ? (
            /* Welcome / Empty State */
            <div className="h-full flex flex-col items-center justify-center text-center max-w-lg mx-auto py-8">
              <div className="p-4 rounded-3xl bg-indigo-500/10 border border-indigo-500/20 text-indigo-400 mb-4 shadow-lg shadow-indigo-500/5">
                <Sparkles className="w-8 h-8" />
              </div>
              <h3 className="text-lg font-semibold text-white tracking-tight">SentinelRAG AI Assistant</h3>
              <p className="text-xs text-zinc-400 mt-1 max-w-md">
                Ask questions about your uploaded documents. Answers are strictly grounded in authorized vector embeddings with verifiable page citations.
              </p>

              {/* Quick Starter Suggestions */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5 mt-8 w-full">
                {[
                  'Summarize the key policies in my documents',
                  'What are the primary technical specifications?',
                  'List any security guidelines and constraints',
                  'What key dates and deadlines are mentioned?',
                ].map((prompt, idx) => (
                  <button
                    key={idx}
                    onClick={() => handleSendMessage(prompt)}
                    className="p-3 text-left rounded-xl bg-zinc-800/50 hover:bg-zinc-800/90 border border-zinc-700/50 hover:border-indigo-500/40 text-xs text-zinc-300 hover:text-white transition-all"
                  >
                    "{prompt}"
                  </button>
                ))}
              </div>
            </div>
          ) : (
            messages.map((msg) => {
              const isUser = msg.role === 'user';
              const isRejected = msg.validation_status === 'rejected';
              const isExpanded = expandedCitations[msg.id];
              return (
                <div
                  key={msg.id}
                  className={`flex flex-col ${isUser ? 'items-end' : 'items-start'} space-y-1.5`}
                >
                  <div
                    className={`max-w-2xl rounded-2xl p-4 text-sm leading-relaxed ${
                      isUser
                        ? isRejected
                          ? 'bg-rose-950/40 border border-rose-500/40 text-rose-200 shadow-md'
                          : 'bg-indigo-600 text-white shadow-md'
                        : isRejected
                          ? 'bg-rose-950/20 border border-rose-500/40 text-rose-200 shadow-sm'
                          : 'bg-zinc-900 border border-zinc-800/90 text-zinc-200 shadow-sm'
                    }`}
                  >
                    {!isUser && (
                      <div className="flex items-center justify-between text-xs font-semibold mb-2 gap-3">
                        <div className={`flex items-center gap-1.5 ${isRejected ? 'text-rose-400' : 'text-indigo-400'}`}>
                          {isRejected ? <ShieldAlert className="w-3.5 h-3.5 shrink-0" /> : <Sparkles className="w-3.5 h-3.5 shrink-0" />}
                          <span>{isRejected ? 'SentinelRAG Security Gateway' : 'SentinelRAG'}</span>
                        </div>
                        {isRejected && (
                          <span className="px-2 py-0.5 rounded-full bg-rose-500/10 text-rose-400 border border-rose-500/20 text-[10px] font-mono tracking-wide">
                            GATEWAY INTERVENTION
                          </span>
                        )}
                      </div>
                    )}
                    <div className="whitespace-pre-wrap">{msg.content}</div>

                    {/* Citations / Sources Drawer */}
                    {!isUser && msg.citations && msg.citations.length > 0 && (
                      <div className="mt-3.5 pt-3 border-t border-zinc-800/80">
                        <button
                          onClick={() => toggleCitations(msg.id)}
                          className="inline-flex items-center gap-1.5 text-xs font-medium text-emerald-400 hover:text-emerald-300 transition-colors"
                        >
                          <ShieldCheck className="w-3.5 h-3.5" />
                          <span>{msg.citations.length} Grounded Source{msg.citations.length > 1 ? 's' : ''}</span>
                          {isExpanded ? (
                            <ChevronUp className="w-3 h-3" />
                          ) : (
                            <ChevronDown className="w-3 h-3" />
                          )}
                        </button>

                        {isExpanded && (
                          <div className="mt-2.5 space-y-2">
                            {msg.citations.map((cite, cIdx) => (
                              <div
                                key={cIdx}
                                className="p-2.5 rounded-xl bg-zinc-950/70 border border-zinc-800/80 text-xs space-y-1"
                              >
                                <div className="flex items-center justify-between text-zinc-300 font-medium">
                                  <div className="flex items-center gap-1.5 truncate max-w-[280px]">
                                    <FileText className="w-3.5 h-3.5 text-indigo-400 shrink-0" />
                                    <span className="truncate">{cite.source_filename}</span>
                                  </div>
                                  <span className="px-1.5 py-0.5 rounded bg-zinc-800 text-zinc-300 text-[10px]">
                                    Page {cite.page_number}
                                  </span>
                                </div>
                                {cite.excerpt && (
                                  <p className="text-[11px] text-zinc-400 italic line-clamp-3">
                                    "{cite.excerpt}"
                                  </p>
                                )}
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                  <span className="text-[10px] text-zinc-500 px-1">
                    {formatDate(msg.created_at)}
                  </span>
                </div>
              );
            })
          )}

          {/* Thinking / Generating State */}
          {isSending && (
            <div className="flex flex-col items-start space-y-1.5">
              <div className="max-w-md rounded-2xl p-4 bg-zinc-900 border border-zinc-800 text-zinc-300 text-sm flex items-center gap-3">
                <RefreshCw className="w-4 h-4 animate-spin text-indigo-400 shrink-0" />
                <span className="text-xs text-zinc-400">
                  Retrieving authorized chunks and generating grounded answer...
                </span>
              </div>
            </div>
          )}

          <div ref={messagesEndRef} />
        </div>

        {/* Input Bar */}
        <div className="p-4 border-t border-zinc-800 bg-zinc-950/30">
          <div className="relative flex items-end gap-2 bg-zinc-900/90 border border-zinc-700/70 focus-within:border-indigo-500/80 rounded-2xl p-2 transition-all shadow-inner">
            <textarea
              ref={textareaRef}
              rows={1}
              value={inputText}
              onChange={(e) => setInputText(e.target.value)}
              onKeyDown={handleKeyDown}
              disabled={isSending}
              placeholder="Ask a question about your documents... (Shift+Enter for newline)"
              className="flex-1 bg-transparent border-0 resize-none text-sm text-zinc-200 placeholder-zinc-500 focus:outline-none focus:ring-0 max-h-32 px-2 py-1"
            />
            <button
              onClick={() => handleSendMessage()}
              disabled={!inputText.trim() || isSending}
              className="p-2 rounded-xl bg-indigo-600 hover:bg-indigo-500 disabled:bg-zinc-800 text-white disabled:text-zinc-600 transition-all shrink-0 shadow-sm"
            >
              {isSending ? (
                <RefreshCw className="w-4 h-4 animate-spin" />
              ) : (
                <Send className="w-4 h-4" />
              )}
            </button>
          </div>
          <p className="mt-2 text-center text-[11px] text-zinc-500">
            Answers are grounded strictly in your uploaded and verified documents.
          </p>
        </div>
      </div>

      {/* Delete Conversation Confirmation Modal */}
      {convToDelete && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm">
          <div className="relative w-full max-w-md rounded-2xl bg-zinc-900 border border-zinc-800 p-6 shadow-2xl">
            <div className="flex items-center gap-3 text-rose-400">
              <div className="p-2.5 rounded-xl bg-rose-500/10 border border-rose-500/20">
                <Trash2 className="w-5 h-5" />
              </div>
              <h3 className="font-semibold text-white">Delete Conversation</h3>
            </div>

            <p className="mt-3 text-sm text-zinc-300">
              Are you sure you want to delete <strong className="text-white">"{convToDelete.title}"</strong>?
            </p>
            <p className="mt-2 text-xs text-zinc-400">
              This action permanently deletes this chat session and all its messages.
            </p>

            <div className="mt-6 flex items-center justify-end gap-3">
              <button
                onClick={() => setConvToDelete(null)}
                disabled={isDeleting}
                className="px-4 py-2 rounded-xl text-sm font-medium bg-zinc-800 hover:bg-zinc-700 text-zinc-300 transition-colors disabled:opacity-50"
              >
                Cancel
              </button>
              <button
                onClick={confirmDeleteConversation}
                disabled={isDeleting}
                className="inline-flex items-center gap-2 px-4 py-2 rounded-xl text-sm font-medium bg-rose-600 hover:bg-rose-500 text-white transition-colors disabled:opacity-50"
              >
                {isDeleting && <RefreshCw className="w-4 h-4 animate-spin" />}
                {isDeleting ? 'Deleting...' : 'Confirm Deletion'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
