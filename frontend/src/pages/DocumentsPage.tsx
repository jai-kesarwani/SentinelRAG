import React, { useState, useEffect, useRef } from 'react';
import {
  UploadCloud,
  FileText,
  Trash2,
  Eye,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  Clock,
  RefreshCw,
  Layers,
  FileCheck,
  ShieldCheck,
  ShieldAlert,
  Shield,
  Copy,
  Check,
  X,
  CheckCircle,
  Ban,
  RotateCw,
} from 'lucide-react';
import { documentsApi } from '../services/api';
import type { DocumentItem, DocumentStatus, DocumentSecurityDetails } from '../types';

export function DocumentsPage() {
  const [documents, setDocuments] = useState<DocumentItem[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [isUploading, setIsUploading] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  // Drag and drop state
  const [isDragging, setIsDragging] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Selected document for details modal
  const [selectedDoc, setSelectedDoc] = useState<DocumentItem | null>(null);

  // Security inspection modal state
  const [securityDoc, setSecurityDoc] = useState<DocumentItem | null>(null);
  const [securityDetails, setSecurityDetails] = useState<DocumentSecurityDetails | null>(null);
  const [isLoadingSecurity, setIsLoadingSecurity] = useState(false);
  const [isActioningSecurity, setIsActioningSecurity] = useState(false);

  // Document marked for deletion
  const [docToDelete, setDocToDelete] = useState<DocumentItem | null>(null);
  const [isDeleting, setIsDeleting] = useState(false);

  // Copied hash state
  const [hasCopiedHash, setHasCopiedHash] = useState(false);

  // Fetch document list
  const fetchDocuments = async () => {
    setIsLoading(true);
    setErrorMsg(null);
    try {
      const res = await documentsApi.list();
      setDocuments(res.data.documents || []);
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to load documents');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchDocuments();
  }, []);

  // Format file size
  const formatBytes = (bytes: number): string => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${(bytes / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`;
  };

  // Format date
  const formatDate = (isoString: string): string => {
    try {
      const date = new Date(isoString);
      return new Intl.DateTimeFormat('en-US', {
        month: 'short',
        day: 'numeric',
        year: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
      }).format(date);
    } catch {
      return isoString;
    }
  };

  // Upload handler
  const handleUploadFile = async (file: File) => {
    setErrorMsg(null);
    setSuccessMsg(null);

    // Client-side validations
    if (!file.name.toLowerCase().endsWith('.pdf') && file.type !== 'application/pdf') {
      setErrorMsg('Invalid file type. Only PDF documents are supported.');
      return;
    }

    const MAX_SIZE_BYTES = 20 * 1024 * 1024; // 20 MB
    if (file.size > MAX_SIZE_BYTES) {
      setErrorMsg(`File exceeds maximum size limit of 20 MB (${formatBytes(file.size)}).`);
      return;
    }

    setIsUploading(true);
    try {
      const res = await documentsApi.upload(file);
      const newDoc = res.data;
      if (newDoc.status === 'quarantined') {
        setErrorMsg(`"${newDoc.original_filename}" was QUARANTINED by the security scanner. Malicious instructions or prompt injection patterns detected.`);
      } else if (newDoc.status === 'review') {
        setSuccessMsg(`"${newDoc.original_filename}" uploaded but held in REVIEW. Awaiting security approval before vector indexing.`);
      } else {
        setSuccessMsg(`"${newDoc.original_filename}" screened & indexed successfully (${newDoc.chunk_count} chunks indexed).`);
      }
      await fetchDocuments();
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to process document');
      await fetchDocuments();
    } finally {
      setIsUploading(false);
      if (fileInputRef.current) {
        fileInputRef.current.value = '';
      }
    }
  };

  const onDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const onDragLeave = () => {
    setIsDragging(false);
  };

  const onDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      handleUploadFile(e.dataTransfer.files[0]);
    }
  };

  const onFileInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      handleUploadFile(e.target.files[0]);
    }
  };

  // Open Security Inspection Modal
  const openSecurityModal = async (doc: DocumentItem) => {
    setSecurityDoc(doc);
    setIsLoadingSecurity(true);
    setSecurityDetails(null);
    try {
      const res = await documentsApi.getSecurityDetails(doc.id || (doc as any)._id);
      setSecurityDetails(res.data);
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to load security scan details');
    } finally {
      setIsLoadingSecurity(false);
    }
  };

  // Review decision handler
  const handleReviewDecision = async (decision: 'approve' | 'quarantine') => {
    if (!securityDoc) return;
    setIsActioningSecurity(true);
    setErrorMsg(null);
    try {
      const docId = securityDoc.id || (securityDoc as any)._id;
      const res = await documentsApi.review(docId, { decision });
      setSuccessMsg(res.data.message);
      // Refresh details and documents list
      const detailsRes = await documentsApi.getSecurityDetails(docId);
      setSecurityDetails(detailsRes.data);
      await fetchDocuments();
    } catch (err: any) {
      setErrorMsg(err.message || `Failed to ${decision} document`);
    } finally {
      setIsActioningSecurity(false);
    }
  };

  // Rescan handler
  const handleRescanDocument = async () => {
    if (!securityDoc) return;
    setIsActioningSecurity(true);
    setErrorMsg(null);
    try {
      const docId = securityDoc.id || (securityDoc as any)._id;
      const res = await documentsApi.rescan(docId);
      setSuccessMsg(res.data.message);
      // Refresh details and list
      const detailsRes = await documentsApi.getSecurityDetails(docId);
      setSecurityDetails(detailsRes.data);
      await fetchDocuments();
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to rescan document');
    } finally {
      setIsActioningSecurity(false);
    }
  };

  // Delete handler
  const handleDeleteConfirm = async () => {
    if (!docToDelete) return;
    setIsDeleting(true);
    setErrorMsg(null);
    try {
      const res = await documentsApi.delete(docToDelete.id || (docToDelete as any)._id);
      setSuccessMsg(`Document deleted and ${res.data.chunks_deleted} vector chunks purged.`);
      setDocToDelete(null);
      await fetchDocuments();
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to delete document');
    } finally {
      setIsDeleting(false);
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setHasCopiedHash(true);
    setTimeout(() => setHasCopiedHash(false), 2000);
  };

  // Status badge styling
  const renderStatusBadge = (status: DocumentStatus) => {
    switch (status) {
      case 'indexed':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
            <ShieldCheck className="w-3 h-3" /> Indexed
          </span>
        );
      case 'processing':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-500/10 text-blue-400 border border-blue-500/20 animate-pulse">
            <Clock className="w-3 h-3 animate-spin" /> Processing
          </span>
        );
      case 'quarantined':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-medium bg-rose-500/10 text-rose-400 border border-rose-500/20">
            <ShieldAlert className="w-3 h-3" /> Quarantined
          </span>
        );
      case 'failed':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-medium bg-rose-500/10 text-rose-400 border border-rose-500/20">
            <XCircle className="w-3 h-3" /> Failed
          </span>
        );
      case 'review':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-medium bg-amber-500/10 text-amber-400 border border-amber-500/20 animate-pulse">
            <AlertTriangle className="w-3 h-3" /> Under Review
          </span>
        );
      case 'deleting':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-medium bg-zinc-500/10 text-zinc-400 border border-zinc-500/20">
            <Clock className="w-3 h-3" /> Deleting
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-medium bg-zinc-800 text-zinc-300 border border-zinc-700">
            {status}
          </span>
        );
    }
  };

  const renderRiskPill = (risk: string) => {
    switch (risk.toLowerCase()) {
      case 'critical':
      case 'high':
        return (
          <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold uppercase bg-rose-500/20 text-rose-400 border border-rose-500/30">
            {risk}
          </span>
        );
      case 'medium':
        return (
          <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold uppercase bg-amber-500/20 text-amber-400 border border-amber-500/30">
            {risk}
          </span>
        );
      default:
        return (
          <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold uppercase bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
            {risk}
          </span>
        );
    }
  };

  // Metrics
  const totalPages = documents.reduce((sum, d) => sum + (d.page_count || 0), 0);
  const totalChunks = documents.reduce((sum, d) => sum + (d.chunk_count || 0), 0);
  const totalBytes = documents.reduce((sum, d) => sum + (d.file_size_bytes || 0), 0);
  const quarantinedCount = documents.filter((d) => d.status === 'quarantined').length;
  const reviewCount = documents.filter((d) => d.status === 'review').length;

  return (
    <div className="space-y-6">
      {/* Alert Banners */}
      {errorMsg && (
        <div className="flex items-center justify-between p-4 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-300 text-sm">
          <div className="flex items-center gap-3">
            <XCircle className="w-5 h-5 text-rose-400 shrink-0" />
            <span>{errorMsg}</span>
          </div>
          <button onClick={() => setErrorMsg(null)} className="text-rose-400 hover:text-rose-200">
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      {successMsg && (
        <div className="flex items-center justify-between p-4 rounded-xl bg-emerald-500/10 border border-emerald-500/20 text-emerald-300 text-sm">
          <div className="flex items-center gap-3">
            <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0" />
            <span>{successMsg}</span>
          </div>
          <button onClick={() => setSuccessMsg(null)} className="text-emerald-400 hover:text-emerald-200">
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      {/* Security Screening Warning if documents are quarantined or in review */}
      {(quarantinedCount > 0 || reviewCount > 0) && (
        <div className="p-4 rounded-2xl bg-amber-500/10 border border-amber-500/30 flex items-start justify-between gap-3 text-amber-200 text-xs">
          <div className="flex items-start gap-2.5">
            <ShieldAlert className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
            <div>
              <span className="font-semibold text-white block mb-0.5">Security Policy Enforcement Active</span>
              {quarantinedCount > 0 && reviewCount > 0
                ? `${quarantinedCount} document(s) are quarantined and ${reviewCount} are held in review. `
                : quarantinedCount > 0
                ? `${quarantinedCount} document(s) have been quarantined due to prompt-injection or security signals. `
                : `${reviewCount} document(s) are held in review awaiting verification. `}
              Their vector contents are strictly blocked from AI Assistant retrieval.
            </div>
          </div>
        </div>
      )}

      {/* Metrics Header */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="p-5 rounded-2xl bg-zinc-900/60 border border-zinc-800/80 backdrop-blur-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium uppercase tracking-wider text-zinc-400">Total Documents</span>
            <div className="p-2 rounded-xl bg-indigo-500/10 border border-indigo-500/20 text-indigo-400">
              <FileText className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3 text-2xl font-bold text-white tracking-tight">{documents.length}</div>
          <p className="mt-1 text-xs text-zinc-400">
            {quarantinedCount > 0 ? `${quarantinedCount} quarantined` : 'All uploaded files'}
          </p>
        </div>

        <div className="p-5 rounded-2xl bg-zinc-900/60 border border-zinc-800/80 backdrop-blur-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium uppercase tracking-wider text-zinc-400">Security Gate</span>
            <div className="p-2 rounded-xl bg-emerald-500/10 border border-emerald-500/20 text-emerald-400">
              <ShieldCheck className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3 text-2xl font-bold text-emerald-400 tracking-tight">Active</div>
          <p className="mt-1 text-xs text-zinc-400">Phase 5 Deterministic Scanner</p>
        </div>

        <div className="p-5 rounded-2xl bg-zinc-900/60 border border-zinc-800/80 backdrop-blur-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium uppercase tracking-wider text-zinc-400">Indexed Chunks</span>
            <div className="p-2 rounded-xl bg-indigo-500/10 border border-indigo-500/20 text-indigo-400">
              <Layers className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3 text-2xl font-bold text-white tracking-tight">{totalChunks}</div>
          <p className="mt-1 text-xs text-zinc-400">Approved ChromaDB vectors</p>
        </div>

        <div className="p-5 rounded-2xl bg-zinc-900/60 border border-zinc-800/80 backdrop-blur-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium uppercase tracking-wider text-zinc-400">Extracted Pages</span>
            <div className="p-2 rounded-xl bg-purple-500/10 border border-purple-500/20 text-purple-400">
              <FileCheck className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3 text-2xl font-bold text-white tracking-tight">{totalPages}</div>
          <p className="mt-1 text-xs text-zinc-400">Across {formatBytes(totalBytes)}</p>
        </div>
      </div>

      {/* Upload Dropzone */}
      <div
        onDragOver={onDragOver}
        onDragLeave={onDragLeave}
        onDrop={onDrop}
        onClick={() => !isUploading && fileInputRef.current?.click()}
        className={`relative border-2 border-dashed rounded-2xl p-8 text-center cursor-pointer transition-all duration-200 ${
          isDragging
            ? 'border-indigo-500 bg-indigo-500/5'
            : 'border-zinc-700/80 hover:border-zinc-500 bg-zinc-900/40 hover:bg-zinc-900/60'
        }`}
      >
        <input
          ref={fileInputRef}
          type="file"
          accept=".pdf,application/pdf"
          className="hidden"
          disabled={isUploading}
          onChange={onFileInputChange}
        />

        <div className="flex flex-col items-center justify-center space-y-3">
          <div className="p-4 rounded-2xl bg-indigo-500/10 border border-indigo-500/20 text-indigo-400">
            {isUploading ? (
              <RefreshCw className="w-8 h-8 animate-spin text-indigo-400" />
            ) : (
              <UploadCloud className="w-8 h-8 text-indigo-400" />
            )}
          </div>
          <div className="space-y-1">
            <p className="text-sm font-medium text-zinc-200">
              {isUploading ? (
                'Extracting, security screening, and indexing PDF...'
              ) : (
                <>
                  <span className="text-indigo-400 hover:underline">Click to upload</span> or drag and drop your PDF
                </>
              )}
            </p>
            <p className="text-xs text-zinc-400">
              Standard PDF up to 20 MB. Screened automatically for prompt injection, secret extraction, and malicious beacons.
            </p>
          </div>
        </div>
      </div>

      {/* Documents Table Header */}
      <div className="flex items-center justify-between pt-2">
        <div>
          <h2 className="text-lg font-semibold text-white tracking-tight">Your Ingested Documents</h2>
          <p className="text-xs text-zinc-400 mt-0.5">Isolated documents accessible for verified RAG retrieval</p>
        </div>
        <button
          onClick={fetchDocuments}
          disabled={isLoading}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-medium bg-zinc-800 hover:bg-zinc-700 text-zinc-200 border border-zinc-700/80 transition-colors disabled:opacity-50"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />
          Refresh
        </button>
      </div>

      {/* Documents Table */}
      <div className="rounded-2xl border border-zinc-800/80 bg-zinc-900/60 overflow-hidden backdrop-blur-sm">
        {isLoading && documents.length === 0 ? (
          <div className="p-12 text-center text-zinc-400 text-sm">
            <RefreshCw className="w-6 h-6 animate-spin mx-auto text-indigo-400 mb-3" />
            Loading documents...
          </div>
        ) : documents.length === 0 ? (
          <div className="p-12 text-center text-zinc-400 text-sm">
            <FileText className="w-8 h-8 mx-auto text-zinc-600 mb-3" />
            <p className="font-medium text-zinc-300">No documents ingested yet</p>
            <p className="text-xs text-zinc-400 mt-1">Upload a PDF document above to screen and index knowledge.</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm text-zinc-300">
              <thead className="bg-zinc-900/90 text-xs uppercase tracking-wider text-zinc-400 border-b border-zinc-800">
                <tr>
                  <th className="px-6 py-3.5 font-medium">Document Name</th>
                  <th className="px-6 py-3.5 font-medium">Size</th>
                  <th className="px-6 py-3.5 font-medium">Pages</th>
                  <th className="px-6 py-3.5 font-medium">Chunks</th>
                  <th className="px-6 py-3.5 font-medium">Security Status</th>
                  <th className="px-6 py-3.5 font-medium">Uploaded</th>
                  <th className="px-6 py-3.5 font-medium text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-800/60">
                {documents.map((doc) => {
                  const docId = doc.id || (doc as any)._id;
                  return (
                    <tr key={docId} className="hover:bg-zinc-800/40 transition-colors">
                      <td className="px-6 py-4 font-medium text-white">
                        <div className="flex items-center gap-3">
                          <div className="p-2 rounded-lg bg-zinc-800/80 text-indigo-400 border border-zinc-700/50">
                            <FileText className="w-4 h-4" />
                          </div>
                          <div className="truncate max-w-xs" title={doc.original_filename}>
                            {doc.original_filename}
                          </div>
                        </div>
                      </td>
                      <td className="px-6 py-4 text-zinc-400">{formatBytes(doc.file_size_bytes)}</td>
                      <td className="px-6 py-4 text-zinc-300">{doc.page_count}</td>
                      <td className="px-6 py-4 text-zinc-300">{doc.chunk_count}</td>
                      <td className="px-6 py-4">{renderStatusBadge(doc.status)}</td>
                      <td className="px-6 py-4 text-zinc-400 text-xs">{formatDate(doc.created_at)}</td>
                      <td className="px-6 py-4 text-right">
                        <div className="inline-flex items-center gap-1">
                          {/* Security Findings Button */}
                          <button
                            onClick={() => openSecurityModal(doc)}
                            title="Security Scan Findings"
                            className="p-1.5 rounded-lg text-zinc-400 hover:text-amber-400 hover:bg-amber-500/10 transition-colors"
                          >
                            <Shield className="w-4 h-4" />
                          </button>
                          {/* Details Button */}
                          <button
                            onClick={() => setSelectedDoc(doc)}
                            title="View Metadata"
                            className="p-1.5 rounded-lg text-zinc-400 hover:text-indigo-400 hover:bg-zinc-800 transition-colors"
                          >
                            <Eye className="w-4 h-4" />
                          </button>
                          {/* Delete Button */}
                          <button
                            onClick={() => setDocToDelete(doc)}
                            title="Delete Document"
                            className="p-1.5 rounded-lg text-zinc-400 hover:text-rose-400 hover:bg-rose-500/10 transition-colors"
                          >
                            <Trash2 className="w-4 h-4" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Security Findings & Inspection Modal */}
      {securityDoc && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-sm">
          <div className="relative w-full max-w-2xl max-h-[85vh] flex flex-col rounded-2xl bg-zinc-900 border border-zinc-800 shadow-2xl overflow-hidden">
            <div className="flex items-center justify-between p-5 border-b border-zinc-800 bg-zinc-950/40">
              <div className="flex items-center gap-2.5">
                <div className="p-2 rounded-xl bg-indigo-500/10 border border-indigo-500/20 text-indigo-400">
                  <Shield className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="font-semibold text-white">Document Security Findings</h3>
                  <p className="text-xs text-zinc-400 truncate max-w-md">{securityDoc.original_filename}</p>
                </div>
              </div>
              <button
                onClick={() => setSecurityDoc(null)}
                className="text-zinc-400 hover:text-white transition-colors"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="flex-1 overflow-y-auto p-6 space-y-5 text-sm">
              {isLoadingSecurity ? (
                <div className="p-12 text-center text-zinc-400 text-xs flex items-center justify-center gap-2">
                  <RefreshCw className="w-4 h-4 animate-spin text-indigo-400" />
                  Loading security scan report...
                </div>
              ) : securityDetails ? (
                <>
                  {/* Status Overview Card */}
                  <div className="grid grid-cols-3 gap-3 p-4 rounded-xl bg-zinc-950/60 border border-zinc-800">
                    <div>
                      <span className="text-[11px] uppercase font-semibold text-zinc-500 block">Risk Level</span>
                      <div className="mt-1">{renderRiskPill(securityDetails.risk_level)}</div>
                    </div>
                    <div>
                      <span className="text-[11px] uppercase font-semibold text-zinc-500 block">Policy Decision</span>
                      <div className="mt-1">{renderStatusBadge(securityDetails.status as DocumentStatus)}</div>
                    </div>
                    <div>
                      <span className="text-[11px] uppercase font-semibold text-zinc-500 block">Signals Detected</span>
                      <span className="mt-1 text-sm font-bold text-white block">
                        {securityDetails.signals_count} Signal(s)
                      </span>
                    </div>
                  </div>

                  {/* Summary Callout */}
                  <div className={`p-3.5 rounded-xl border text-xs leading-relaxed ${
                    securityDetails.policy_decision === 'quarantined'
                      ? 'bg-rose-500/10 border-rose-500/20 text-rose-300'
                      : securityDetails.policy_decision === 'review'
                      ? 'bg-amber-500/10 border-amber-500/20 text-amber-300'
                      : 'bg-emerald-500/10 border-emerald-500/20 text-emerald-300'
                  }`}>
                    <strong>Inspection Summary:</strong> {securityDetails.summary}
                  </div>

                  {/* Signals List */}
                  <div>
                    <h4 className="text-xs font-semibold uppercase tracking-wider text-zinc-400 mb-2.5">
                      Flagged Threat Signals ({securityDetails.signals.length})
                    </h4>
                    {securityDetails.signals.length === 0 ? (
                      <div className="p-4 rounded-xl bg-zinc-950/40 border border-zinc-800 text-center text-xs text-zinc-400">
                        <CheckCircle className="w-5 h-5 text-emerald-400 mx-auto mb-1.5" />
                        No prompt-injection, exfiltration, or override patterns detected.
                      </div>
                    ) : (
                      <div className="space-y-2.5">
                        {securityDetails.signals.map((sig, sIdx) => (
                          <div
                            key={sIdx}
                            className="p-3.5 rounded-xl bg-zinc-950/80 border border-zinc-800/80 space-y-2"
                          >
                            <div className="flex items-center justify-between text-xs">
                              <span className="font-semibold text-white flex items-center gap-1.5">
                                <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
                                {sig.pattern_name.replace(/_/g, ' ').toUpperCase()}
                              </span>
                              <div className="flex items-center gap-2">
                                <span className="px-1.5 py-0.5 rounded bg-zinc-800 text-zinc-300 text-[10px]">
                                  Page {sig.page_number}
                                </span>
                                {renderRiskPill(sig.severity)}
                              </div>
                            </div>
                            <p className="text-xs text-zinc-400">{sig.description}</p>
                            <div className="p-2 rounded-lg bg-zinc-900 border border-zinc-800/60 font-mono text-[11px] text-rose-300 break-all">
                              "{sig.matched_snippet}"
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                </>
              ) : (
                <div className="text-xs text-zinc-400">Could not retrieve scan details.</div>
              )}
            </div>

            {/* Modal Footer Actions */}
            <div className="p-4 border-t border-zinc-800 bg-zinc-950/40 flex items-center justify-between gap-3">
              <button
                onClick={handleRescanDocument}
                disabled={isActioningSecurity}
                className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-xl text-xs font-medium bg-zinc-800 hover:bg-zinc-700 text-zinc-200 border border-zinc-700 transition-colors disabled:opacity-50"
              >
                <RotateCw className={`w-3.5 h-3.5 ${isActioningSecurity ? 'animate-spin' : ''}`} />
                Re-scan Document
              </button>

              <div className="flex items-center gap-2">
                {/* Manual Review Actions if held in review */}
                {securityDetails && securityDetails.status === 'review' && (
                  <>
                    <button
                      onClick={() => handleReviewDecision('approve')}
                      disabled={isActioningSecurity}
                      className="inline-flex items-center gap-1 px-3.5 py-2 rounded-xl text-xs font-semibold bg-emerald-600 hover:bg-emerald-500 text-white transition-colors disabled:opacity-50 shadow-sm"
                    >
                      <CheckCircle className="w-3.5 h-3.5" />
                      Approve & Index
                    </button>
                    <button
                      onClick={() => handleReviewDecision('quarantine')}
                      disabled={isActioningSecurity}
                      className="inline-flex items-center gap-1 px-3.5 py-2 rounded-xl text-xs font-semibold bg-rose-600 hover:bg-rose-500 text-white transition-colors disabled:opacity-50 shadow-sm"
                    >
                      <Ban className="w-3.5 h-3.5" />
                      Confirm Quarantine
                    </button>
                  </>
                )}
                <button
                  onClick={() => setSecurityDoc(null)}
                  className="px-4 py-2 rounded-xl text-xs font-medium bg-zinc-800 hover:bg-zinc-700 text-white transition-colors"
                >
                  Close
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Document Details Modal */}
      {selectedDoc && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm">
          <div className="relative w-full max-w-lg rounded-2xl bg-zinc-900 border border-zinc-800 p-6 shadow-2xl">
            <div className="flex items-center justify-between pb-4 border-b border-zinc-800">
              <div className="flex items-center gap-2.5">
                <FileText className="w-5 h-5 text-indigo-400" />
                <h3 className="font-semibold text-white">Document Information</h3>
              </div>
              <button
                onClick={() => setSelectedDoc(null)}
                className="text-zinc-400 hover:text-white transition-colors"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="mt-4 space-y-4 text-sm">
              <div>
                <label className="text-xs uppercase text-zinc-500 font-medium">Filename</label>
                <p className="text-white font-medium break-all">{selectedDoc.original_filename}</p>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="text-xs uppercase text-zinc-500 font-medium">Document ID</label>
                  <p className="text-zinc-300 font-mono text-xs">{selectedDoc.id || (selectedDoc as any)._id}</p>
                </div>
                <div>
                  <label className="text-xs uppercase text-zinc-500 font-medium">Status</label>
                  <div className="mt-1">{renderStatusBadge(selectedDoc.status)}</div>
                </div>
              </div>

              <div className="grid grid-cols-3 gap-4">
                <div>
                  <label className="text-xs uppercase text-zinc-500 font-medium">File Size</label>
                  <p className="text-zinc-300">{formatBytes(selectedDoc.file_size_bytes)}</p>
                </div>
                <div>
                  <label className="text-xs uppercase text-zinc-500 font-medium">Page Count</label>
                  <p className="text-zinc-300">{selectedDoc.page_count} pages</p>
                </div>
                <div>
                  <label className="text-xs uppercase text-zinc-500 font-medium">Vector Chunks</label>
                  <p className="text-zinc-300">{selectedDoc.chunk_count} chunks</p>
                </div>
              </div>

              <div>
                <label className="text-xs uppercase text-zinc-500 font-medium">SHA-256 Checksum</label>
                <div className="flex items-center gap-2 mt-1 p-2 rounded-lg bg-zinc-950 border border-zinc-800">
                  <span className="text-xs font-mono text-zinc-400 break-all flex-1">{selectedDoc.sha256}</span>
                  <button
                    onClick={() => copyToClipboard(selectedDoc.sha256)}
                    className="p-1 rounded text-zinc-400 hover:text-white hover:bg-zinc-800 transition-colors"
                    title="Copy SHA-256"
                  >
                    {hasCopiedHash ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  </button>
                </div>
              </div>

              {selectedDoc.trust && (
                <div className="p-3 rounded-xl bg-zinc-950/60 border border-zinc-800/80 space-y-2">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <ShieldCheck className="w-4 h-4 text-emerald-400" />
                      <span className="text-xs font-semibold text-zinc-200">Security Gate Status</span>
                    </div>
                    <button
                      onClick={() => {
                        setSelectedDoc(null);
                        openSecurityModal(selectedDoc);
                      }}
                      className="text-[11px] text-indigo-400 hover:underline"
                    >
                      View Findings
                    </button>
                  </div>
                  <div className="flex items-center justify-between text-xs text-zinc-400">
                    <span>Risk Level: <strong className="text-zinc-200 uppercase">{selectedDoc.trust.risk_level}</strong></span>
                    <span>Decision: <strong className="text-emerald-400 uppercase">{selectedDoc.trust.policy_decision}</strong></span>
                  </div>
                </div>
              )}
            </div>

            <div className="mt-6 flex justify-end">
              <button
                onClick={() => setSelectedDoc(null)}
                className="px-4 py-2 rounded-xl text-sm font-medium bg-zinc-800 hover:bg-zinc-700 text-white transition-colors"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Delete Confirmation Modal */}
      {docToDelete && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm">
          <div className="relative w-full max-w-md rounded-2xl bg-zinc-900 border border-zinc-800 p-6 shadow-2xl">
            <div className="flex items-center gap-3 text-rose-400">
              <div className="p-2.5 rounded-xl bg-rose-500/10 border border-rose-500/20">
                <Trash2 className="w-5 h-5" />
              </div>
              <h3 className="font-semibold text-white">Delete Document</h3>
            </div>

            <p className="mt-3 text-sm text-zinc-300">
              Are you sure you want to delete <strong className="text-white">"{docToDelete.original_filename}"</strong>?
            </p>
            <p className="mt-2 text-xs text-zinc-400">
              This action permanently deletes the stored PDF file and purges all {docToDelete.chunk_count} vector chunks from ChromaDB.
            </p>

            <div className="mt-6 flex items-center justify-end gap-3">
              <button
                onClick={() => setDocToDelete(null)}
                disabled={isDeleting}
                className="px-4 py-2 rounded-xl text-sm font-medium bg-zinc-800 hover:bg-zinc-700 text-zinc-300 transition-colors disabled:opacity-50"
              >
                Cancel
              </button>
              <button
                onClick={handleDeleteConfirm}
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
