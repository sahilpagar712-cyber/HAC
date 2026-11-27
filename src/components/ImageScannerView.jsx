import React, { useEffect, useRef, useState } from 'react';
import {
  Image as ImageIcon,
  Upload,
  Trash2,
  RefreshCw,
  ShieldCheck,
  AlertTriangle,
  ShieldAlert,
  Download,
  Search,
  CheckCircle2,
  XCircle,
  Info,
  History,
  FileSearch,
  Loader2,
} from 'lucide-react';
import { api } from '../api/client.js';

const MAX_BYTES = 10 * 1024 * 1024;
const ALLOWED_EXTS = ['.jpg', '.jpeg', '.png', '.webp', '.gif'];

function formatBytes(bytes) {
  if (!bytes && bytes !== 0) return '0 B';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

async function inspectMagicHeader(file) {
  const buf = await file.slice(0, 12).arrayBuffer();
  const b = new Uint8Array(buf);
  if (b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) return 'JPEG';
  if (b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4e && b[3] === 0x47) return 'PNG';
  if (
    b[0] === 0x52 && b[1] === 0x49 && b[2] === 0x46 && b[3] === 0x46 &&
    b[8] === 0x57 && b[9] === 0x45 && b[10] === 0x42 && b[11] === 0x50
  ) {
    return 'WEBP';
  }
  if (b[0] === 0x47 && b[1] === 0x49 && b[2] === 0x46) return 'GIF';
  return 'UNKNOWN';
}

export function ImageScannerView({ onNotify, onScanCompleted }) {
  const [subTab, setSubTab] = useState('scan'); // 'scan' | 'history'
  const [selectedFile, setSelectedFile] = useState(null);
  const [previewUrl, setPreviewUrl] = useState('');
  const [isDragging, setIsDragging] = useState(false);
  const [validationError, setValidationError] = useState('');
  const [progress, setProgress] = useState(0);
  const [scanning, setScanning] = useState(false);
  const [scanResult, setScanResult] = useState(null);

  // History state
  const [history, setHistory] = useState([]);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [filterCategory, setFilterCategory] = useState('');
  const [dateFrom, setDateFrom] = useState('');
  const [dateTo, setDateTo] = useState('');

  const fileInputRef = useRef(null);

  const loadHistory = async (overrides = {}) => {
    setHistoryLoading(true);
    try {
      const items = await api.listImageScans({
        search: overrides.search ?? searchTerm,
        risk_category: overrides.risk_category ?? filterCategory,
        date_from: overrides.date_from ?? dateFrom,
        date_to: overrides.date_to ?? dateTo,
      });
      setHistory(items);
    } catch (err) {
      onNotify?.(err.message || 'Failed to load image scan history');
    } finally {
      setHistoryLoading(false);
    }
  };

  useEffect(() => {
    loadHistory();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    return () => {
      if (previewUrl) URL.revokeObjectURL(previewUrl);
    };
  }, [previewUrl]);

  const handleSelectFile = async (file) => {
    setValidationError('');
    setScanResult(null);
    if (!file) return;

    const lowerName = file.name.toLowerCase();
    const hasAllowedExt = ALLOWED_EXTS.some((ext) => lowerName.endsWith(ext));
    if (file.size > MAX_BYTES) {
      setValidationError(`File exceeds 10 MB limit (${formatBytes(file.size)}).`);
      return;
    }
    if (file.size === 0) {
      setValidationError('Selected file is empty (0 bytes).');
      return;
    }

    const magic = await inspectMagicHeader(file);
    if (magic === 'UNKNOWN' && !hasAllowedExt) {
      setValidationError('Unsupported file format. Only JPG, JPEG, PNG, WEBP, and GIF are allowed.');
      return;
    }

    if (previewUrl) URL.revokeObjectURL(previewUrl);
    setSelectedFile(file);
    setPreviewUrl(URL.createObjectURL(file));
    if (magic === 'UNKNOWN') {
      setValidationError('Warning: File content magic bytes do not match a standard image header. You can still scan it to inspect.');
    }
  };

  const handleClearFile = () => {
    if (previewUrl) URL.revokeObjectURL(previewUrl);
    setSelectedFile(null);
    setPreviewUrl('');
    setValidationError('');
    setScanResult(null);
    setProgress(0);
    if (fileInputRef.current) fileInputRef.current.value = '';
  };

  const handleScanImage = async () => {
    if (!selectedFile || scanning) return;
    setScanning(true);
    setProgress(20);
    setValidationError('');

    try {
      const staged = await api.uploadImageForScan(selectedFile);
      setProgress(60);
      const result = await api.scanUploadedImage(staged.upload_id);
      setProgress(100);
      setScanResult(result);
      onNotify?.(`Image scan completed: ${result.risk_category} (${result.risk_score}/100)`);
      onScanCompleted?.();
      loadHistory();
    } catch (err) {
      setValidationError(err.message || 'Image scan failed');
      setProgress(0);
    } finally {
      setScanning(false);
    }
  };

  const handleDownloadPdf = async (scanId) => {
    try {
      const blob = await api.downloadImageReportPdf(scanId);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `securex_image_report_${scanId}.pdf`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      onNotify?.(`Downloaded PDF report #${scanId}`);
    } catch (err) {
      onNotify?.(err.message || 'Failed to download PDF report');
    }
  };

  const handleDeleteScan = async (scanId) => {
    try {
      await api.deleteImageScan(scanId);
      setHistory((prev) => prev.filter((item) => item.id !== scanId));
      if (scanResult?.id === scanId) setScanResult(null);
      onNotify?.(`Deleted scan record #${scanId}`);
    } catch (err) {
      onNotify?.(err.message || 'Failed to delete scan record');
    }
  };

  const badgeForCategory = (cat) => {
    if (cat === 'RED') return 'bg-rose-500/15 text-rose-500 border-rose-500/30';
    if (cat === 'YELLOW') return 'bg-amber-500/15 text-amber-500 border-amber-500/30';
    return 'bg-emerald-500/15 text-emerald-500 border-emerald-500/30';
  };

  return (
    <div className="space-y-5">
      {/* Header + Sub-tabs */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-xl font-bold text-slate-900 dark:text-white flex items-center gap-2">
            <ImageIcon className="w-5 h-5 text-[#5b93ff]" />
            Image Security Scanner
          </h2>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
            Inspect image integrity, magic-byte signatures, EXIF privacy exposure, trailing payloads, and static threat indicators.
          </p>
        </div>

        <div className="inline-flex p-1 rounded-xl bg-slate-100 dark:bg-[#131b2e] border border-slate-200 dark:border-slate-800">
          <button
            type="button"
            onClick={() => setSubTab('scan')}
            className={`inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-all ${
              subTab === 'scan'
                ? 'bg-[#5b93ff] text-slate-950'
                : 'text-slate-600 dark:text-slate-300 hover:text-white'
            }`}
          >
            <FileSearch className="w-3.5 h-3.5" />
            Scan Image
          </button>
          <button
            type="button"
            onClick={() => {
              setSubTab('history');
              loadHistory();
            }}
            className={`inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-all ${
              subTab === 'history'
                ? 'bg-[#5b93ff] text-slate-950'
                : 'text-slate-600 dark:text-slate-300 hover:text-white'
            }`}
          >
            <History className="w-3.5 h-3.5" />
            Scan History ({history.length})
          </button>
        </div>
      </div>

      {subTab === 'scan' && (
        <div className="space-y-5">
          {/* Upload Dropzone */}
          <section className="rounded-2xl border border-slate-200 dark:border-slate-800/90 bg-white dark:bg-[#131b2e] p-5 shadow-sm space-y-4">
            <div
              onDragOver={(e) => {
                e.preventDefault();
                setIsDragging(true);
              }}
              onDragLeave={() => setIsDragging(false)}
              onDrop={(e) => {
                e.preventDefault();
                setIsDragging(false);
                handleSelectFile(e.dataTransfer.files?.[0]);
              }}
              className={`rounded-2xl border-2 border-dashed p-6 transition-colors flex flex-col items-center justify-center text-center ${
                isDragging
                  ? 'border-[#5b93ff] bg-blue-500/10'
                  : 'border-slate-300 dark:border-slate-700 bg-slate-50/60 dark:bg-[#0b1120]/60'
              }`}
            >
              {!selectedFile ? (
                <>
                  <div className="w-12 h-12 rounded-2xl bg-blue-500/15 border border-blue-500/30 flex items-center justify-center mb-3">
                    <Upload className="w-6 h-6 text-[#5b93ff]" />
                  </div>
                  <p className="text-sm font-semibold text-slate-900 dark:text-white">
                    Drag &amp; drop an image here to inspect
                  </p>
                  <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
                    Supports JPG, JPEG, PNG, WEBP, GIF • Max 10 MB • Temporary uploads are deleted after scanning
                  </p>
                  <button
                    type="button"
                    onClick={() => fileInputRef.current?.click()}
                    className="mt-4 px-4 py-2 rounded-xl bg-[#5b93ff] hover:bg-[#4983f2] text-slate-950 text-xs font-semibold"
                  >
                    Browse Files
                  </button>
                </>
              ) : (
                <div className="w-full flex flex-col sm:flex-row items-center gap-5 text-left">
                  <div className="w-32 h-32 rounded-xl overflow-hidden border border-slate-200 dark:border-slate-700 bg-slate-900 shrink-0 flex items-center justify-center">
                    {previewUrl ? (
                      <img
                        src={previewUrl}
                        alt="Uploaded preview"
                        className="w-full h-full object-contain"
                      />
                    ) : (
                      <ImageIcon className="w-8 h-8 text-slate-500" />
                    )}
                  </div>
                  <div className="flex-1 min-w-0 space-y-1.5">
                    <div className="text-sm font-semibold font-mono text-slate-900 dark:text-white truncate">
                      {selectedFile.name}
                    </div>
                    <div className="text-xs text-slate-500 dark:text-slate-400">
                      Size: {formatBytes(selectedFile.size)} • MIME: {selectedFile.type || 'unknown'}
                    </div>
                    <div className="flex flex-wrap items-center gap-2 pt-2">
                      <button
                        type="button"
                        onClick={handleScanImage}
                        disabled={scanning}
                        className="inline-flex items-center gap-1.5 px-4 py-2 rounded-xl bg-[#5b93ff] hover:bg-[#4983f2] text-slate-950 text-xs font-semibold disabled:opacity-60"
                      >
                        {scanning ? (
                          <Loader2 className="w-3.5 h-3.5 animate-spin" />
                        ) : (
                          <ShieldCheck className="w-3.5 h-3.5" />
                        )}
                        {scanning ? 'Scanning Image...' : 'Scan Image'}
                      </button>
                      <button
                        type="button"
                        onClick={() => fileInputRef.current?.click()}
                        disabled={scanning}
                        className="inline-flex items-center gap-1.5 px-3 py-2 rounded-xl border border-slate-200 dark:border-slate-700 text-xs font-medium text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800"
                      >
                        <RefreshCw className="w-3.5 h-3.5" />
                        Replace
                      </button>
                      <button
                        type="button"
                        onClick={handleClearFile}
                        disabled={scanning}
                        className="inline-flex items-center gap-1.5 px-3 py-2 rounded-xl border border-rose-500/30 text-xs font-medium text-rose-500 hover:bg-rose-500/10"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                        Remove
                      </button>
                    </div>
                  </div>
                </div>
              )}

              <input
                ref={fileInputRef}
                type="file"
                accept=".jpg,.jpeg,.png,.webp,.gif,image/jpeg,image/png,image/webp,image/gif"
                className="hidden"
                onChange={(e) => handleSelectFile(e.target.files?.[0])}
              />
            </div>

            {progress > 0 && scanning && (
              <div className="space-y-1">
                <div className="flex justify-between text-[11px] font-mono text-[#5b93ff]">
                  <span>Uploading &amp; running static/EXIF security checks...</span>
                  <span>{progress}%</span>
                </div>
                <div className="h-1.5 rounded-full bg-slate-200 dark:bg-slate-800 overflow-hidden">
                  <div
                    className="h-full bg-[#5b93ff] transition-all duration-200"
                    style={{ width: `${progress}%` }}
                  />
                </div>
              </div>
            )}

            {validationError && (
              <div className="p-3 rounded-xl border border-amber-500/30 bg-amber-500/10 text-amber-600 dark:text-amber-300 text-xs flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 shrink-0" />
                <span>{validationError}</span>
              </div>
            )}
          </section>

          {/* Detailed Scan Report */}
          {scanResult && (
            <section className="rounded-2xl border border-slate-200 dark:border-slate-800/90 bg-white dark:bg-[#131b2e] p-5 shadow-sm space-y-5">
              <div className="flex flex-wrap items-center justify-between gap-3 pb-4 border-b border-slate-200 dark:border-slate-800">
                <div className="flex items-center gap-3">
                  {scanResult.thumbnail_b64 && (
                    <img
                      src={scanResult.thumbnail_b64}
                      alt="Safe thumbnail"
                      className="w-14 h-14 rounded-xl object-contain bg-slate-900 border border-slate-700"
                    />
                  )}
                  <div>
                    <div className="flex items-center gap-2">
                      <h3 className="text-base font-bold text-slate-900 dark:text-white font-mono">
                        {scanResult.filename}
                      </h3>
                      <span
                        className={`px-2.5 py-0.5 rounded-full text-[11px] font-bold border ${badgeForCategory(
                          scanResult.risk_category
                        )}`}
                      >
                        {scanResult.risk_category}
                      </span>
                    </div>
                    <p className="text-xs text-slate-500 dark:text-slate-400">
                      Scan #{scanResult.id} • {new Date(scanResult.created_at).toLocaleString()}
                    </p>
                  </div>
                </div>

                <button
                  type="button"
                  onClick={() => handleDownloadPdf(scanResult.id)}
                  className="inline-flex items-center gap-1.5 px-4 py-2 rounded-xl bg-[#5b93ff] hover:bg-[#4983f2] text-slate-950 text-xs font-semibold"
                >
                  <Download className="w-3.5 h-3.5" />
                  Download PDF Report
                </button>
              </div>

              {/* Score + File Metadata Grid */}
              <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
                <div className="lg:col-span-4 p-4 rounded-xl bg-slate-50 dark:bg-[#0b1120] border border-slate-200 dark:border-slate-800 space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-semibold text-slate-500 dark:text-slate-400">
                      Security Score
                    </span>
                    <span className="text-2xl font-bold font-mono text-slate-900 dark:text-white">
                      {scanResult.risk_score}/100
                    </span>
                  </div>
                  <div className="h-2.5 rounded-full bg-slate-200 dark:bg-slate-800 overflow-hidden">
                    <div
                      className={`h-full ${
                        scanResult.risk_category === 'RED'
                          ? 'bg-rose-500'
                          : scanResult.risk_category === 'YELLOW'
                            ? 'bg-amber-500'
                            : 'bg-emerald-500'
                      }`}
                      style={{ width: `${scanResult.risk_score}%` }}
                    />
                  </div>
                  <ul className="space-y-1 text-[11px] text-slate-600 dark:text-slate-300">
                    {(scanResult.score_reasons_json || []).map((r, i) => (
                      <li key={i}>• {r}</li>
                    ))}
                  </ul>
                </div>

                <div className="lg:col-span-8 grid grid-cols-2 sm:grid-cols-3 gap-3 text-xs">
                  <div className="p-3 rounded-xl bg-slate-50 dark:bg-[#0b1120] border border-slate-200 dark:border-slate-800">
                    <div className="text-[11px] text-slate-500">Format / MIME</div>
                    <div className="font-mono font-semibold mt-0.5">
                      {scanResult.file_format} ({scanResult.mime_type})
                    </div>
                  </div>
                  <div className="p-3 rounded-xl bg-slate-50 dark:bg-[#0b1120] border border-slate-200 dark:border-slate-800">
                    <div className="text-[11px] text-slate-500">Dimensions</div>
                    <div className="font-mono font-semibold mt-0.5">
                      {scanResult.width && scanResult.height
                        ? `${scanResult.width} × ${scanResult.height} px`
                        : 'Decode Failed'}
                    </div>
                  </div>
                  <div className="p-3 rounded-xl bg-slate-50 dark:bg-[#0b1120] border border-slate-200 dark:border-slate-800">
                    <div className="text-[11px] text-slate-500">File Size</div>
                    <div className="font-mono font-semibold mt-0.5">
                      {formatBytes(scanResult.file_size)}
                    </div>
                  </div>
                  <div className="col-span-2 sm:col-span-3 p-3 rounded-xl bg-slate-50 dark:bg-[#0b1120] border border-slate-200 dark:border-slate-800">
                    <div className="text-[11px] text-slate-500">SHA-256 Hash</div>
                    <div className="font-mono text-[11px] break-all text-slate-800 dark:text-slate-200 mt-0.5">
                      {scanResult.sha256_hash}
                    </div>
                  </div>
                  <div className="col-span-2 sm:col-span-3 p-3 rounded-xl bg-slate-50 dark:bg-[#0b1120] border border-slate-200 dark:border-slate-800">
                    <div className="text-[11px] text-slate-500">EXIF &amp; Engine Summary</div>
                    <div className="text-xs text-slate-700 dark:text-slate-300 mt-0.5">
                      Camera: {scanResult.exif_json?.camera_make || 'N/A'}{' '}
                      {scanResult.exif_json?.camera_model || ''} • GPS:{' '}
                      {scanResult.exif_json?.gps_present ? 'Present (Redacted)' : 'None'} •{' '}
                      {scanResult.clamav_status}
                    </div>
                  </div>
                </div>
              </div>

              {/* Individual Security Checks */}
              <div>
                <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-500 mb-2">
                  Individual Security Checks
                </h4>
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2.5">
                  {(scanResult.security_checks_json || []).map((chk, idx) => (
                    <div
                      key={idx}
                      className="p-3 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-[#0e1525] text-xs"
                    >
                      <div className="flex items-center justify-between gap-2 font-semibold">
                        <span className="truncate">{chk.name}</span>
                        {chk.status === 'PASS' ? (
                          <CheckCircle2 className="w-4 h-4 text-emerald-500 shrink-0" />
                        ) : chk.status === 'FAIL' ? (
                          <XCircle className="w-4 h-4 text-rose-500 shrink-0" />
                        ) : chk.status === 'WARN' ? (
                          <AlertTriangle className="w-4 h-4 text-amber-500 shrink-0" />
                        ) : (
                          <Info className="w-4 h-4 text-[#5b93ff] shrink-0" />
                        )}
                      </div>
                      <div className="text-[11px] text-slate-500 dark:text-slate-400 mt-1">
                        {chk.detail}
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Findings */}
              {(scanResult.findings_json || []).length > 0 && (
                <div>
                  <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-500 mb-2">
                    Security &amp; Metadata Findings ({scanResult.findings_json.length})
                  </h4>
                  <div className="space-y-2">
                    {scanResult.findings_json.map((f, idx) => (
                      <div
                        key={idx}
                        className="p-3 rounded-xl border border-amber-500/30 bg-amber-500/5 text-xs flex items-start gap-2.5"
                      >
                        <ShieldAlert className="w-4 h-4 text-amber-500 shrink-0 mt-0.5" />
                        <div>
                          <div className="font-semibold text-slate-900 dark:text-white">
                            [{f.severity?.toUpperCase()}] {f.title}
                          </div>
                          <div className="text-slate-600 dark:text-slate-300 mt-0.5">{f.detail}</div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </section>
          )}
        </div>
      )}

      {subTab === 'history' && (
        <section className="rounded-2xl border border-slate-200 dark:border-slate-800/90 bg-white dark:bg-[#131b2e] overflow-hidden shadow-sm">
          <div className="p-4 border-b border-slate-200 dark:border-slate-800 flex flex-wrap items-center justify-between gap-3">
            <div className="flex flex-wrap items-center gap-2 flex-1">
              <div className="relative min-w-[200px] flex-1 max-w-xs">
                <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
                <input
                  type="text"
                  value={searchTerm}
                  onChange={(e) => {
                    setSearchTerm(e.target.value);
                    loadHistory({ search: e.target.value });
                  }}
                  placeholder="Search filename or SHA-256..."
                  className="w-full h-9 pl-8 pr-3 rounded-xl border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-[#0b1120] text-xs"
                />
              </div>

              <select
                value={filterCategory}
                onChange={(e) => {
                  setFilterCategory(e.target.value);
                  loadHistory({ risk_category: e.target.value });
                }}
                className="h-9 px-3 rounded-xl border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-[#0b1120] text-xs"
              >
                <option value="">All Results</option>
                <option value="GREEN">GREEN</option>
                <option value="YELLOW">YELLOW</option>
                <option value="RED">RED</option>
              </select>

              <input
                type="date"
                value={dateFrom}
                onChange={(e) => {
                  setDateFrom(e.target.value);
                  loadHistory({ date_from: e.target.value });
                }}
                className="h-9 px-2.5 rounded-xl border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-[#0b1120] text-xs"
              />
              <input
                type="date"
                value={dateTo}
                onChange={(e) => {
                  setDateTo(e.target.value);
                  loadHistory({ date_to: e.target.value });
                }}
                className="h-9 px-2.5 rounded-xl border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-[#0b1120] text-xs"
              />
            </div>

            <button
              type="button"
              onClick={() => loadHistory()}
              className="px-3 py-1.5 rounded-xl border border-slate-200 dark:border-slate-700 text-xs font-medium hover:bg-slate-100 dark:hover:bg-slate-800"
            >
              Refresh
            </button>
          </div>

          <div className="overflow-auto">
            {historyLoading ? (
              <div className="p-6 text-xs text-slate-500">Loading scan history...</div>
            ) : history.length === 0 ? (
              <div className="p-6 text-xs text-slate-500">No image scan records found.</div>
            ) : (
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-50 dark:bg-[#0e1525] text-slate-500 uppercase text-[11px]">
                  <tr>
                    <th className="px-4 py-2.5">Image</th>
                    <th className="px-4 py-2.5">Format / Size</th>
                    <th className="px-4 py-2.5">SHA-256</th>
                    <th className="px-4 py-2.5">Score</th>
                    <th className="px-4 py-2.5">Scanned At</th>
                    <th className="px-4 py-2.5 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 dark:divide-slate-800/70">
                  {history.map((item) => (
                    <tr key={item.id} className="hover:bg-slate-50 dark:hover:bg-slate-800/40">
                      <td className="px-4 py-2.5 font-mono font-medium text-slate-900 dark:text-slate-100">
                        <div className="flex items-center gap-2.5">
                          {item.thumbnail_b64 && (
                            <img
                              src={item.thumbnail_b64}
                              alt=""
                              className="w-8 h-8 rounded object-cover bg-slate-900 shrink-0"
                            />
                          )}
                          <span className="truncate max-w-[160px]">{item.filename}</span>
                        </div>
                      </td>
                      <td className="px-4 py-2.5 font-mono text-slate-500">
                        {item.file_format} • {formatBytes(item.file_size)}
                      </td>
                      <td className="px-4 py-2.5 font-mono text-slate-400">
                        {item.sha256_hash.slice(0, 14)}...
                      </td>
                      <td className="px-4 py-2.5">
                        <span
                          className={`px-2 py-0.5 rounded-full text-[10px] font-bold border ${badgeForCategory(
                            item.risk_category
                          )}`}
                        >
                          {item.risk_score}/100 ({item.risk_category})
                        </span>
                      </td>
                      <td className="px-4 py-2.5 text-slate-400">
                        {new Date(item.created_at).toLocaleString()}
                      </td>
                      <td className="px-4 py-2.5 text-right space-x-1.5 whitespace-nowrap">
                        <button
                          type="button"
                          onClick={() => {
                            setScanResult(item);
                            setSubTab('scan');
                          }}
                          className="px-2.5 py-1 rounded-lg bg-[#5b93ff]/15 text-[#5b93ff] hover:bg-[#5b93ff]/25 font-medium"
                        >
                          View
                        </button>
                        <button
                          type="button"
                          onClick={() => handleDownloadPdf(item.id)}
                          className="px-2.5 py-1 rounded-lg bg-emerald-500/15 text-emerald-500 hover:bg-emerald-500/25 font-medium"
                        >
                          PDF
                        </button>
                        <button
                          type="button"
                          onClick={() => handleDeleteScan(item.id)}
                          className="px-2.5 py-1 rounded-lg bg-rose-500/15 text-rose-500 hover:bg-rose-500/25 font-medium"
                        >
                          Delete
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </section>
      )}
    </div>
  );
}
