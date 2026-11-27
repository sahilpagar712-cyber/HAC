import React, { useRef, useState } from 'react';
import {
  Upload,
  FileText,
  Trash2,
  Database,
  Filter,
  Check,
  AlertCircle,
} from 'lucide-react';
import { PII_TYPES, PII_TYPE_ORDER } from '../engine/piiDetector.js';
import { SAMPLE_DATASETS } from '../data/sampleDatasets.js';

export function InputPanel({
  inputText,
  onTextChange,
  sourceMeta,
  onFileLoaded,
  onLoadSample,
  onClear,
  enabledTypes,
  onToggleType,
  onSetAllTypes,
}) {
  const fileInputRef = useRef(null);
  const [isDragging, setIsDragging] = useState(false);
  const [uploadError, setUploadError] = useState('');

  const charCount = inputText.length;
  const wordCount = inputText.trim()
    ? inputText.trim().split(/\s+/).length
    : 0;
  const lineCount = inputText ? inputText.split(/\r?\n/).length : 0;

  const processFile = (file) => {
    setUploadError('');
    if (!file) return;
    const extMatch = file.name.match(/\.(txt|csv)$/i);
    if (!extMatch) {
      setUploadError('Unsupported file format. Please upload a .txt or .csv file.');
      return;
    }

    const reader = new FileReader();
    reader.onload = (event) => {
      const content = typeof event.target?.result === 'string' ? event.target.result : '';
      const dotIndex = file.name.lastIndexOf('.');
      const baseName = dotIndex > 0 ? file.name.slice(0, dotIndex) : file.name;
      const extension = extMatch[1].toLowerCase();
      onFileLoaded(content, {
        fileName: file.name,
        baseName,
        extension,
        isSample: false,
        rawFile: file,
      });
    };
    reader.onerror = () => {
      setUploadError('Failed to read file locally via FileReader.');
    };
    reader.readAsText(file);
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
    const file = e.dataTransfer.files?.[0];
    processFile(file);
  };

  const handleDragOver = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (!isDragging) setIsDragging(true);
  };

  const handleDragLeave = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
  };

  const allEnabled = PII_TYPE_ORDER.every((t) => enabledTypes[t]);

  return (
    <section className="rounded-2xl border border-slate-200 dark:border-slate-800/90 bg-white dark:bg-[#131b2e] shadow-sm overflow-hidden">
      {/* Header & Sample Loader */}
      <div className="px-4 sm:px-5 py-3.5 border-b border-slate-200 dark:border-slate-800 flex flex-wrap items-center justify-between gap-3 bg-slate-50/70 dark:bg-[#0f1627]">
        <div className="flex items-center gap-2.5">
          <FileText className="w-4 h-4 text-[#5b93ff]" />
          <h2 className="text-sm font-semibold text-slate-900 dark:text-white">
            Source Data Input
          </h2>
          {sourceMeta?.fileName && (
            <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md text-xs font-mono bg-cyan-500/10 text-cyan-700 dark:text-cyan-300 border border-cyan-500/30">
              {sourceMeta.fileName}
            </span>
          )}
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <span className="text-xs font-medium text-slate-500 dark:text-slate-400 flex items-center gap-1 mr-1">
            <Database className="w-3.5 h-3.5" />
            Samples:
          </span>
          {SAMPLE_DATASETS.map((sample) => {
            const isActive = sourceMeta?.sampleId === sample.id;
            return (
              <button
                key={sample.id}
                type="button"
                title={sample.description}
                onClick={() => {
                  setUploadError('');
                  onLoadSample(sample);
                }}
                className={`px-2.5 py-1 rounded-lg text-xs font-medium border transition-all ${
                  isActive
                    ? 'bg-emerald-500 text-white border-emerald-500 shadow-sm shadow-emerald-500/25'
                    : 'bg-white dark:bg-slate-800 text-slate-700 dark:text-slate-200 border-slate-200 dark:border-slate-700 hover:border-emerald-500/50 hover:text-emerald-600 dark:hover:text-emerald-400'
                }`}
              >
                {sample.shortLabel}
                <span className="ml-1 opacity-70 text-[10px] uppercase">
                  .{sample.extension}
                </span>
              </button>
            );
          })}
          {inputText && (
            <button
              type="button"
              onClick={() => {
                setUploadError('');
                onClear();
              }}
              className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg text-xs font-medium text-rose-600 dark:text-rose-400 hover:bg-rose-500/10 border border-transparent hover:border-rose-500/30 transition-colors"
            >
              <Trash2 className="w-3.5 h-3.5" />
              Clear
            </button>
          )}
        </div>
      </div>

      {/* Editor + Dropzone */}
      <div className="p-4 sm:p-5 grid grid-cols-1 lg:grid-cols-12 gap-4">
        <div className="lg:col-span-9 flex flex-col gap-2">
          <textarea
            value={inputText}
            onChange={(e) => onTextChange(e.target.value)}
            rows={7}
            spellCheck={false}
            placeholder="Paste raw server logs, CSV records, KYC forms, or clinical notes here — all parsing runs 100% locally in your browser..."
            className="w-full rounded-xl border border-slate-200 dark:border-slate-700/80 bg-slate-50 dark:bg-slate-950/80 px-3.5 py-3 text-xs sm:text-[13px] leading-relaxed font-mono text-slate-900 dark:text-slate-100 placeholder:text-slate-400 dark:placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-emerald-500/50 focus:border-emerald-500 resize-y custom-scrollbar"
          />

          <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-slate-500 dark:text-slate-400">
            <div className="flex items-center gap-4 font-mono">
              <span>{charCount.toLocaleString()} chars</span>
              <span>{wordCount.toLocaleString()} words</span>
              <span>{lineCount.toLocaleString()} lines</span>
            </div>
            {uploadError && (
              <div className="flex items-center gap-1.5 text-rose-500 font-medium">
                <AlertCircle className="w-3.5 h-3.5" />
                {uploadError}
              </div>
            )}
          </div>
        </div>

        {/* Drag & Drop FileReader Zone */}
        <div className="lg:col-span-3 flex flex-col">
          <div
            onDrop={handleDrop}
            onDragOver={handleDragOver}
            onDragLeave={handleDragLeave}
            onClick={() => fileInputRef.current?.click()}
            role="button"
            tabIndex={0}
            onKeyDown={(e) => {
              if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                fileInputRef.current?.click();
              }
            }}
            className={`flex-1 min-h-[140px] rounded-xl border-2 border-dashed p-4 flex flex-col items-center justify-center text-center cursor-pointer transition-all ${
              isDragging
                ? 'border-emerald-500 bg-emerald-500/10 scale-[0.99]'
                : 'border-slate-300 dark:border-slate-700 hover:border-emerald-500/60 bg-slate-50/60 dark:bg-slate-950/40'
            }`}
          >
            <input
              ref={fileInputRef}
              type="file"
              accept=".txt,.csv,text/plain,text/csv"
              className="hidden"
              onChange={(e) => {
                processFile(e.target.files?.[0]);
                e.target.value = '';
              }}
            />
            <div className="h-10 w-10 rounded-full bg-emerald-500/10 text-emerald-500 flex items-center justify-center mb-2.5">
              <Upload className="w-5 h-5" />
            </div>
            <p className="text-xs font-semibold text-slate-800 dark:text-slate-200">
              Drop <span className="font-mono">.txt</span> or{' '}
              <span className="font-mono">.csv</span> here
            </p>
            <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-1">
              or click to browse locally via FileReader
            </p>
          </div>
        </div>
      </div>

      {/* Granular PII Category Filter Toggles */}
      <div className="px-4 sm:px-5 py-3 border-t border-slate-200 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-900/50 flex flex-wrap items-center justify-between gap-2.5">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-xs font-medium text-slate-500 dark:text-slate-400 flex items-center gap-1.5 mr-1">
            <Filter className="w-3.5 h-3.5" />
            Redact Categories:
          </span>
          {PII_TYPE_ORDER.map((typeKey) => {
            const meta = PII_TYPES[typeKey];
            const active = !!enabledTypes[typeKey];
            return (
              <button
                key={typeKey}
                type="button"
                onClick={() => onToggleType(typeKey)}
                aria-pressed={active}
                className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium border transition-all ${
                  active
                    ? meta.badgeClass
                    : 'bg-slate-100 dark:bg-slate-800/60 text-slate-400 dark:text-slate-500 border-slate-200 dark:border-slate-800 opacity-70 hover:opacity-100'
                }`}
              >
                <span
                  className={`w-2 h-2 rounded-full ${
                    active ? meta.dotClass : 'bg-slate-400 dark:bg-slate-600'
                  }`}
                />
                <span>{meta.label}</span>
                {active && <Check className="w-3 h-3" />}
              </button>
            );
          })}
        </div>

        <button
          type="button"
          onClick={() => onSetAllTypes(!allEnabled)}
          className="text-xs font-medium text-emerald-600 dark:text-emerald-400 hover:underline"
        >
          {allEnabled ? 'Disable All' : 'Enable All'}
        </button>
      </div>
    </section>
  );
}
