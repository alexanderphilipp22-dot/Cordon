import React, { useState } from 'react';
import { CSHARP_FILES, CSharpFile } from '../services/csharpSourceCode';
import { Copy, Check, Download, FileCode, Terminal, BookOpen, ExternalLink } from 'lucide-react';

export const CodebaseView: React.FC = () => {
  const [selectedFileIndex, setSelectedFileIndex] = useState(0);
  const [copied, setCopied] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');

  const filteredFiles = CSHARP_FILES.filter(
    (f) =>
      f.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      f.description.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const activeFile = CSHARP_FILES[selectedFileIndex] || CSHARP_FILES[0];

  const handleCopy = () => {
    navigator.clipboard.writeText(activeFile.content);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownload = (file: CSharpFile) => {
    const blob = new Blob([file.content], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = file.name;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const handleDownloadAll = () => {
    CSHARP_FILES.forEach((file) => handleDownload(file));
  };

  const lines = activeFile.content.split('\n');

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="bg-slate-900 border border-slate-800 rounded p-6 flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 text-cyan-400 font-mono text-xs uppercase tracking-wider">
            <Terminal className="w-4 h-4" />
            <span>Windows C# .NET Produktions-Codebasis</span>
          </div>
          <h2 className="text-xl font-bold text-white font-mono mt-1">
            Cordon C# Quellcode-Repository &amp; Exporter
          </h2>
          <p className="text-xs text-slate-400 mt-1 max-w-3xl">
            Kompilierfertige Windows C#-Klassen mit nativer Win32 Security P/Invoke Integration,
            interaktivem Human-in-the-Loop Choke Point, E-1 Genotyp-Rotation, E-2 Entropie-Steuer,
            E-3 Control/Data Pfadtrennung und E-4 Lineage-Apoptose.
          </p>
        </div>

        <button
          onClick={handleDownloadAll}
          className="px-4 py-2 bg-cyan-400 hover:bg-cyan-300 text-slate-950 font-bold text-xs font-mono rounded transition-colors flex items-center gap-2 cursor-pointer shadow-sm shadow-cyan-950"
        >
          <Download className="w-3.5 h-3.5" />
          <span>Alle C#-Dateien herunterladen</span>
        </button>
      </div>

      {/* Main File Explorer & Code Viewer Split */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* File Navigator Sidebar */}
        <div className="bg-slate-900 border border-slate-800 rounded p-4 space-y-3">
          <div className="text-xs font-mono text-slate-400 uppercase font-bold border-b border-slate-800 pb-2">
            Dateien ({CSHARP_FILES.length})
          </div>

          <div className="space-y-1.5 max-h-[600px] overflow-y-auto">
            {CSHARP_FILES.map((file, idx) => {
              const isSelected = idx === selectedFileIndex;

              return (
                <div
                  key={file.name}
                  onClick={() => setSelectedFileIndex(idx)}
                  className={`p-2.5 rounded border text-xs font-mono cursor-pointer transition-colors ${
                    isSelected
                      ? 'bg-slate-800 border-cyan-500 text-white'
                      : 'bg-slate-950/60 border-slate-800/80 text-slate-400 hover:bg-slate-800/40 hover:text-slate-200'
                  }`}
                >
                  <div className="flex items-center gap-2">
                    <FileCode className="w-4 h-4 text-cyan-400 shrink-0" />
                    <span className="font-semibold truncate">{file.name}</span>
                  </div>
                  <div className="text-[10px] text-slate-500 mt-1 truncate pl-6">
                    {file.path}
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Code Editor & Viewer */}
        <div className="lg:col-span-3 bg-slate-900 border border-slate-800 rounded overflow-hidden flex flex-col">
          {/* File Tab Header */}
          <div className="bg-slate-950 px-5 py-3 border-b border-slate-800 flex flex-wrap items-center justify-between gap-3">
            <div>
              <div className="flex items-center gap-2 text-white font-mono text-sm font-bold">
                <FileCode className="w-4 h-4 text-cyan-400" />
                <span>{activeFile.name}</span>
                <span className="text-xs text-slate-500 font-normal">({activeFile.path})</span>
              </div>
              <div className="text-xs text-slate-400 mt-0.5">
                {activeFile.description}
              </div>
            </div>

            <div className="flex items-center gap-2">
              <button
                onClick={handleCopy}
                className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono rounded border border-slate-700 flex items-center gap-1.5 transition-colors cursor-pointer"
              >
                {copied ? (
                  <>
                    <Check className="w-3.5 h-3.5 text-emerald-400" />
                    <span>Kopiert!</span>
                  </>
                ) : (
                  <>
                    <Copy className="w-3.5 h-3.5" />
                    <span>Code kopieren</span>
                  </>
                )}
              </button>

              <button
                onClick={() => handleDownload(activeFile)}
                className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono rounded border border-slate-700 flex items-center gap-1.5 transition-colors cursor-pointer"
              >
                <Download className="w-3.5 h-3.5" />
                <span>Download</span>
              </button>
            </div>
          </div>

          {/* Syntax Highlighted Code Viewer with Line Numbers */}
          <div className="bg-slate-950 p-4 font-mono text-xs overflow-x-auto max-h-[580px] overflow-y-auto leading-relaxed select-text">
            <div className="flex">
              {/* Line Numbers Column */}
              <div className="pr-4 text-slate-600 select-none text-right min-w-[40px] border-r border-slate-800/80 mr-4">
                {lines.map((_, i) => (
                  <div key={i} className="tabular-nums">
                    {i + 1}
                  </div>
                ))}
              </div>

              {/* Code Content Column */}
              <pre className="text-slate-200 flex-1 overflow-x-auto">
                <code>{activeFile.content}</code>
              </pre>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
