import React, { useState } from 'react';
import { Send, X, AlertTriangle, Shield, Globe } from 'lucide-react';

interface NewRequestModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSubmit: (targetHost: string, targetPort: number, method: string) => void;
}

export const NewRequestModal: React.FC<NewRequestModalProps> = ({
  isOpen,
  onClose,
  onSubmit,
}) => {
  const [targetHost, setTargetHost] = useState('api.anthropic.com');
  const [targetPort, setTargetPort] = useState(443);
  const [method, setMethod] = useState('POST');

  if (!isOpen) return null;

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!targetHost) return;
    onSubmit(targetHost, targetPort, method);
    onClose();
  };

  const setPreset = (host: string, port: number, meth: string) => {
    setTargetHost(host);
    setTargetPort(port);
    setMethod(meth);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="bg-slate-900 border border-slate-700 rounded-lg max-w-lg w-full shadow-2xl overflow-hidden flex flex-col">
        {/* Header */}
        <div className="bg-slate-950 px-6 py-4 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Globe className="w-4 h-4 text-cyan-400" />
            <h3 className="text-sm font-bold text-white font-mono uppercase">
              Agenten-Verbindungsversuch Simulieren
            </h3>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-white transition-colors cursor-pointer"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Form Body */}
        <form onSubmit={handleSubmit} className="p-6 space-y-4 text-xs font-mono">
          <p className="text-slate-400">
            Simuliere, wie ein isolierter AppContainer-Agent versucht, eine ausgehende Verbindung
            über die Named Pipe zu initialisieren. Dies testet den interaktiven Choke Point oder
            den DNS-Rebinding-Schutz live.
          </p>

          <div className="space-y-1.5">
            <label className="text-slate-300 block font-semibold">Ziel-Host / Domain:</label>
            <input
              type="text"
              value={targetHost}
              onChange={(e) => setTargetHost(e.target.value)}
              placeholder="z.B. api.openai.com oder 169.254.169.254"
              className="w-full bg-slate-950 border border-slate-800 rounded p-2.5 text-cyan-300 focus:border-cyan-500 focus:outline-none"
              required
            />
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1.5">
              <label className="text-slate-300 block font-semibold">Port:</label>
              <input
                type="number"
                value={targetPort}
                onChange={(e) => setTargetPort(Number(e.target.value))}
                className="w-full bg-slate-950 border border-slate-800 rounded p-2.5 text-white focus:border-cyan-500 focus:outline-none"
                required
              />
            </div>

            <div className="space-y-1.5">
              <label className="text-slate-300 block font-semibold">Methode:</label>
              <select
                value={method}
                onChange={(e) => setMethod(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded p-2.5 text-white focus:border-cyan-500 focus:outline-none"
              >
                <option value="CONNECT">CONNECT</option>
                <option value="GET">GET</option>
                <option value="POST">POST</option>
                <option value="HEAD">HEAD</option>
              </select>
            </div>
          </div>

          {/* Quick Presets */}
          <div className="space-y-1.5 pt-2">
            <span className="text-slate-500 text-[11px] block">Test-Presets wählen:</span>
            <div className="flex flex-wrap gap-1.5">
              <button
                type="button"
                onClick={() => setPreset('api.openai.com', 443, 'POST')}
                className="px-2 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-[11px] cursor-pointer"
              >
                KI-API (Unbekannt / HITL)
              </button>
              <button
                type="button"
                onClick={() => setPreset('169.254.169.254', 80, 'GET')}
                className="px-2 py-1 bg-rose-950/50 border border-rose-800/40 text-rose-300 hover:bg-rose-900/60 rounded text-[11px] cursor-pointer"
              >
                Cloud Metadata (SSRF Rebind Block)
              </button>
              <button
                type="button"
                onClick={() => setPreset('127.0.0.1', 8080, 'GET')}
                className="px-2 py-1 bg-amber-950/50 border border-amber-800/40 text-amber-300 hover:bg-amber-900/60 rounded text-[11px] cursor-pointer"
              >
                Localhost (Loopback Block)
              </button>
              <button
                type="button"
                onClick={() => setPreset('docs.python.org', 443, 'GET')}
                className="px-2 py-1 bg-emerald-950/50 border border-emerald-800/40 text-emerald-300 hover:bg-emerald-900/60 rounded text-[11px] cursor-pointer"
              >
                Python Docs (Statisch Erlaubt)
              </button>
            </div>
          </div>

          {/* Submit Buttons */}
          <div className="flex justify-end gap-2 pt-4 border-t border-slate-800">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 bg-slate-800 text-slate-300 rounded hover:bg-slate-700 transition-colors cursor-pointer"
            >
              Abbrechen
            </button>
            <button
              type="submit"
              className="px-4 py-2 bg-cyan-400 hover:bg-cyan-300 text-slate-950 font-bold rounded flex items-center gap-1.5 transition-colors cursor-pointer shadow-sm shadow-cyan-950"
            >
              <Send className="w-3.5 h-3.5" />
              <span>Verbindung anfragen</span>
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
