import React, { useState } from 'react';
import { BinaryFrame, FrameKind } from '../types/cordon';
import { formatHexDump } from '../services/crypto';
import { Terminal, Send, ArrowRight, Layers, FileCode } from 'lucide-react';

interface ProtocolInspectorViewProps {
  frames: BinaryFrame[];
  onInjectFrame: (kind: number, headerJson: Record<string, any>, payload: string) => void;
}

export const ProtocolInspectorView: React.FC<ProtocolInspectorViewProps> = ({
  frames,
  onInjectFrame,
}) => {
  const [selectedFrameIndex, setSelectedFrameIndex] = useState(0);
  const [composeKind, setComposeKind] = useState<number>(0x01);
  const [composeHeader, setComposeHeader] = useState<string>(
    JSON.stringify({ action: 'CONNECT', target: 'api.github.com', port: 443 }, null, 2)
  );
  const [composePayload, setComposePayload] = useState<string>('SYN-CONNECT host=api.github.com:443');

  const selectedFrame = frames[selectedFrameIndex] || frames[0];

  const handleSendFrame = () => {
    try {
      const parsed = JSON.parse(composeHeader);
      onInjectFrame(composeKind, parsed, composePayload);
    } catch (e) {
      alert('Ungültiges JSON im Header!');
    }
  };

  const getKindLabel = (kind: number) => {
    switch (kind) {
      case 0x01:
        return { name: '0x01 Connect', plane: 'Control Plane', color: 'text-cyan-400' };
      case 0x02:
        return { name: '0x02 Data Relay', plane: 'Data Plane (Opaque)', color: 'text-emerald-400' };
      case 0x03:
        return { name: '0x03 Ack/Heartbeat', plane: 'Control Plane', color: 'text-slate-400' };
      case 0x04:
        return { name: '0x04 Close Channel', plane: 'Control Plane', color: 'text-amber-400' };
      case 0x05:
        return { name: '0x05 Error / Deny', plane: 'Control Plane', color: 'text-rose-400' };
      case 0x06:
        return { name: '0x06 TargetGate Auth', plane: 'Control Plane', color: 'text-purple-400' };
      default:
        return { name: `0x${kind.toString(16)} Custom`, plane: 'Unknown', color: 'text-slate-300' };
    }
  };

  // Convert payload to simulated buffer for hex dump
  const dummyBuffer = new Uint8Array([
    selectedFrame?.kind || 1,
    selectedFrame?.flags || 0,
    0x00,
    selectedFrame?.seq || 1,
    0x00,
    0x00,
    0x00,
    selectedFrame?.length || 32,
    ...new TextEncoder().encode(JSON.stringify(selectedFrame?.headerJson || {})).slice(0, 48),
  ]);

  const hexRows = formatHexDump(dummyBuffer);

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="bg-slate-900 border border-slate-800 rounded p-6">
        <div className="flex items-center gap-2 text-cyan-400 font-mono text-xs uppercase tracking-wider">
          <Layers className="w-4 h-4" />
          <span>Binäres Named-Pipe Frame-Protokoll &amp; E-3 Pfad-Trennung</span>
        </div>
        <h2 className="text-xl font-bold text-white font-mono mt-1">
          Named Pipe Protocol &amp; Hex Frame Inspector
        </h2>
        <p className="text-xs text-slate-400 mt-1 max-w-3xl">
          Kommunikation zwischen AppContainer-Agent und Cordon erfolgt strikt über binäre Named-Pipe Frames
          <code className="text-cyan-300 ml-1">\\.\pipe\CordonGateway\&lt;agentId&gt;_&lt;nonce&gt;</code>.
          Das Cordon-Layout trennt die Control Plane (Policy &amp; HITL Token Exchange) strikt von der opaken
          Byte-Relay Data Plane (kein In-Band HTTP Parsing).
        </p>

        {/* Binary Layout Diagram */}
        <div className="mt-4 p-3 bg-slate-950 rounded border border-slate-800 font-mono text-xs overflow-x-auto">
          <div className="text-[11px] text-slate-500 mb-2">Cordon Binär-Header-Struktur (Big-Endian):</div>
          <div className="flex items-center gap-1 min-w-[600px]">
            <div className="bg-cyan-950/80 border border-cyan-700/60 p-2 text-center rounded flex-1">
              <div className="text-[10px] text-cyan-400">Byte 0</div>
              <div className="font-bold text-white">Kind (u8)</div>
              <div className="text-[9px] text-slate-400">0x01/0x02/0x06</div>
            </div>
            <div className="bg-slate-800 border border-slate-700 p-2 text-center rounded flex-1">
              <div className="text-[10px] text-slate-400">Byte 1</div>
              <div className="font-bold text-white">Flags (u8)</div>
              <div className="text-[9px] text-slate-400">Sync/Fin/Enc</div>
            </div>
            <div className="bg-slate-800 border border-slate-700 p-2 text-center rounded flex-1">
              <div className="text-[10px] text-slate-400">Bytes 2–3</div>
              <div className="font-bold text-white">Seq (u16)</div>
              <div className="text-[9px] text-slate-400">Sequence No</div>
            </div>
            <div className="bg-purple-950/80 border border-purple-700/60 p-2 text-center rounded flex-1">
              <div className="text-[10px] text-purple-400">Bytes 4–7</div>
              <div className="font-bold text-white">Length (u32)</div>
              <div className="text-[9px] text-slate-400">Header Length</div>
            </div>
            <div className="bg-amber-950/80 border border-amber-700/60 p-2 text-center rounded flex-[2]">
              <div className="text-[10px] text-amber-400">N Bytes</div>
              <div className="font-bold text-white">JSON Header</div>
              <div className="text-[9px] text-slate-400">Target, Port, Action</div>
            </div>
            <div className="bg-emerald-950/80 border border-emerald-700/60 p-2 text-center rounded flex-[3]">
              <div className="text-[10px] text-emerald-400">Rest Bytes</div>
              <div className="font-bold text-white">Payload / Opaque Stream</div>
              <div className="text-[9px] text-slate-400">Raw TCP Relay Data</div>
            </div>
          </div>
        </div>
      </div>

      {/* Main Split View */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Frame Stream List */}
        <div className="bg-slate-900 border border-slate-800 rounded p-4 space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-white font-mono uppercase">
              Protokollierte Frames ({frames.length})
            </h3>
            <span className="text-[11px] text-slate-500 font-mono">Live Stream</span>
          </div>

          <div className="space-y-2 max-h-[500px] overflow-y-auto">
            {frames.map((frame, idx) => {
              const meta = getKindLabel(frame.kind);
              const isSelected = idx === selectedFrameIndex;

              return (
                <div
                  key={idx}
                  onClick={() => setSelectedFrameIndex(idx)}
                  className={`p-3 rounded border text-xs font-mono cursor-pointer transition-colors ${
                    isSelected
                      ? 'bg-slate-800 border-cyan-500 shadow-sm'
                      : 'bg-slate-950/60 border-slate-800/80 hover:bg-slate-800/40'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className={`font-bold ${meta.color}`}>{meta.name}</span>
                    <span className="text-slate-500 text-[10px] tabular-nums">
                      Seq: #{frame.seq}
                    </span>
                  </div>

                  <div className="text-slate-300 text-[11px] mt-1 truncate">
                    {frame.payload || JSON.stringify(frame.headerJson)}
                  </div>

                  <div className="flex items-center justify-between text-[10px] text-slate-500 mt-2 border-t border-slate-800/80 pt-1">
                    <span>{meta.plane}</span>
                    <span>{frame.length} Bytes</span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Detailed Frame & Hex Dump Inspector */}
        <div className="lg:col-span-2 bg-slate-900 border border-slate-800 rounded p-5 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div>
              <h3 className="text-sm font-bold text-white font-mono uppercase">
                Frame-Detailanalyse &amp; Hex Viewer
              </h3>
              <p className="text-xs text-slate-400 font-mono">
                Seq #{selectedFrame?.seq} · {getKindLabel(selectedFrame?.kind).name} ·{' '}
                {getKindLabel(selectedFrame?.kind).plane}
              </p>
            </div>
            <span className="text-xs font-mono bg-cyan-950 text-cyan-300 border border-cyan-800 px-2.5 py-1 rounded">
              Länge: {selectedFrame?.length} Bytes
            </span>
          </div>

          {/* Hex Dump Section */}
          <div className="space-y-1.5">
            <span className="text-xs font-mono text-slate-400 block uppercase">
              Hex Dump (WinDbg / Wireshark Format)
            </span>
            <div className="bg-slate-950 rounded border border-slate-800 p-3 font-mono text-[11px] overflow-x-auto space-y-1 select-all">
              <div className="text-slate-500 pb-1 border-b border-slate-900 flex justify-between">
                <span>Offset</span>
                <span>Hex Bytes (00 - 0F)</span>
                <span>ASCII Representation</span>
              </div>
              {hexRows.map((r, i) => (
                <div key={i} className="flex justify-between gap-4 hover:bg-slate-900/50">
                  <span className="text-slate-600">{r.offset}</span>
                  <span className="text-cyan-400 tracking-wider font-semibold">{r.hex}</span>
                  <span className="text-emerald-400">{r.ascii}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Decoded JSON Header */}
          <div className="space-y-1.5">
            <span className="text-xs font-mono text-slate-400 block uppercase">
              Dekodierter JSON-Header (Control Plane Parameter)
            </span>
            <pre className="bg-slate-950 rounded border border-slate-800 p-3 text-xs font-mono text-amber-300 overflow-x-auto">
              {JSON.stringify(selectedFrame?.headerJson || {}, null, 2)}
            </pre>
          </div>

          {/* Payload Raw Content */}
          <div className="space-y-1.5">
            <span className="text-xs font-mono text-slate-400 block uppercase">
              Payload-Inhalt (Data Plane Relay Stream)
            </span>
            <div className="bg-slate-950 rounded border border-slate-800 p-3 text-xs font-mono text-slate-200 overflow-x-auto max-h-24">
              {selectedFrame?.payload || '—'}
            </div>
          </div>
        </div>
      </div>

      {/* Frame Composer / Tester */}
      <div className="bg-slate-900 border border-slate-800 rounded p-5 space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2 text-cyan-400 font-mono text-xs uppercase">
            <Send className="w-4 h-4" />
            <span>Interaktiver Frame-Composer &amp; Parser-Test</span>
          </div>
          <span className="text-xs text-slate-400 font-mono">
            Testet die Kernel-Pipe-Parser auf Malformed Frames (T10)
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div>
            <label className="text-xs font-mono text-slate-400 block mb-1">Frame Kind:</label>
            <select
              value={composeKind}
              onChange={(e) => setComposeKind(Number(e.target.value))}
              className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-xs font-mono text-white"
            >
              <option value={0x01}>0x01 - CONNECT (Control Plane Handshake)</option>
              <option value={0x02}>0x02 - DATA (Opaque Stream Relay)</option>
              <option value={0x06}>0x06 - TARGETGATE_AUTH (Token Exchange)</option>
              <option value={0x04}>0x04 - CLOSE (Disconnect Channel)</option>
            </select>
          </div>

          <div className="md:col-span-2">
            <label className="text-xs font-mono text-slate-400 block mb-1">
              JSON Header (Payload Header Parameter):
            </label>
            <input
              type="text"
              value={composeHeader}
              onChange={(e) => setComposeHeader(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-xs font-mono text-cyan-300"
            />
          </div>
        </div>

        <div className="flex justify-end">
          <button
            onClick={handleSendFrame}
            className="px-4 py-2 bg-cyan-400 hover:bg-cyan-300 text-slate-950 font-bold text-xs font-mono rounded flex items-center gap-2 cursor-pointer transition-colors shadow-sm"
          >
            <Send className="w-3.5 h-3.5" />
            <span>Frame Encodieren &amp; in Named Pipe injizieren</span>
          </button>
        </div>
      </div>
    </div>
  );
};
