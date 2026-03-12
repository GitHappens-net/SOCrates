import { useEffect, useRef, useState } from "react";
import {
  BotMessageSquare,
  Send,
  ShieldAlert,
  Ban,
  Search,
  CheckCircle2,
  History,
  Zap,
} from "lucide-react";
import {
  INITIAL_ACTION_HISTORY,
  INITIAL_CHAT,
  type ActionHistoryItem,
  type ChatMessage,
  type TextMessage,
  type ThreatMessage,
  type ThreatAction,
  type ThreatInfo,
} from "../data/mockData";

/* â”€â”€ Threat Action Card â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */

interface ThreatCardProps {
  threat: ThreatInfo;
  onAction: (action: ThreatAction, threat: ThreatInfo) => void;
}

function ThreatCard({ threat, onAction }: ThreatCardProps) {
  return (
    <div className="my-2 rounded border border-red-600 bg-red-50 p-3">
      <div className="mb-2 flex items-center gap-2">
        <ShieldAlert className="h-4 w-4 text-red-600" />
        <span className="text-xs font-bold uppercase tracking-wider text-red-700">
          Threat Detected
        </span>
      </div>
      <p className="mb-3 text-sm text-gray-900">{threat.description}</p>
      <div className="flex flex-wrap gap-2">
        <button
          onClick={() => onAction("block", threat)}
          className="flex items-center gap-1.5 rounded border border-red-600 bg-red-50 px-3 py-1.5 text-[11px] font-semibold text-red-700 transition hover:bg-red-100"
        >
          <Ban className="h-3.5 w-3.5" /> Block IP
        </button>
        <button
          onClick={() => onAction("investigate", threat)}
          className="flex items-center gap-1.5 rounded border border-blue-600 bg-blue-50 px-3 py-1.5 text-[11px] font-semibold text-blue-700 transition hover:bg-blue-100"
        >
          <Search className="h-3.5 w-3.5" /> Investigate
        </button>
        <button
          onClick={() => onAction("ignore", threat)}
          className="flex items-center gap-1.5 rounded border border-gray-300 bg-gray-50 px-3 py-1.5 text-[11px] font-semibold text-gray-600 transition hover:bg-gray-100"
        >
          <CheckCircle2 className="h-3.5 w-3.5" /> Ignore
        </button>
      </div>
    </div>
  );
}

/* â”€â”€ Chat Bubble â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */

function ChatBubble({ msg }: { msg: ChatMessage }) {
  const isUser = msg.role === "user";
  return (
    <div className={`flex ${isUser ? "justify-end" : "justify-start"}`}>
      <div
        className={`max-w-[85%] rounded-lg px-4 py-2.5 text-sm leading-relaxed ${
          isUser
            ? "bg-blue-600 text-white"
            : "bg-gray-100 text-gray-900"
        }`}
      >
        {msg.type === "threat" ? (
          <ThreatCard threat={msg.threat} onAction={msg.onAction} />
        ) : (
          <p className="whitespace-pre-wrap">{msg.content}</p>
        )}
      </div>
    </div>
  );
}

/* â”€â”€ Typing Indicator â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */

function TypingDots() {
  return (
    <div className="flex justify-start">
      <div className="rounded-lg bg-gray-100 px-4 py-3 text-gray-500 dot-blink">
        <span>â—</span> <span>â—</span> <span>â—</span>
      </div>
    </div>
  );
}

/* â”€â”€ Main AI Chat Panel â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */

const AI_RESPONSES: string[] = [
  "I've analysed the traffic pattern. The spike from 185.220.101.1 correlates with a known Tor exit node. Recommend blocking.",
  "Port 8080 has been rate-limited. I'm monitoring for further anomalies on that vector.",
  "The DDoS signature matches Mirai botnet variant. I've already triggered an incident report (INC-20260307-002).",
  "Current traffic from Germany: 847 flows in the last hour. 12 flagged as suspicious â€” mostly TLS probes on non-standard ports.",
  "False positive confirmed. The traffic spike was from a scheduled backup job. I've updated the baseline.",
  "All east-zone firewalls are responding. No configuration drift detected.",
];

const THREAT_POOL: Omit<ThreatInfo, "id">[] = [
  { description: "DoS Attack detected from 45.33.32.156 â€” 50k SYN packets/sec targeting port 443.", ip: "45.33.32.156" },
  { description: "Brute Force SSH attempt from 91.198.174.192 â€” 312 failed logins in 5 minutes.",   ip: "91.198.174.192" },
  { description: "SQL Injection probe from 203.0.113.42 â€” malicious payload detected in query string.", ip: "203.0.113.42" },
];

export default function AIChatPanel() {
  const [messages, setMessages] = useState<ChatMessage[]>(INITIAL_CHAT);
  const [input, setInput] = useState("");
  const [isTyping, setIsTyping] = useState(false);
  const [actionHistory, setActionHistory] = useState<ActionHistoryItem[]>(INITIAL_ACTION_HISTORY);
  const [showHistory, setShowHistory] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [messages, isTyping]);

  useEffect(() => {
    const iv = setInterval(() => {
      const base = THREAT_POOL[Math.floor(Math.random() * THREAT_POOL.length)];
      const threat: ThreatInfo = { id: Date.now(), ...base };
      const msg: ThreatMessage = {
        id: threat.id,
        role: "assistant",
        type: "threat",
        content: "",
        threat,
        onAction: handleThreatAction,
      };
      setMessages((prev) => [...prev, msg]);
    }, 20_000);
    return () => clearInterval(iv);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  function handleThreatAction(action: ThreatAction, threat: ThreatInfo): void {
    const actionText =
      action === "block"
        ? `Blocked IP ${threat.ip}`
        : action === "investigate"
        ? `Investigating traffic from ${threat.ip}`
        : `Ignored threat from ${threat.ip}`;

    setActionHistory((prev) => [
      {
        id: Date.now(),
        time: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }),
        action: actionText,
        context: threat.description.slice(0, 60) + "â€¦",
      },
      ...prev,
    ]);

    const reply: TextMessage = {
      id: Date.now(),
      role: "assistant",
      type: "text",
      content: `âœ… Action taken: ${actionText}`,
    };
    setMessages((prev) => [...prev, reply]);
  }

  async function handleSend(): Promise<void> {
    const text = input.trim();
    if (!text) return;

    const userMsg: TextMessage = { id: Date.now(), role: "user", type: "text", content: text };
    setMessages((prev) => [...prev, userMsg]);
    setInput("");
    setIsTyping(true);

    try {
      const res = await fetch("/api/v1/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: text }),
      });

      if (res.ok && res.headers.get("content-type")?.includes("text/event-stream")) {
        const reader = res.body!.getReader();
        const decoder = new TextDecoder();
        let aiText = "";
        const aiId = Date.now() + 1;

        const streamMsg: TextMessage = { id: aiId, role: "assistant", type: "text", content: "" };
        setMessages((prev) => [...prev, streamMsg]);
        setIsTyping(false);

        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          const chunk = decoder.decode(value);
          const lines = chunk.split("\n").filter((l) => l.startsWith("data: "));
          for (const line of lines) {
            const payload = line.slice(6);
            if (payload === "[DONE]") break;
            try {
              const parsed = JSON.parse(payload) as { content?: string };
              aiText += parsed.content ?? "";
              setMessages((prev) =>
                prev.map((m) =>
                  m.id === aiId ? ({ ...m, content: aiText } as TextMessage) : m
                )
              );
            } catch {
              // ignore malformed SSE frames
            }
          }
        }
        return;
      }
    } catch {
      // Backend unreachable â€” fall back to mock
    }

    setTimeout(() => {
      setIsTyping(false);
      const reply: TextMessage = {
        id: Date.now() + 1,
        role: "assistant",
        type: "text",
        content: AI_RESPONSES[Math.floor(Math.random() * AI_RESPONSES.length)],
      };
      setMessages((prev) => [...prev, reply]);
    }, 1200 + Math.random() * 1000);
  }

  function handleKeyDown(e: React.KeyboardEvent<HTMLInputElement>): void {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      void handleSend();
    }
  }

  return (
    <div className="bg-white border border-black flex h-full flex-col rounded-lg">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-black px-4 py-3">
        <div className="flex items-center gap-2">
          <div className="flex h-8 w-8 items-center justify-center rounded border border-black">
            <BotMessageSquare className="h-4 w-4 text-black" />
          </div>
          <div>
            <p className="text-sm font-semibold text-black">Sentinel AI Agent</p>
            <p className="text-[10px] text-green-600">Online â€¢ Monitoring</p>
          </div>
        </div>
        <button
          onClick={() => setShowHistory(!showHistory)}
          title="Action History"
          className={`flex h-8 w-8 items-center justify-center rounded border transition ${
            showHistory
              ? "border-black bg-black text-white"
              : "border-gray-300 text-gray-500 hover:border-black hover:text-black"
          }`}
        >
          <History className="h-4 w-4" />
        </button>
      </div>

      {/* Action History Panel */}
      {showHistory && (
        <div className="max-h-[200px] overflow-y-auto border-b border-gray-200 bg-gray-50 px-4 py-3">
          <p className="mb-2 flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-wider text-gray-500">
            <Zap className="h-3 w-3 text-blue-600" /> Autonomous Action Log
          </p>
          <div className="space-y-2">
            {actionHistory.map((a) => (
              <div key={a.id} className="rounded border border-gray-200 bg-white px-3 py-2 text-xs">
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-blue-700">{a.action}</span>
                  <span className="font-mono text-gray-500">{a.time}</span>
                </div>
                <p className="mt-0.5 text-gray-500">{a.context}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Messages */}
      <div ref={scrollRef} className="flex-1 space-y-3 overflow-y-auto p-4">
        {messages.map((msg) => (
          <ChatBubble key={msg.id} msg={msg} />
        ))}
        {isTyping && <TypingDots />}
      </div>

      {/* Input */}
      <div className="border-t border-black p-3">
        <div className="flex items-center gap-2 rounded border border-gray-300 bg-gray-50 px-3 py-2 focus-within:border-black transition">
          <input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Ask Sentinel or run a commandâ€¦"
            className="flex-1 bg-transparent text-sm text-gray-900 placeholder-gray-400 outline-none"
          />
          <button
            onClick={() => void handleSend()}
            disabled={!input.trim()}
            className="flex h-8 w-8 items-center justify-center rounded bg-black text-white transition hover:bg-gray-800 disabled:opacity-30"
          >
            <Send className="h-4 w-4" />
          </button>
        </div>
        <p className="mt-1.5 px-1 text-[10px] text-gray-400">
          Try: "Why did you block that IP?" Â· "Show traffic from Germany" Â· "Close port 8080"
        </p>
      </div>
    </div>
  );
}
