import { useEffect, useRef, useState } from "react";
import {
  BotMessageSquare,
  Send,
  Trash2,
} from "lucide-react";
import { sendChat, clearChat } from "../api/client";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import remarkBreaks from "remark-breaks";

/* ── Types ────────────────────────────────────────────────────────── */

interface ChatMsg {
  id: number;
  role: "user" | "assistant";
  content: string;
}

function normalizeAssistantMarkdown(input: string): string {
  // Handle double-escaped payloads coming from JSON strings.
  let text = input
    .replace(/\\r\\n/g, "\n")
    .replace(/\\n/g, "\n")
    .replace(/\\t/g, "\t");

  // If headers were escaped (\#), unescape them.
  text = text.replace(/(^|\n)\\#/g, "$1#");

  // Dedent common leading whitespace to avoid accidental code blocks.
  const lines = text.split("\n");
  const nonEmpty = lines.filter((l) => l.trim().length > 0);
  const minIndent = nonEmpty.length
    ? Math.min(...nonEmpty.map((l) => (l.match(/^\s*/)?.[0].length ?? 0)))
    : 0;
  if (minIndent > 0) {
    text = lines.map((l) => l.slice(minIndent)).join("\n");
  }

  return text;
}

/* ── Chat Bubble ─────────────────────────────────────────────────── */

function ChatBubble({ msg }: { msg: ChatMsg }) {
  const isUser = msg.role === "user";
  const normalized = isUser ? msg.content : normalizeAssistantMarkdown(msg.content);
  return (
    <div className={`flex ${isUser ? "justify-end" : "justify-start"}`}>
      <div
        className={`max-w-[85%] rounded-lg px-4 py-2.5 text-sm leading-relaxed ${
          isUser ? "bg-blue-600 text-white" : "bg-gray-100 text-gray-900"
        }`}
      >
        {isUser ? (
          <p className="whitespace-pre-wrap">{normalized}</p>
        ) : (
          <div className="chat-markdown">
            <ReactMarkdown
              remarkPlugins={[remarkGfm, remarkBreaks]}
              components={{
                h1: ({ children }) => <h1 className="text-[1.05rem] font-bold">{children}</h1>,
                h2: ({ children }) => <h2 className="text-[1rem] font-bold">{children}</h2>,
                h3: ({ children }) => <h3 className="text-[0.95rem] font-bold">{children}</h3>,
                p: ({ children }) => <p className="my-2">{children}</p>,
                ul: ({ children }) => <ul className="my-2 list-disc pl-5">{children}</ul>,
                ol: ({ children }) => <ol className="my-2 list-decimal pl-5">{children}</ol>,
                li: ({ children }) => <li className="my-1">{children}</li>,
                pre: ({ children }) => (
                  <pre className="my-2 overflow-x-auto rounded bg-gray-900 p-3 text-gray-100">{children}</pre>
                ),
                code: ({ children, className }) => (
                  <code className={`text-[12px] ${className ?? ""}`}>{children}</code>
                ),
              }}
            >
              {normalized}
            </ReactMarkdown>
          </div>
        )}
      </div>
    </div>
  );
}

/* ── Thinking Indicator ──────────────────────────────────────────── */

function ThinkingIndicator() {
  return (
    <div className="flex justify-start">
      <div className="flex items-center gap-2 rounded-lg bg-gray-100 px-4 py-3">
        <div className="flex gap-1">
          <span className="h-2 w-2 animate-bounce rounded-full bg-gray-400" style={{ animationDelay: "0ms" }} />
          <span className="h-2 w-2 animate-bounce rounded-full bg-gray-400" style={{ animationDelay: "150ms" }} />
          <span className="h-2 w-2 animate-bounce rounded-full bg-gray-400" style={{ animationDelay: "300ms" }} />
        </div>
        <span className="text-xs text-gray-500">Thinking...</span>
      </div>
    </div>
  );
}

/* ── Main AI Chat Panel ──────────────────────────────────────────── */

export default function AIChatPanel() {
  const [messages, setMessages] = useState<ChatMsg[]>([
    {
      id: 1,
      role: "assistant",
      content:
        "SOCrates AI Agent online. I have access to the full log and alert database. Ask me anything about your network security.",
    },
  ]);
  const [input, setInput] = useState("");
  const [isThinking, setIsThinking] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);

  /* Auto-scroll to bottom */
  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [messages, isThinking]);

  async function handleSend(): Promise<void> {
    const text = input.trim();
    if (!text || isThinking) return;

    const userMsg: ChatMsg = { id: Date.now(), role: "user", content: text };
    setMessages((prev) => [...prev, userMsg]);
    setInput("");
    setIsThinking(true);

    try {
      const resp = await sendChat(text);
      const aiMsg: ChatMsg = {
        id: Date.now() + 1,
        role: "assistant",
        content: resp.reply,
      };
      setMessages((prev) => [...prev, aiMsg]);
    } catch {
      const errMsg: ChatMsg = {
        id: Date.now() + 1,
        role: "assistant",
        content: "Sorry, I couldn't reach the backend. Make sure the server is running.",
      };
      setMessages((prev) => [...prev, errMsg]);
    } finally {
      setIsThinking(false);
    }
  }

  async function handleClear(): Promise<void> {
    try { await clearChat(); } catch { /* ignore */ }
    setMessages([
      {
        id: Date.now(),
        role: "assistant",
        content: "Chat cleared. How can I help?",
      },
    ]);
  }

  function handleKeyDown(e: React.KeyboardEvent<HTMLInputElement>): void {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      void handleSend();
    }
  }

  return (
    <div className="flex h-full flex-col rounded-lg border border-black bg-white">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-black px-4 py-3">
        <div className="flex items-center gap-2">
          <div className="flex h-8 w-8 items-center justify-center rounded border border-black">
            <BotMessageSquare className="h-4 w-4 text-black" />
          </div>
          <div>
            <p className="text-sm font-semibold text-black">SOCrates AI</p>
            <p className="text-[10px] text-green-600">Online</p>
          </div>
        </div>
        <button
          onClick={handleClear}
          title="Clear chat"
          className="flex h-8 w-8 items-center justify-center rounded border border-gray-300 text-gray-500 transition hover:border-black hover:text-black"
        >
          <Trash2 className="h-4 w-4" />
        </button>
      </div>

      {/* Messages — min-h-0 + flex-1 + overflow-y-auto fixes the scroll bug */}
      <div ref={scrollRef} className="min-h-0 flex-1 space-y-3 overflow-y-auto p-4">
        {messages.map((msg) => (
          <ChatBubble key={msg.id} msg={msg} />
        ))}
        {isThinking && <ThinkingIndicator />}
      </div>

      {/* Input */}
      <div className="border-t border-gray-200 px-4 py-3">
        <div className="flex items-center gap-2">
          <input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Ask about your network..."
            disabled={isThinking}
            className="flex-1 rounded-lg border border-gray-300 bg-gray-50 px-4 py-2.5 text-sm text-gray-900 outline-none transition focus:border-black disabled:opacity-50"
          />
          <button
            onClick={() => void handleSend()}
            disabled={!input.trim() || isThinking}
            className="flex h-10 w-10 items-center justify-center rounded-lg bg-black text-white transition hover:bg-gray-800 disabled:opacity-30"
          >
            <Send className="h-4 w-4" />
          </button>
        </div>
      </div>
    </div>
  );
}
