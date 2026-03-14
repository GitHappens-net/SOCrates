import { useEffect, useRef, useState } from "react";
import { BotMessageSquare, Send, Trash2, ShieldAlert, CheckCircle2, XCircle } from "lucide-react";
import { sendChat, clearChat } from "@/api/client";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import remarkBreaks from "remark-breaks";

/* Types */
interface ChatMsg {
  id: number;
  role: "user" | "assistant";
  content: string;
}

interface SoarConfirmPayload {
  title?: string;
  mode?: "live";
  device_ip?: string;
  action_type?: string;
  parameters?: Record<string, unknown>;
  confirm_hint?: string;
}

interface SoarResultPayload {
  ok?: boolean;
  action_id?: number;
  status?: string;
  summary?: string;
  details?: string;
}

const SOAR_CONFIRM_PREFIX = "SOAR_CONFIRM::";
const SOAR_RESULT_PREFIX = "SOAR_RESULT::";

function parseSoarConfirm(content: string): SoarConfirmPayload | null {
  if (!content.startsWith(SOAR_CONFIRM_PREFIX)) return null;
  try {
    return JSON.parse(content.slice(SOAR_CONFIRM_PREFIX.length)) as SoarConfirmPayload;
  } catch {
    return null;
  }
}

function parseSoarResult(content: string): SoarResultPayload | null {
  if (!content.startsWith(SOAR_RESULT_PREFIX)) return null;
  try {
    return JSON.parse(content.slice(SOAR_RESULT_PREFIX.length)) as SoarResultPayload;
  } catch {
    return null;
  }
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

/* Chat Bubble */
function ChatBubble({ msg, onQuickReply }: { msg: ChatMsg; onQuickReply: (text: string) => void }) {
  const isUser = msg.role === "user";
  const normalized = isUser ? msg.content : normalizeAssistantMarkdown(msg.content);
  const confirm = !isUser ? parseSoarConfirm(normalized) : null;
  const result = !isUser ? parseSoarResult(normalized) : null;

  if (confirm) {
    const params = confirm.parameters ?? {};
    return (
      <div className="flex justify-start">
        <div className="max-w-[92%] rounded-lg border border-amber-500 bg-amber-50 px-4 py-3 text-sm text-amber-900">
          <p className="mb-2 flex items-center gap-2 font-semibold">
            <ShieldAlert className="h-4 w-4" />
            {confirm.title ?? "SOAR Action Confirmation"}
          </p>
          <div className="space-y-1 text-xs">
            <p><span className="font-semibold">Mode:</span> {confirm.mode ?? "live"}</p>
            <p><span className="font-semibold">Device:</span> {confirm.device_ip ?? "unknown"}</p>
            <p><span className="font-semibold">Action:</span> {confirm.action_type ?? "unknown"}</p>
            {Object.keys(params).length > 0 && (
              <p><span className="font-semibold">Parameters:</span> {JSON.stringify(params)}</p>
            )}
          </div>
          <p className="mt-2 text-xs text-amber-700">{confirm.confirm_hint ?? "Reply confirm or cancel."}</p>
          <div className="mt-3 flex gap-2">
            <button
              onClick={() => onQuickReply("confirm")}
              className="rounded border border-amber-700 bg-amber-600 px-2.5 py-1 text-xs font-semibold text-white transition hover:bg-amber-700"
            >
              Confirm
            </button>
            <button
              onClick={() => onQuickReply("cancel")}
              className="rounded border border-amber-400 bg-white px-2.5 py-1 text-xs font-semibold text-amber-800 transition hover:bg-amber-100"
            >
              Cancel
            </button>
          </div>
        </div>
      </div>
    );
  }

  if (result) {
    const ok = Boolean(result.ok);
    return (
      <div className="flex justify-start">
        <div className={`max-w-[92%] rounded-lg border px-4 py-3 text-sm ${ok ? "border-green-500 bg-green-50 text-green-900" : "border-red-500 bg-red-50 text-red-900"}`}>
          <p className="mb-1 flex items-center gap-2 font-semibold">
            {ok ? <CheckCircle2 className="h-4 w-4" /> : <XCircle className="h-4 w-4" />}
            {ok ? "SOAR Action Completed" : "SOAR Action Failed"}
          </p>
          <p className="text-xs"><span className="font-semibold">Status:</span> {result.status ?? "unknown"}</p>
          {typeof result.action_id === "number" && result.action_id > 0 && (
            <p className="text-xs"><span className="font-semibold">Action ID:</span> {result.action_id}</p>
          )}
          {result.summary && <p className="mt-1 text-xs">{result.summary}</p>}
          {result.details && <p className="mt-1 text-xs opacity-90">{result.details}</p>}
        </div>
      </div>
    );
  }

  return (
    <div className={`flex ${isUser ? "justify-end" : "justify-start"}`}>
      <div
        className={`rounded-3xl px-4 py-2.5 text-sm leading-relaxed ${
          isUser ? "bg-blue-500 text-white" : "bg-gray-200 text-gray-900"
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

/* Thinking Indicator */
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

/* Main AI Chat Panel */
export default function AIChatPanel() {
  const [messages, setMessages] = useState<ChatMsg[]>([
    {
      id: 1,
      role: "assistant",
      content:
        "Ask me anything about your network security.",
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

  async function sendMessage(text: string): Promise<void> {
    if (!text.trim() || isThinking) return;

    const userMsg: ChatMsg = { id: Date.now(), role: "user", content: text };
    setMessages((prev) => [...prev, userMsg]);
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
        content: "Sorry, but I couldn't responed to your message, something went wrong.",
      };
      setMessages((prev) => [...prev, errMsg]);
    } finally {
      setIsThinking(false);
    }
  }

  async function handleSend(): Promise<void> {
    const text = input.trim();
    if (!text || isThinking) return;
    setInput("");
    await sendMessage(text);
  }

  function handleQuickReply(text: string): void {
    if (isThinking) return;
    void sendMessage(text);
  }

  async function handleClear(): Promise<void> {
    try { await clearChat(); } catch { /* ignore */ }
    setMessages([
      {
        id: Date.now(),
        role: "assistant",
        content: "Chat cleared.",
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
    <div className="flex h-full flex-col w-full rounded-xl border border-black bg-gray-100">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-gray-300 px-4 py-3">
        <div className="flex items-center gap-2">
          <div className="flex h-8 w-8 items-center justify-center">
            <BotMessageSquare className="h-6 w-6 text-gray-700" />
          </div>
          <div>
            <p className="text-md font-semibold text-gray-900">SOCrates AI</p>
          </div>
        </div>
        <button
          onClick={handleClear}
          title="Clear chat"
          className="flex h-8 w-8 items-center justify-center rounded-lg text-gray-700 transition hover:text-red-500"
        >
          <Trash2 className="h-5 w-5" />
        </button>
      </div>

      {/* Messages */}
      <div ref={scrollRef} className="min-h-0 flex-1 space-y-3 overflow-y-auto p-4">
        {messages.map((msg) => (
          <ChatBubble key={msg.id} msg={msg} onQuickReply={handleQuickReply} />
        ))}
        {isThinking && <ThinkingIndicator />}
      </div>

      {/* Input */}
      <div className="border-t border-gray-300 px-4 py-3">
        <div className="flex items-center gap-2">
          <input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Ask about anything..."
            disabled={isThinking}
            className="flex-1 rounded-xl border border-gray-300 bg-gray-50 px-4 py-2 text-sm text-gray-900 outline-none transition focus:border-gray-700 disabled:opacity-50"
          />
          <button
            onClick={() => void handleSend()}
            disabled={!input.trim() || isThinking}
            className="flex h-10 w-10 items-center justify-center rounded-xl bg-blue-500 text-white transition hover:bg-blue disabled:bg-gray-500"
          >
            <Send className="h-4 w-4" />
          </button>
        </div>
      </div>
    </div>
  );
}
