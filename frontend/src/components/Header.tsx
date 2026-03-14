import { Wifi, ToggleLeft, ToggleRight } from "lucide-react";
import { useDataMode } from "@/hooks/useDataMode";

export default function Header() {
  const { useMock, toggleMock } = useDataMode();

  return (
    <header className="sticky top-0 z-30 flex items-center justify-between py-4 bg-gray-100">

      {/* Left — branding */}
      <div className="flex items-center gap-3">
        <h1 className="font-unica text-3xl text-blue-500">
          SOCRATES
        </h1>
      </div>

      {/* mock toggle + connection indicator */}
      <div className="flex items-center gap-4">
        <button
          onClick={toggleMock}
          className="flex items-center gap-1.5 rounded-lg border border-blue-300/40 bg-blue-800/40 px-3 py-1 text-sm font-medium text-white transition hover:bg-blue-700/60"
          title={useMock ? "Switch to live API" : "Switch to mock data"}
        >
          {useMock ? (
            <ToggleRight className="h-5 w-5" />
          ) : (
            <ToggleLeft className="h-5 w-5" />
          )}
          <span className={useMock ? "bg-amber-200 text-amber-400" : "text-gray-200"}>
            {useMock ? "Mock" : "Live"}
          </span>
        </button>

        <div className="flex items-center gap-2 rounded-lg border border-emerald-300/60 bg-emerald-500/20 px-3 py-1">
          <Wifi className="h-5 w-5 text-green-400" />
          <span className="text-sm font-semibold text-green-400">Operational</span>
        </div>
      </div>
    </header>
  );
}
