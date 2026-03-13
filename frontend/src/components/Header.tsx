import { Wifi, ToggleLeft, ToggleRight } from "lucide-react";
import { useDataMode } from "../context/DataContext";

export default function Header() {
  const { useMock, toggleMock } = useDataMode();
  
  return (
    <header className="sticky top-0 z-30 flex items-center justify-between rounded-xl border border-gray-800 bg-white px-6 py-3 shadow-md">

      {/* Left — branding */}
      <div className="flex items-center gap-3">
        <img src="/trace.svg" alt="trace" className="-ml-2 h-10 w-10" />
        <h1 className="text-xl font-bold tracking-wide text-gray-800">
          SOCrates
        </h1>
      </div>

      {/* Right — mock toggle + connection indicator */}
      <div className="flex items-center gap-4">
        <button
          onClick={toggleMock}
          className="flex items-center gap-1.5 rounded-lg border px-3 py-1 text-sm font-medium transition hover:bg-gray-50"
          title={useMock ? "Switch to live API" : "Switch to mock data"}
        >
          {useMock ? (
            <ToggleRight className="h-5 w-5 text-amber-600" />
          ) : (
            <ToggleLeft className="h-5 w-5 text-gray-400" />
          )}
          <span className={useMock ? "text-amber-700" : "text-gray-500"}>
            {useMock ? "Mock" : "Live"}
          </span>
        </button>

        <div className="flex items-center gap-2 rounded-lg border border-green-600 bg-green-50 px-3 py-1">
          <Wifi className="h-5 w-5 text-green-600" />
          <span className="text-sm font-semibold text-green-700">Operational</span>
        </div>
      </div>
    </header>
  );
}
