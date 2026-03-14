import { Wifi, ToggleLeft, ToggleRight } from "lucide-react";
import { useDataMode } from "@/hooks/useDataMode";

export default function Header() {
  const { useMock, toggleMock } = useDataMode();

  return (
    <header className="flex items-center justify-between px-6 h-20 bg-gray-100 w-full shrink-0">
      {/* Left — branding */}
      <div className="flex items-center gap-3">
        <h1 className="font-unica text-4xl font-semibold text-blue-600 tracking-wide mt-1 flex items-center gap-6">
          <img className="-ml-[6px] h-12 w-12" src="./icon.svg" alt="SOCrates Logo" />
          <span>SOC<span className="text-black">RATES</span></span>
        </h1>
      </div>

      {/* mock toggle + connection indicator */}
      <div className="flex items-center gap-4 py-1">
        <button
          onClick={toggleMock}
          className="flex items-center w-24 gap-1.5 rounded-full border-2 border-gray-700 bg-gray-500 px-3 py-1 text-sm font-medium text-white transition"
        >
          {useMock ? (
            <ToggleRight className="h-5 w-5" />
          ) : (
            <ToggleLeft className="h-5 w-5" />
          )}
          <span className="px-1">
            {useMock ? "Mock" : "Live"}
          </span>
        </button>

        <div className="flex items-center gap-2 rounded-full text-green-700 bg-green-200 border-2 border-green-700 px-3 py-1">
          <Wifi className="h-5 w-5" />
          <span className="text-sm font-semibold">Operational</span>
        </div>
      </div>
    </header>
  );
}
