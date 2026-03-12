import { Wifi } from "lucide-react";

export default function Header() {
  return (
    <header className="bg-white border border-gray-800 sticky top-0 z-30 flex items-center justify-between rounded-xl px-6 py-3 shadow-md">

      {/* Left — branding */}
      <div className="flex items-center gap-3">
        <img src="/trace.svg" alt="trace" className="-ml-2 h-10 w-10" />
        <h1 className="text-xl font-bold tracking-wide text-gray-800">
          SOCrates
        </h1>
      </div>

      {/* Right — connection indicator */}
      <div className="flex items-center gap-2 rounded-lg border border-green-600 bg-green-50 px-3 py-1">
        <Wifi className="h-5 w-5 text-green-600" />
        <span className="text-sm font-semibold text-green-700">Operational</span>
      </div>
    </header>
  );
}
