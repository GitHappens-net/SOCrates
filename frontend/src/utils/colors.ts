const VENDOR_PALETTE = [
  "#2563eb", // blue-600
  "#dc2626", // red-600
  "#16a34a", // green-600
  "#d97706", // amber-600
  "#7c3aed", // violet-600
  "#06b6d4", // cyan-500
  "#64748b", // slate-500
  "#db2777", // pink-600
  "#0d9488", // teal-600
  "#4f46e5", // indigo-600
  "#84cc16", // lime-500
  "#c026d3", // fuchsia-600
  "#e11d48", // rose-600
  "#0284c7", // sky-600
  "#059669", // emerald-600
  "#9333ea", // purple-600
  "#eab308", // yellow-500
  "#ea580c", // orange-600
  "#78716c", // stone-500
  "#52525b", // zinc-600
];

// Helper to reliably generate the exact same color for a specific vendor
export function getVendorColor(vendorName: string) {
  if (!vendorName) return "#6b7280"; // fallback for empty strings

  let hash = 0;
  for (let i = 0; i < vendorName.length; i++) {
    hash = vendorName.charCodeAt(i) + ((hash << 5) - hash);
  }
  return VENDOR_PALETTE[Math.abs(hash) % VENDOR_PALETTE.length];
}
