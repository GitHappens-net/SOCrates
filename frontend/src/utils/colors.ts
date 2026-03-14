const VENDOR_PALETTE = [
  "#2563eb", // blue
  "#dc2626", // red
  "#16a34a", // green
  "#d97706", // orange
  "#7c3aed", // purple
  "#06b6d4", // cyan
  "#64748b", // slate
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
