import { useState, useEffect } from "react";
import { X } from "lucide-react";

interface SettingsModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export default function SettingsModal({ isOpen, onClose }: SettingsModalProps) {
  const [backendUrl, setBackendUrl] = useState("");

  useEffect(() => {
    if (isOpen) {
      const stored = localStorage.getItem("socrates_backend_url");
      if (stored) {
        setBackendUrl(stored);
      } else {
        setBackendUrl("");
      }
    }
  }, [isOpen]);

  if (!isOpen) return null;

  const handleSave = () => {
    if (backendUrl.trim() === "") {
      localStorage.removeItem("socrates_backend_url");
    } else {
      // Basic cleanup of trailing slashes
      const cleanedUrl = backendUrl.trim().replace(/\/+$/, "");
      localStorage.setItem("socrates_backend_url", cleanedUrl);
    }
    onClose();
    // Optional: reload to ensure all data is fetched from the new URL
    window.location.reload();
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
      <div className="w-full max-w-md rounded-xl bg-white p-6 shadow-xl relative">
        <button
          onClick={onClose}
          className="absolute right-4 top-4 text-gray-400 hover:text-gray-600"
        >
          <X className="h-5 w-5" />
        </button>

        <h2 className="mb-4 text-xl font-unica font-bold text-gray-700">SETTINGS</h2>

        <div className="mb-6">
          <label className="mb-2 block text-sm font-medium text-gray-700">
            Backend API URL
          </label>
          <input
            type="text"
            value={backendUrl}
            onChange={(e) => setBackendUrl(e.target.value)}
            placeholder="e.g. http://192.168.1.50:5000"
            className="w-full rounded-lg border border-gray-300 p-2 text-sm focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
          />
          <p className="mt-2 text-xs text-gray-500">
            Leave blank to use the default relative path ("/api"). Note: Saving will reload the page.
          </p>
        </div>

        <div className="flex justify-end gap-3">
          <button
            onClick={onClose}
            className="rounded-lg px-4 py-2 text-sm font-medium text-gray-600 hover:bg-gray-200"
          >
            Cancel
          </button>
          <button
            onClick={handleSave}
            className="rounded-lg bg-[#5271ff] px-4 py-2 text-sm font-medium text-white hover:bg-blue-700"
          >
            Save Options
          </button>
        </div>
      </div>
    </div>
  );
}
