import { useLocation } from "react-router-dom";

const TITLES: Record<string, string> = {
  "/dashboard": "Dashboard",
  "/traces": "Trace Explorer",
  "/policies": "Policy Management",
  "/alerts": "Alert Center",
  "/agents": "Agent Registry",
  "/sources": "Data Sources",
  "/settings": "Settings",
};

export function Header() {
  const { pathname } = useLocation();
  const basePath = "/" + pathname.split("/").filter(Boolean)[0];
  const title = TITLES[basePath] || "AgentShield";

  return (
    <header className="flex h-16 items-center justify-between border-b border-gray-800/50 bg-surface/80 backdrop-blur-sm px-6">
      <h1 className="text-lg font-semibold text-gray-100">{title}</h1>
      <div className="flex items-center gap-4">
        <div className="relative">
          <input
            type="text"
            placeholder="Search..."
            className="input w-64 pl-9 text-xs"
          />
          <svg
            className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500"
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
            strokeWidth={1.5}
          >
            <path strokeLinecap="round" strokeLinejoin="round" d="m21 21-5.197-5.197m0 0A7.5 7.5 0 1 0 5.196 5.196a7.5 7.5 0 0 0 10.607 10.607Z" />
          </svg>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="h-2 w-2 rounded-full bg-status-success" />
          <span className="text-xs text-gray-400">System OK</span>
        </div>
      </div>
    </header>
  );
}
