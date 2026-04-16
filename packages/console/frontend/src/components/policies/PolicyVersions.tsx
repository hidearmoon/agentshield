import { clsx } from "clsx";
import type { Policy } from "@/api/policies";

interface PolicyVersionsProps {
  versions: Policy[];
  selectedId: string | null;
  onSelect: (policy: Policy) => void;
}

export function PolicyVersions({
  versions,
  selectedId,
  onSelect,
}: PolicyVersionsProps) {
  if (versions.length === 0) {
    return (
      <div className="text-sm text-gray-500 py-4">No version history</div>
    );
  }

  return (
    <div className="space-y-1">
      {versions.map((v) => (
        <button
          key={v.id}
          onClick={() => onSelect(v)}
          className={clsx(
            "w-full flex items-center gap-3 rounded-lg px-3 py-2 text-left transition-colors",
            selectedId === v.id
              ? "bg-surface-overlay border border-accent/30"
              : "hover:bg-surface-raised"
          )}
        >
          <span className="text-xs font-mono text-gray-400">v{v.version}</span>
          <span className="flex-1 text-sm text-gray-200">
            {v.name}
          </span>
          {v.is_active && (
            <span className="badge badge-success">active</span>
          )}
          <span className="text-xs text-gray-500">
            {v.created_at
              ? new Date(v.created_at).toLocaleDateString()
              : "-"}
          </span>
        </button>
      ))}
    </div>
  );
}
