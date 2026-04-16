import { clsx } from "clsx";

const PRESETS = [
  { label: "1h", hours: 1 },
  { label: "6h", hours: 6 },
  { label: "24h", hours: 24 },
  { label: "7d", hours: 168 },
  { label: "30d", hours: 720 },
];

interface TimeRangePickerProps {
  value: number;
  onChange: (hours: number) => void;
}

export function TimeRangePicker({ value, onChange }: TimeRangePickerProps) {
  return (
    <div className="inline-flex items-center gap-1 rounded-lg bg-surface-raised p-1">
      {PRESETS.map((preset) => (
        <button
          key={preset.hours}
          onClick={() => onChange(preset.hours)}
          className={clsx(
            "rounded-md px-3 py-1.5 text-xs font-medium transition-colors",
            value === preset.hours
              ? "bg-accent text-white"
              : "text-gray-400 hover:text-gray-200 hover:bg-surface-overlay"
          )}
        >
          {preset.label}
        </button>
      ))}
    </div>
  );
}
