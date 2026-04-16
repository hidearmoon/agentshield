import { clsx } from "clsx";

interface IntentDriftBadgeProps {
  score: number;
}

export function IntentDriftBadge({ score }: IntentDriftBadgeProps) {
  const level =
    score >= 0.7 ? "high" : score >= 0.4 ? "medium" : "low";

  return (
    <span
      className={clsx(
        "badge font-mono",
        level === "high" && "badge-danger",
        level === "medium" && "badge-warning",
        level === "low" && "badge-success"
      )}
    >
      {score.toFixed(3)}
    </span>
  );
}
