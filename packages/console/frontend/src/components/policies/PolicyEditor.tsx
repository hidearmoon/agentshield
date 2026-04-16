import { useState } from "react";
import { clsx } from "clsx";
import type { PolicyRule } from "@/api/policies";

interface PolicyEditorProps {
  rules: PolicyRule[];
  onChange: (rules: PolicyRule[]) => void;
  readOnly?: boolean;
}

const ACTIONS = ["ALLOW", "REQUIRE_CONFIRMATION", "BLOCK"];
const OPERATORS = ["equals", "contains", "gt", "lt", "in", "regex"];

function emptyRule(): PolicyRule {
  return {
    rule_name: "",
    rule_type: "custom",
    condition: { field: "", operator: "equals", value: "" },
    action: "BLOCK",
    priority: 0,
    enabled: true,
  };
}

export function PolicyEditor({ rules, onChange, readOnly = false }: PolicyEditorProps) {
  const [expandedIdx, setExpandedIdx] = useState<number | null>(null);

  function updateRule(idx: number, patch: Partial<PolicyRule>) {
    const updated = [...rules];
    updated[idx] = { ...updated[idx], ...patch };
    onChange(updated);
  }

  function updateCondition(idx: number, key: string, value: string) {
    const updated = [...rules];
    updated[idx] = {
      ...updated[idx],
      condition: { ...updated[idx].condition, [key]: value },
    };
    onChange(updated);
  }

  function addRule() {
    onChange([...rules, emptyRule()]);
    setExpandedIdx(rules.length);
  }

  function removeRule(idx: number) {
    onChange(rules.filter((_, i) => i !== idx));
    setExpandedIdx(null);
  }

  function moveRule(idx: number, dir: -1 | 1) {
    const target = idx + dir;
    if (target < 0 || target >= rules.length) return;
    const updated = [...rules];
    [updated[idx], updated[target]] = [updated[target], updated[idx]];
    onChange(updated);
    setExpandedIdx(target);
  }

  return (
    <div className="space-y-2">
      {rules.map((rule, idx) => {
        const isExpanded = expandedIdx === idx;
        const cond = rule.condition as Record<string, string>;
        const actionColor =
          rule.action === "BLOCK"
            ? "badge-danger"
            : rule.action === "ALLOW"
              ? "badge-success"
              : "badge-warning";

        return (
          <div
            key={idx}
            className="rounded-lg border border-gray-800/50 bg-surface-raised overflow-hidden"
          >
            {/* Header row */}
            <div
              className="flex items-center gap-3 px-4 py-3 cursor-pointer"
              onClick={() => setExpandedIdx(isExpanded ? null : idx)}
            >
              <svg
                className={clsx(
                  "w-4 h-4 text-gray-500 transition-transform",
                  isExpanded && "rotate-90"
                )}
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
                strokeWidth={2}
              >
                <path strokeLinecap="round" strokeLinejoin="round" d="m8.25 4.5 7.5 7.5-7.5 7.5" />
              </svg>
              <span className="text-sm font-medium text-gray-200 flex-1">
                {rule.rule_name || "(unnamed rule)"}
              </span>
              <span className={`badge ${actionColor}`}>{rule.action}</span>
              <span
                className={clsx(
                  "h-2 w-2 rounded-full",
                  rule.enabled ? "bg-status-success" : "bg-gray-600"
                )}
              />
            </div>

            {/* Expanded editor */}
            {isExpanded && (
              <div className="border-t border-gray-800/30 px-4 py-4 space-y-4">
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="text-xs text-gray-500 uppercase mb-1 block">
                      Rule Name
                    </label>
                    <input
                      className="input"
                      value={rule.rule_name}
                      onChange={(e) =>
                        updateRule(idx, { rule_name: e.target.value })
                      }
                      disabled={readOnly}
                    />
                  </div>
                  <div>
                    <label className="text-xs text-gray-500 uppercase mb-1 block">
                      Action
                    </label>
                    <select
                      className="input"
                      value={rule.action}
                      onChange={(e) =>
                        updateRule(idx, { action: e.target.value })
                      }
                      disabled={readOnly}
                    >
                      {ACTIONS.map((a) => (
                        <option key={a} value={a}>
                          {a}
                        </option>
                      ))}
                    </select>
                  </div>
                </div>

                <div>
                  <label className="text-xs text-gray-500 uppercase mb-2 block">
                    Condition
                  </label>
                  <div className="grid grid-cols-3 gap-3">
                    <input
                      className="input"
                      placeholder="Field"
                      value={cond.field || ""}
                      onChange={(e) =>
                        updateCondition(idx, "field", e.target.value)
                      }
                      disabled={readOnly}
                    />
                    <select
                      className="input"
                      value={cond.operator || "equals"}
                      onChange={(e) =>
                        updateCondition(idx, "operator", e.target.value)
                      }
                      disabled={readOnly}
                    >
                      {OPERATORS.map((op) => (
                        <option key={op} value={op}>
                          {op}
                        </option>
                      ))}
                    </select>
                    <input
                      className="input"
                      placeholder="Value"
                      value={cond.value || ""}
                      onChange={(e) =>
                        updateCondition(idx, "value", e.target.value)
                      }
                      disabled={readOnly}
                    />
                  </div>
                </div>

                <div className="grid grid-cols-3 gap-4">
                  <div>
                    <label className="text-xs text-gray-500 uppercase mb-1 block">
                      Priority
                    </label>
                    <input
                      type="number"
                      className="input"
                      value={rule.priority}
                      onChange={(e) =>
                        updateRule(idx, {
                          priority: parseInt(e.target.value) || 0,
                        })
                      }
                      disabled={readOnly}
                    />
                  </div>
                  <div>
                    <label className="text-xs text-gray-500 uppercase mb-1 block">
                      Type
                    </label>
                    <select
                      className="input"
                      value={rule.rule_type}
                      onChange={(e) =>
                        updateRule(idx, { rule_type: e.target.value })
                      }
                      disabled={readOnly}
                    >
                      <option value="custom">custom</option>
                      <option value="builtin">builtin</option>
                    </select>
                  </div>
                  <div className="flex items-end gap-2">
                    <label className="flex items-center gap-2 text-sm text-gray-300 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={rule.enabled}
                        onChange={(e) =>
                          updateRule(idx, { enabled: e.target.checked })
                        }
                        disabled={readOnly}
                        className="rounded border-gray-600"
                      />
                      Enabled
                    </label>
                  </div>
                </div>

                {!readOnly && (
                  <div className="flex gap-2 pt-2">
                    <button
                      onClick={() => moveRule(idx, -1)}
                      disabled={idx === 0}
                      className="btn-ghost text-xs"
                    >
                      Move Up
                    </button>
                    <button
                      onClick={() => moveRule(idx, 1)}
                      disabled={idx === rules.length - 1}
                      className="btn-ghost text-xs"
                    >
                      Move Down
                    </button>
                    <div className="flex-1" />
                    <button
                      onClick={() => removeRule(idx)}
                      className="btn-danger text-xs"
                    >
                      Remove
                    </button>
                  </div>
                )}
              </div>
            )}
          </div>
        );
      })}

      {!readOnly && (
        <button onClick={addRule} className="btn-secondary w-full">
          + Add Rule
        </button>
      )}
    </div>
  );
}
