import { useState } from "react";
import { clsx } from "clsx";
import { useRules, useCreateRule, useDeleteRule, useToggleRule, useValidateRule } from "@/hooks/useRules";
import { RuleDSLReference } from "@/components/policies/RuleDSLReference";
import type { RuleDefinition } from "@/api/rules";

const EMPTY_RULE_YAML = `name: my_custom_rule
description: "Describe what this rule does"
when:
  tool: send_email
  trust_level:
    - EXTERNAL
    - UNTRUSTED
  params:
    to:
      matches: ".*@example\\\\.com$"
action: BLOCK
reason: "Custom rule triggered"`;

export default function RulesPage() {
  const [yamlInput, setYamlInput] = useState(EMPTY_RULE_YAML);
  const [validationResult, setValidationResult] = useState<{ valid: boolean; error?: string } | null>(null);
  const [showReference, setShowReference] = useState(true);
  const [filter, setFilter] = useState<"all" | "builtin" | "custom">("all");

  const { data, isLoading } = useRules();
  const createMut = useCreateRule();
  const deleteMut = useDeleteRule();
  const toggleMut = useToggleRule();
  const validateMut = useValidateRule();

  const rules = data?.rules ?? [];
  const filtered = filter === "all" ? rules : rules.filter(r => r.type === filter);

  function parseYamlToRule(): RuleDefinition | null {
    try {
      // Simple YAML-like parser for the rule definition
      // In production, use a proper YAML library (js-yaml)
      const lines = yamlInput.split("\n");
      const rule: Record<string, unknown> = {};
      let currentKey = "";
      let whenBlock: Record<string, unknown> = {};
      let inWhen = false;
      let inParams = false;
      let inTrustLevel = false;
      let paramName = "";
      let trustLevels: string[] = [];

      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith("#")) continue;

        const indent = line.length - line.trimStart().length;

        if (indent === 0 && trimmed.includes(":")) {
          const [key, ...rest] = trimmed.split(":");
          const value = rest.join(":").trim().replace(/^["']|["']$/g, "");
          inWhen = key.trim() === "when";
          inParams = false;
          inTrustLevel = false;
          if (!inWhen && value) {
            rule[key.trim()] = value === "true" ? true : value === "false" ? false : value;
          }
        } else if (inWhen && indent >= 2) {
          if (trimmed.startsWith("- ") && inTrustLevel) {
            trustLevels.push(trimmed.replace("- ", "").trim().replace(/^["']|["']$/g, ""));
            whenBlock["trust_level"] = trustLevels;
          } else if (trimmed === "trust_level:") {
            inTrustLevel = true;
            inParams = false;
            trustLevels = [];
          } else if (trimmed === "params:") {
            inParams = true;
            inTrustLevel = false;
            whenBlock["params"] = whenBlock["params"] || {};
          } else if (inParams && indent === 4 && trimmed.includes(":") && !trimmed.includes(": ")) {
            paramName = trimmed.replace(":", "").trim();
            (whenBlock["params"] as Record<string, unknown>)[paramName] = {};
          } else if (inParams && indent >= 6 && trimmed.includes(":")) {
            const [k, ...v] = trimmed.split(":");
            const val = v.join(":").trim().replace(/^["']|["']$/g, "");
            ((whenBlock["params"] as Record<string, Record<string, string>>)[paramName])[k.trim()] = val;
          } else if (trimmed.includes(":")) {
            const [k, ...v] = trimmed.split(":");
            const val = v.join(":").trim().replace(/^["']|["']$/g, "");
            inTrustLevel = false;
            whenBlock[k.trim()] = val;
          }
        }
      }

      return {
        name: (rule.name as string) || "",
        description: (rule.description as string) || "",
        enabled: rule.enabled !== false,
        when: whenBlock,
        action: (rule.action as string) || "BLOCK",
        reason: (rule.reason as string) || "",
      };
    } catch {
      return null;
    }
  }

  async function handleValidate() {
    const rule = parseYamlToRule();
    if (!rule || !rule.name) {
      setValidationResult({ valid: false, error: "Could not parse rule. Check YAML syntax." });
      return;
    }
    const result = await validateMut.mutateAsync(rule);
    setValidationResult(result);
  }

  async function handleCreate() {
    const rule = parseYamlToRule();
    if (!rule || !rule.name) {
      setValidationResult({ valid: false, error: "Could not parse rule." });
      return;
    }
    try {
      await createMut.mutateAsync(rule);
      setValidationResult(null);
      setYamlInput(EMPTY_RULE_YAML);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : "Failed to create rule";
      setValidationResult({ valid: false, error: message });
    }
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-semibold text-gray-100">Detection Rules</h2>
          <p className="text-sm text-gray-500 mt-0.5">
            {rules.length} rules ({rules.filter(r => r.type === "builtin").length} built-in, {rules.filter(r => r.type === "custom").length} custom)
          </p>
        </div>
        <button
          onClick={() => setShowReference(!showReference)}
          className={clsx("btn-secondary text-sm", showReference && "ring-1 ring-accent/30")}
        >
          {showReference ? "Hide" : "Show"} DSL Reference
        </button>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
        {/* Left: YAML Editor + Rule List */}
        <div className="space-y-6">
          {/* YAML Editor */}
          <div className="card">
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-sm font-semibold text-gray-200">Create Custom Rule</h3>
              <div className="flex gap-2">
                <button
                  onClick={handleValidate}
                  disabled={validateMut.isPending}
                  className="btn-secondary text-xs"
                >
                  {validateMut.isPending ? "Validating..." : "Validate"}
                </button>
                <button
                  onClick={handleCreate}
                  disabled={createMut.isPending}
                  className="btn-primary text-xs"
                >
                  {createMut.isPending ? "Creating..." : "Create Rule"}
                </button>
              </div>
            </div>

            <textarea
              value={yamlInput}
              onChange={e => setYamlInput(e.target.value)}
              className="w-full h-72 bg-[#0d1117] text-gray-300 text-xs font-mono leading-relaxed p-4 rounded-lg border border-gray-800/50 focus:border-accent/50 focus:outline-none resize-y"
              spellCheck={false}
              placeholder="Write your rule in YAML..."
            />

            {/* Validation result */}
            {validationResult && (
              <div className={clsx(
                "mt-3 px-3 py-2 rounded-lg text-xs",
                validationResult.valid
                  ? "bg-green-500/10 text-green-400 border border-green-500/20"
                  : "bg-red-500/10 text-red-400 border border-red-500/20"
              )}>
                {validationResult.valid
                  ? "Rule syntax is valid"
                  : `Error: ${validationResult.error}`}
              </div>
            )}
          </div>

          {/* Rule List */}
          <div className="card">
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-sm font-semibold text-gray-200">Active Rules</h3>
              <div className="flex gap-1">
                {(["all", "builtin", "custom"] as const).map(f => (
                  <button
                    key={f}
                    onClick={() => setFilter(f)}
                    className={clsx(
                      "px-2.5 py-1 rounded text-xs font-medium transition-colors",
                      filter === f
                        ? "bg-accent/20 text-accent"
                        : "text-gray-500 hover:text-gray-300"
                    )}
                  >
                    {f}
                  </button>
                ))}
              </div>
            </div>

            {isLoading ? (
              <div className="space-y-2">
                {Array.from({ length: 5 }).map((_, i) => (
                  <div key={i} className="h-12 rounded-lg bg-surface-overlay animate-pulse" />
                ))}
              </div>
            ) : filtered.length === 0 ? (
              <div className="text-center py-8 text-sm text-gray-500">
                No {filter !== "all" ? filter : ""} rules found
              </div>
            ) : (
              <div className="space-y-1">
                {filtered.map(rule => (
                  <div
                    key={rule.name}
                    className="flex items-center gap-3 px-3 py-2.5 rounded-lg hover:bg-surface-overlay transition-colors group"
                  >
                    {/* Enable/disable toggle */}
                    <button
                      onClick={() => toggleMut.mutate({ name: rule.name, enabled: !rule.enabled })}
                      className={clsx(
                        "h-2.5 w-2.5 rounded-full shrink-0 transition-colors",
                        rule.enabled ? "bg-status-success" : "bg-gray-600"
                      )}
                      title={rule.enabled ? "Click to disable" : "Click to enable"}
                    />

                    {/* Rule info */}
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="text-sm text-gray-200 font-medium truncate">
                          {rule.name}
                        </span>
                        <span className={clsx(
                          "badge text-[10px]",
                          rule.type === "builtin" ? "badge-neutral" : "badge-info"
                        )}>
                          {rule.type}
                        </span>
                      </div>
                      {rule.description && (
                        <p className="text-xs text-gray-500 truncate mt-0.5">
                          {rule.description}
                        </p>
                      )}
                    </div>

                    {/* Delete (custom only) */}
                    {rule.type === "custom" && (
                      <button
                        onClick={() => deleteMut.mutate(rule.name)}
                        className="opacity-0 group-hover:opacity-100 text-gray-500 hover:text-red-400 transition-all"
                        title="Delete rule"
                      >
                        <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                          <path strokeLinecap="round" strokeLinejoin="round" d="m14.74 9-.346 9m-4.788 0L9.26 9m9.968-3.21c.342.052.682.107 1.022.166m-1.022-.165L18.16 19.673a2.25 2.25 0 0 1-2.244 2.077H8.084a2.25 2.25 0 0 1-2.244-2.077L4.772 5.79m14.456 0a48.108 48.108 0 0 0-3.478-.397m-12 .562c.34-.059.68-.114 1.022-.165m0 0a48.11 48.11 0 0 1 3.478-.397m7.5 0v-.916c0-1.18-.91-2.164-2.09-2.201a51.964 51.964 0 0 0-3.32 0c-1.18.037-2.09 1.022-2.09 2.201v.916m7.5 0a48.667 48.667 0 0 0-7.5 0" />
                        </svg>
                      </button>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Right: DSL Reference */}
        {showReference && (
          <div className="xl:sticky xl:top-6 xl:self-start">
            <RuleDSLReference />
          </div>
        )}
      </div>
    </div>
  );
}
