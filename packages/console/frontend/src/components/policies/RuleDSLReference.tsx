import { useState } from "react";
import { clsx } from "clsx";

const SECTIONS = [
  {
    title: "Basic Structure",
    content: `rules:
  - name: rule_unique_name        # Required, unique identifier
    description: "Human readable"  # Optional
    enabled: true                  # Default: true
    when:                          # Conditions (AND logic)
      tool: send_email             # Tool name match
      trust_level: ["EXTERNAL"]    # Trust level filter
      params:                      # Parameter matchers
        to:
          matches: ".*@evil\\.com$"
    action: BLOCK                  # BLOCK | REQUIRE_CONFIRMATION | ALLOW
    reason: "Blocked because..."   # User-facing reason`,
  },
  {
    title: "Tool Matching",
    content: `# Match single tool
when:
  tool: send_email

# Match multiple tools
when:
  tool: [send_email, send_sms, post_message]

# Match by category
when:
  tool_category: send
  # or multiple categories
  tool_category: [send, write, delete]`,
  },
  {
    title: "Trust Level Filter",
    content: `# Rule only fires at specific trust levels
when:
  trust_level: ["EXTERNAL", "UNTRUSTED"]

# Available levels (high to low):
#   TRUSTED    - System instructions
#   VERIFIED   - Authenticated user input
#   INTERNAL   - Inter-agent data
#   EXTERNAL   - Email, web, RAG, files
#   UNTRUSTED  - Unknown/high-risk sources`,
  },
  {
    title: "Parameter Matchers",
    content: `when:
  params:
    # Exact match
    status:
      equals: "admin"

    # Regex match
    to:
      matches: ".*@(competitor1|competitor2)\\.com$"

    # Substring match
    query:
      contains: "DROP TABLE"

    # Numeric comparisons
    limit:
      gt: 100      # greater than
      gte: 100     # greater than or equal
      lt: 10       # less than
      lte: 10      # less than or equal

    # Value in list
    region:
      in: ["us-east-1", "eu-west-1"]

    # Value NOT in list
    env:
      not_in: ["production", "staging"]

    # Not equals
    mode:
      not_equals: "debug"

    # String prefix/suffix
    filename:
      starts_with: "tmp_"
      ends_with: ".csv"`,
  },
  {
    title: "Extra Conditions",
    content: `when:
  conditions:
    # Time range - block outside business hours
    - type: time_range
      outside: "09:00-18:00"

    # Time range - only during window
    - type: time_range
      within: "09:00-18:00"

    # Intent pattern match
    - type: intent_match
      pattern: "delete|remove|destroy"

    # Intent NOT matching
    - type: intent_not_match
      pattern: "export|download"

    # Call history count
    - type: history_count
      op: gte        # gt | gte | lt | lte | eq
      value: 10`,
  },
  {
    title: "Full Examples",
    content: `rules:
  # Block emails to competitors
  - name: block_competitor_emails
    description: "Prevent data leaks to competitors"
    when:
      tool: send_email
      trust_level: ["EXTERNAL", "UNTRUSTED"]
      params:
        to:
          matches: ".*@(acme|globex)\\.com$"
    action: BLOCK
    reason: "Sending to competitor domain is prohibited"

  # Require confirmation for large exports
  - name: confirm_large_export
    when:
      tool: [export_data, bulk_export, export_csv]
      params:
        limit:
          gt: 50
    action: REQUIRE_CONFIRMATION
    reason: "Exporting >50 records requires approval"

  # Block deploys to non-approved regions
  - name: restrict_deploy_regions
    when:
      tool: deploy
      params:
        region:
          not_in: ["us-east-1", "eu-west-1"]
    action: BLOCK
    reason: "Deploy only allowed in approved regions"

  # Block sensitive actions after hours
  - name: after_hours_block
    when:
      tool_category: [send, write, delete]
      trust_level: ["EXTERNAL"]
      conditions:
        - type: time_range
          outside: "09:00-18:00"
    action: BLOCK
    reason: "Sensitive actions blocked outside 9am-6pm UTC"`,
  },
];

export function RuleDSLReference() {
  const [activeSection, setActiveSection] = useState(0);

  return (
    <div className="rounded-lg border border-gray-800/50 bg-surface-raised overflow-hidden">
      <div className="border-b border-gray-800/30 px-4 py-3">
        <h3 className="text-sm font-semibold text-gray-200">
          Rule DSL Reference
        </h3>
        <p className="text-xs text-gray-500 mt-0.5">
          YAML syntax for writing custom detection rules
        </p>
      </div>

      {/* Section tabs */}
      <div className="flex flex-wrap gap-1 px-4 pt-3">
        {SECTIONS.map((section, idx) => (
          <button
            key={idx}
            onClick={() => setActiveSection(idx)}
            className={clsx(
              "px-2.5 py-1 rounded text-xs font-medium transition-colors",
              activeSection === idx
                ? "bg-accent/20 text-accent"
                : "text-gray-500 hover:text-gray-300 hover:bg-surface-overlay"
            )}
          >
            {section.title}
          </button>
        ))}
      </div>

      {/* Content */}
      <div className="p-4">
        <pre className="text-xs leading-relaxed text-gray-300 bg-[#0d1117] rounded-lg p-4 overflow-x-auto border border-gray-800/30">
          <code>{SECTIONS[activeSection].content}</code>
        </pre>
      </div>

      {/* Quick tips */}
      <div className="border-t border-gray-800/30 px-4 py-3 space-y-1.5">
        <p className="text-[11px] text-gray-500">
          <span className="text-gray-400 font-medium">AND logic:</span>{" "}
          All conditions under <code className="text-accent/80">when:</code> must be true to trigger the rule.
        </p>
        <p className="text-[11px] text-gray-500">
          <span className="text-gray-400 font-medium">Actions:</span>{" "}
          <code className="text-red-400/80">BLOCK</code> stops execution,{" "}
          <code className="text-yellow-400/80">REQUIRE_CONFIRMATION</code> asks the user,{" "}
          <code className="text-green-400/80">ALLOW</code> explicitly permits.
        </p>
        <p className="text-[11px] text-gray-500">
          <span className="text-gray-400 font-medium">Validate:</span>{" "}
          Use the "Validate" button to check syntax before saving.
        </p>
      </div>
    </div>
  );
}
