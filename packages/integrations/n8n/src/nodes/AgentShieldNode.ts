/**
 * AgentGuard Security Check node for n8n.
 *
 * Two usage patterns:
 *
 * 1. As a classifier node in AI Agent workflows:
 *    Place before or after the Agent node. Routes items to "Allowed" or "Blocked" output.
 *
 * 2. As a general security gate in any workflow:
 *    Check any action against AgentGuard policy before executing.
 *
 * Outputs:
 *   - Output 0 ("Allowed"): Items that passed the security check
 *   - Output 1 ("Blocked"): Items that were blocked, with reason attached
 */

import type {
  IExecuteFunctions,
  INodeExecutionData,
  INodeType,
  INodeTypeDescription,
} from "n8n-workflow";

export class AgentGuardNode implements INodeType {
  description: INodeTypeDescription = {
    displayName: "AgentGuard Security Check",
    name: "agentShield",
    icon: "file:agentguard.svg",
    group: ["transform"],
    version: 1,
    subtitle: "={{$parameter[\"toolName\"]}}",
    description: "Check AI agent tool calls against AgentGuard security policy",
    defaults: {
      name: "AgentGuard",
    },
    inputs: ["main"],
    outputs: ["main", "main"],
    outputNames: ["Allowed", "Blocked"],
    credentials: [
      {
        name: "agentShieldApi",
        required: true,
      },
    ],
    properties: [
      {
        displayName: "Tool Name",
        name: "toolName",
        type: "string",
        default: "",
        required: true,
        description: "Name of the tool/action being checked (e.g., \"send_email\", \"query_database\")",
      },
      {
        displayName: "Tool Parameters",
        name: "toolParams",
        type: "json",
        default: "{}",
        description: "JSON parameters being passed to the tool",
      },
      {
        displayName: "Source ID",
        name: "sourceId",
        type: "string",
        default: "n8n/workflow",
        description: "Data source identifier for trust level computation",
      },
      {
        displayName: "Agent ID",
        name: "agentId",
        type: "string",
        default: "n8n",
        description: "Agent identifier for trace grouping",
      },
      {
        displayName: "Fail Open",
        name: "failOpen",
        type: "boolean",
        default: true,
        description: "Whether to allow the action if AgentGuard is unreachable",
      },
    ],
  };

  async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
    const items = this.getInputData();
    const allowed: INodeExecutionData[] = [];
    const blocked: INodeExecutionData[] = [];

    const credentials = await this.getCredentials("agentShieldApi");
    const baseUrl = (credentials.baseUrl as string || "http://localhost:8000").replace(/\/+$/, "");
    const apiKey = credentials.apiKey as string;

    for (let i = 0; i < items.length; i++) {
      const toolName = this.getNodeParameter("toolName", i) as string;
      const toolParamsRaw = this.getNodeParameter("toolParams", i) as string;
      const sourceId = this.getNodeParameter("sourceId", i) as string;
      const failOpen = this.getNodeParameter("failOpen", i) as boolean;

      let toolParams: Record<string, unknown> = {};
      try {
        toolParams = JSON.parse(toolParamsRaw);
      } catch {
        toolParams = { raw: toolParamsRaw };
      }

      let result: { action: string; reason: string; trace_id: string };

      try {
        const response = await this.helpers.httpRequest({
          method: "POST",
          url: `${baseUrl}/api/v1/check`,
          headers: {
            Authorization: `Bearer ${apiKey}`,
            "Content-Type": "application/json",
            "User-Agent": "agentguard-n8n/0.1.0",
          },
          body: {
            session_id: `n8n-${this.getExecutionId()}`,
            tool_name: toolName,
            params: toolParams,
            source_id: sourceId,
          },
          json: true,
        });
        result = response as typeof result;
      } catch (error) {
        if (failOpen) {
          result = { action: "ALLOW", reason: "fail-open", trace_id: "" };
        } else {
          throw error;
        }
      }

      const enrichedItem: INodeExecutionData = {
        json: {
          ...items[i].json,
          _agentguard: {
            decision: result.action,
            reason: result.reason,
            trace_id: result.trace_id,
            tool_name: toolName,
          },
        },
        pairedItem: { item: i },
      };

      if (result.action === "ALLOW") {
        allowed.push(enrichedItem);
      } else {
        blocked.push(enrichedItem);
      }
    }

    return [allowed, blocked];
  }
}
