import type { ICredentialType, INodeProperties } from "n8n-workflow";

export class AgentGuardApi implements ICredentialType {
  name = "agentShieldApi";
  displayName = "AgentGuard API";
  documentationUrl = "https://github.com/hidearmoon/agentguard";

  properties: INodeProperties[] = [
    {
      displayName: "API Key",
      name: "apiKey",
      type: "string",
      typeOptions: { password: true },
      default: "",
      required: true,
    },
    {
      displayName: "Core Engine URL",
      name: "baseUrl",
      type: "string",
      default: "http://localhost:8000",
    },
  ];
}
