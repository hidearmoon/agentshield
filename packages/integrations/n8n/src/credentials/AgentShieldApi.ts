import type { ICredentialType, INodeProperties } from "n8n-workflow";

export class AgentShieldApi implements ICredentialType {
  name = "agentShieldApi";
  displayName = "AgentShield API";
  documentationUrl = "https://github.com/hidearmoon/agentshield";

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
