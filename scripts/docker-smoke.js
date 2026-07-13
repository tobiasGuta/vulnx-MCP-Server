import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const image = process.env.VULNX_MCP_IMAGE || "vulnx-mcp";
const transport = new StdioClientTransport({
  command: "docker",
  args: [
    "run",
    "--rm",
    "-i",
    "--read-only",
    "--cap-drop=ALL",
    "--security-opt=no-new-privileges",
    "--tmpfs",
    "/tmp:rw,noexec,nosuid,size=64m",
    image,
  ],
  stderr: "inherit",
});
const client = new Client({ name: "vulnx-docker-smoke", version: "1.0.0" });

try {
  // connect performs the MCP initialize exchange and initialized notification.
  await client.connect(transport);
  const { tools } = await client.listTools();
  const names = tools.map((tool) => tool.name);
  const expectedNames = [
    "vulnx_search",
    "vulnx_cve",
    "vulnx_filters",
    "vulnx_batch_cve",
    "vulnx_prioritize",
    "vulnx_product_exposure",
    "vulnx_compare",
    "vulnx_enrich_findings",
    "vulnx_status",
  ];
  if (JSON.stringify(names) !== JSON.stringify(expectedNames)) {
    throw new Error(`Unexpected tool list: ${names.join(", ")}`);
  }
  const status = await client.callTool({ name: "vulnx_status", arguments: {} });
  if (status.isError || status.structuredContent?.server?.version !== "1.1.0") {
    throw new Error("vulnx_status did not return the expected server metadata");
  }
  const filters = await client.callTool({ name: "vulnx_filters", arguments: {} });
  if (filters.isError) {
    const message = filters.content?.[0]?.text || "Unknown vulnx_filters failure";
    throw new Error(message);
  }
  process.stdout.write(
    `MCP handshake, status, and filter calls succeeded. Tools: ${names.join(", ")}\n`,
  );
} finally {
  await client.close();
}
