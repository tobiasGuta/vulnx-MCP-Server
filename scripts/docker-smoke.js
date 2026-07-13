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
  if (names.length !== 3) throw new Error(`Expected 3 tools, received ${names.length}`);
  const filters = await client.callTool({ name: "vulnx_filters", arguments: {} });
  if (filters.isError) {
    const message = filters.content?.[0]?.text || "Unknown vulnx_filters failure";
    throw new Error(message);
  }
  process.stdout.write(
    `MCP handshake and filter call succeeded. Tools: ${names.join(", ")}\n`,
  );
} finally {
  await client.close();
}
