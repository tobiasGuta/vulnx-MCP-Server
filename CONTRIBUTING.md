# Contributing

Thank you for helping improve vulnx MCP Server.

## Development workflow

1. Create a focused branch from the current default branch.
2. Install the locked dependencies with `npm ci`.
3. Make the smallest change that solves the issue.
4. Add or update tests and run `npm test`.
5. For container changes, run `docker build -t vulnx-mcp .` and `npm run smoke:docker`.
6. Open a pull request describing the behavior change, security impact, and verification performed.

Never commit API keys, vulnerability data from private environments, or sensitive target details. Report suspected vulnerabilities privately when the repository hosting platform provides a private security-reporting channel.

Dependency and upstream vulnx updates should remain pinned. Include the reviewed version or commit, upstream release notes, and test results in the pull request.
