# MTI plugin for Claude Code

This plugin connects Claude Code to MTI (Motiontic Threat Index), a read-only database of known vulnerabilities, malicious packages, exploitation signals, breaches and AI incidents.

It adds:

- The MTI MCP server at https://mti.motiontic.com/mcp. Sign in when Claude Code asks.
- Two skills: `/mti:are-we-affected` reads the lockfiles in a project you name and reports what to fix first, and `/mti:safe-install` checks a package version before you add it.

## What is sent

Only ecosystem, package name and version leave your machine. No source code, file contents, secrets or personal data are sent. The skills read lockfiles in the project you name, and nothing else.

## Do you need it?

Clients that support skills over MCP (Claude Code 2.1.331 or later) get the same two skills from the MTI MCP server with no extra step. The plugin is for clients that do not support that yet.

More at https://mti.motiontic.com/docs/mcp
