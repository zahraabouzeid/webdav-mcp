# WebDAV MCP Server

A Model Context Protocol server that provides read-only access to files on WebDAV
services such as Nextcloud, ownCloud and Sciebo. This server enables LLMs to list
and read files, including PDF and Office documents.

## Available Tools

- `list_files` - Lists the files and folders in one folder.
- `read_file` - Reads a file as text or as page images.

## Usage

Add the server as a custom connector in an MCP client:

`https://webdav.mcp.zahraabouzeid.me/mcp`

The sign-in page asks for the server address, the username and an app password.

## Security

This server stores the login encrypted on the server. A connection unused for 90
days is deleted. Only connect an account if you trust the operator of this server.

## License

This project is licensed under the [AGPL-3.0](LICENSE).
