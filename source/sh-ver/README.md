# Axe Language Server Protocol (LSP)

A Language Server Protocol implementation for the Axe programming language, written in Axe itself.

## Building

To build the LSP server:

```bash
cd tooling/axe-lsp
../../axe lsp_server.axe -o axe-lsp
```

On Windows, this will produce `axe-lsp.exe`. On Linux/macOS, it will produce `axe-lsp`.

## Usage

### With VS Code

The Axe extension for VS Code will automatically use the LSP server if it's in your PATH or configured.

1. Build the LSP server (see above)
2. Place `axe-lsp` (or `axe-lsp.exe`) in your PATH, or
3. Configure the path in VS Code settings:
   ```json
   {
     "axe.lsp.serverPath": "/path/to/axe-lsp"
   }
   ```

### Standalone

The LSP server communicates via stdio using the Language Server Protocol. You can test it manually:

```bash
echo 'Content-Length: 52\r\n\r\n{"jsonrpc":"2.0","id":1,"method":"initialize"}' | ./axe-lsp
```

## Supported LSP Methods

### Lifecycle
- `initialize` - Initialize the server with client capabilities
- `initialized` - Notification that initialization is complete
- `shutdown` - Prepare to shut down
- `exit` - Exit the server

### Text Synchronization
- `textDocument/didOpen` - Document opened
- `textDocument/didChange` - Document content changed
- `textDocument/didClose` - Document closed

### Language Features
- `textDocument/hover` - Hover information (stub)
- `textDocument/completion` - Code completion
- `textDocument/definition` - Go to definition (stub)
- `textDocument/diagnostic` - Diagnostics (stub)
- `textDocument/documentSymbol` - Document outline / symbols (now supported)

## Roadmap

- Full semantic analysis using parser.axe
- Type checking and inference
- Symbol resolution and renaming
- Code formatting
- Find all references
- Document symbols outline
- Signature help for function calls
- Workspace-wide symbol search

## License

GPL-3.0
