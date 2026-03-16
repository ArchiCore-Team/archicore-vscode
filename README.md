# ArchiCore for VS Code

Security and architecture analysis for your codebase, powered by ArchiCore.

## Features

- **Security analysis** -- findings shown as editor diagnostics (squiggly underlines)
- **Sidebar tree view** -- findings grouped by severity (Critical, High, Medium, Low)
- **Status bar** -- live risk score and grade (e.g. `ArchiCore: A (0/100)`)
- **Click-to-navigate** -- click any finding to jump to the exact file and line

## Installation

1. Install the ArchiCore CLI globally or in your project:
   ```bash
   npm install -g archicore-oss
   # or
   npm install --save-dev archicore-oss
   ```
2. Install this extension from a `.vsix` file:
   ```bash
   cd archicore-vscode
   npm install
   npm run compile
   npx vsce package
   code --install-extension archicore-vscode-0.1.0.vsix
   ```

## Usage

- **Analyze**: Run `ArchiCore: Analyze Workspace` from the Command Palette (`Ctrl+Shift+P`).
- **Clear**: Run `ArchiCore: Clear Results` to remove all diagnostics and reset the tree view.
- The sidebar panel (shield icon) shows all findings grouped by severity. Click any item to open the file.

## Configuration

| Setting                      | Type    | Default       | Description                                                  |
|------------------------------|---------|---------------|--------------------------------------------------------------|
| `archicore.cliPath`          | string  | `"archicore"` | Path to the ArchiCore CLI executable.                        |
| `archicore.autoAnalyze`      | boolean | `false`       | Run analysis automatically when the workspace opens.         |
| `archicore.failOnSeverity`   | enum    | `"none"`      | Warn if findings at or above this severity exist.            |

## CLI Resolution Order

1. `archicore.cliPath` setting (if set to an absolute path)
2. `<workspace>/node_modules/.bin/archicore` (local install)
3. `npx archicore-oss` (fallback)

## Development

```bash
npm install
npm run watch   # rebuild on change
# Press F5 in VS Code to launch Extension Development Host
```
