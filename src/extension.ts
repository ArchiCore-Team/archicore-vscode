import * as vscode from "vscode";
import * as cp from "child_process";
import * as path from "path";
import * as fs from "fs";
import * as os from "os";

// ---------------------------------------------------------------------------
// Types — raw ArchiCore CLI output format
// ---------------------------------------------------------------------------

interface RawVulnerability {
  id: string;
  type: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  description: string;
  file: string;
  line: number;
  code?: string;
  cwe?: string;
  owasp?: string;
  remediation?: string;
}

interface RawSecret {
  type: string;
  file: string;
  line: number;
  preview?: string;
  confidence: "high" | "medium" | "low";
}

interface RawCliOutput {
  security?: {
    vulnerabilities?: RawVulnerability[];
    secrets?: RawSecret[];
    summary?: {
      riskScore?: number;
      grade?: string;
      critical?: number;
      high?: number;
      medium?: number;
      low?: number;
      secretsFound?: number;
    };
  };
  metrics?: {
    summary?: {
      totalFiles?: number;
      totalLOC?: number;
      avgComplexity?: number;
      avgMaintainability?: number;
      technicalDebtHours?: number;
      grade?: string;
    };
  };
}

// ---------------------------------------------------------------------------
// Types — normalized internal format
// ---------------------------------------------------------------------------

interface ArchicoreFinding {
  id: string;
  rule: string;
  severity: "critical" | "high" | "medium" | "low";
  message: string;
  file: string;
  line: number;
  column?: number;
  endLine?: number;
  endColumn?: number;
  category?: string;
  cwe?: string;
}

interface ArchicoreMetrics {
  riskScore: number;
  grade: string;
  totalFiles: number;
  totalLines: number;
  securityFindings: number;
  deadCodeItems?: number;
}

interface ArchicoreOutput {
  findings: ArchicoreFinding[];
  metrics: ArchicoreMetrics;
}

// ---------------------------------------------------------------------------
// Severity helpers
// ---------------------------------------------------------------------------

const SEVERITY_ORDER: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
};

const SEVERITY_LABELS: Record<string, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
};

function toDiagnosticSeverity(
  severity: string
): vscode.DiagnosticSeverity {
  switch (severity) {
    case "critical":
    case "high":
      return vscode.DiagnosticSeverity.Error;
    case "medium":
      return vscode.DiagnosticSeverity.Warning;
    case "low":
      return vscode.DiagnosticSeverity.Information;
    default:
      return vscode.DiagnosticSeverity.Hint;
  }
}

function severityIcon(severity: string): vscode.ThemeIcon {
  switch (severity) {
    case "critical":
      return new vscode.ThemeIcon("error", new vscode.ThemeColor("errorForeground"));
    case "high":
      return new vscode.ThemeIcon("warning", new vscode.ThemeColor("errorForeground"));
    case "medium":
      return new vscode.ThemeIcon("warning", new vscode.ThemeColor("editorWarning.foreground"));
    case "low":
      return new vscode.ThemeIcon("info", new vscode.ThemeColor("editorInfo.foreground"));
    default:
      return new vscode.ThemeIcon("circle-outline");
  }
}

// ---------------------------------------------------------------------------
// Tree view data provider
// ---------------------------------------------------------------------------

type TreeElement = SeverityGroup | FindingItem;

class SeverityGroup extends vscode.TreeItem {
  constructor(
    public readonly severity: string,
    public readonly findings: ArchicoreFinding[],
    private readonly workspaceRoot: string
  ) {
    super(
      `${SEVERITY_LABELS[severity] ?? severity} (${findings.length})`,
      vscode.TreeItemCollapsibleState.Expanded
    );
    this.iconPath = severityIcon(severity);
    this.contextValue = "severityGroup";
  }

  getChildren(): FindingItem[] {
    return this.findings.map((f) => new FindingItem(f, this.workspaceRoot));
  }
}

class FindingItem extends vscode.TreeItem {
  constructor(
    public readonly finding: ArchicoreFinding,
    workspaceRoot: string
  ) {
    const relPath = path.relative(workspaceRoot, finding.file) || finding.file;
    super(`${finding.rule}: ${finding.message}`, vscode.TreeItemCollapsibleState.None);
    this.description = `${relPath}:${finding.line}`;
    this.tooltip = new vscode.MarkdownString(
      [
        `**${finding.rule}**`,
        finding.message,
        `File: \`${relPath}:${finding.line}\``,
        finding.cwe ? `CWE: ${finding.cwe}` : "",
      ]
        .filter(Boolean)
        .join("\n\n")
    );
    this.iconPath = severityIcon(finding.severity);
    this.contextValue = "finding";

    const fileUri = vscode.Uri.file(
      path.isAbsolute(finding.file) ? finding.file : path.join(workspaceRoot, finding.file)
    );
    this.command = {
      command: "vscode.open",
      title: "Open Finding",
      arguments: [
        fileUri,
        <vscode.TextDocumentShowOptions>{
          selection: new vscode.Range(
            Math.max(0, finding.line - 1),
            finding.column ?? 0,
            Math.max(0, (finding.endLine ?? finding.line) - 1),
            finding.endColumn ?? 0
          ),
        },
      ],
    };
  }
}

class FindingsProvider implements vscode.TreeDataProvider<TreeElement> {
  private _onDidChangeTreeData = new vscode.EventEmitter<TreeElement | undefined | void>();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

  private groups: SeverityGroup[] = [];

  update(findings: ArchicoreFinding[], workspaceRoot: string): void {
    const grouped = new Map<string, ArchicoreFinding[]>();
    for (const f of findings) {
      const sev = f.severity ?? "low";
      if (!grouped.has(sev)) {
        grouped.set(sev, []);
      }
      grouped.get(sev)!.push(f);
    }

    this.groups = Array.from(grouped.entries())
      .sort(([a], [b]) => (SEVERITY_ORDER[a] ?? 9) - (SEVERITY_ORDER[b] ?? 9))
      .map(([sev, items]) => new SeverityGroup(sev, items, workspaceRoot));

    this._onDidChangeTreeData.fire();
  }

  clear(): void {
    this.groups = [];
    this._onDidChangeTreeData.fire();
  }

  getTreeItem(element: TreeElement): vscode.TreeItem {
    return element;
  }

  getChildren(element?: TreeElement): TreeElement[] {
    if (!element) {
      return this.groups;
    }
    if (element instanceof SeverityGroup) {
      return element.getChildren();
    }
    return [];
  }
}

// ---------------------------------------------------------------------------
// CLI resolution
// ---------------------------------------------------------------------------

function resolveCliPath(workspaceRoot: string): string {
  const config = vscode.workspace.getConfiguration("archicore");
  const configured = config.get<string>("cliPath", "archicore");

  // If user set an explicit absolute path, use it directly.
  if (configured !== "archicore" && path.isAbsolute(configured)) {
    return configured;
  }

  // Check workspace-local install.
  const localBin = path.join(workspaceRoot, "node_modules", ".bin", "archicore");
  if (fs.existsSync(localBin)) {
    return localBin;
  }

  // Fall back to npx.
  if (configured === "archicore") {
    return "npx archicore-oss";
  }

  return configured;
}

// ---------------------------------------------------------------------------
// Run CLI
// ---------------------------------------------------------------------------

function runCli(
  cliPath: string,
  workspaceRoot: string,
  token: vscode.CancellationToken
): Promise<ArchicoreOutput> {
  return new Promise((resolve, reject) => {
    const tmpFile = path.join(os.tmpdir(), `archicore-${Date.now()}.json`);

    // Build the command. If cliPath starts with "npx " we need to use shell mode.
    const useShell = cliPath.startsWith("npx ");
    const args = [
      ...(useShell ? [] : []),
      "analyze",
      "--root",
      workspaceRoot,
      "--security",
      "--metrics",
      "--json",
      "--output",
      tmpFile,
    ];

    let command: string;
    let spawnArgs: string[];
    if (useShell) {
      command = cliPath.split(" ")[0];
      spawnArgs = [...cliPath.split(" ").slice(1), ...args];
    } else {
      command = cliPath;
      spawnArgs = args;
    }

    const proc = cp.spawn(command, spawnArgs, {
      cwd: workspaceRoot,
      shell: useShell,
      env: { ...process.env },
      windowsHide: true,
    });

    let stderr = "";

    proc.stderr?.on("data", (data: Buffer) => {
      stderr += data.toString();
    });

    const cancelListener = token.onCancellationRequested(() => {
      proc.kill();
      reject(new Error("Analysis cancelled."));
    });

    proc.on("error", (err) => {
      cancelListener.dispose();
      cleanTmp(tmpFile);
      reject(new Error(`Failed to start ArchiCore CLI: ${err.message}`));
    });

    proc.on("close", (code) => {
      cancelListener.dispose();

      // Try to read the JSON output file first.
      if (fs.existsSync(tmpFile)) {
        try {
          const raw = fs.readFileSync(tmpFile, "utf-8");
          const parsed = JSON.parse(raw) as RawCliOutput;
          cleanTmp(tmpFile);
          resolve(normalizeOutput(parsed, workspaceRoot));
          return;
        } catch {
          // Fall through to stderr/stdout parsing.
        }
      }
      cleanTmp(tmpFile);

      // If CLI exited non-zero and there was no output file, try parsing
      // stdout captured via pipe (some versions print JSON to stdout).
      if (code !== 0) {
        reject(
          new Error(
            `ArchiCore CLI exited with code ${code}.\n${stderr.slice(0, 500)}`
          )
        );
        return;
      }

      // Successful exit but no output file — return empty results.
      resolve({ findings: [], metrics: defaultMetrics() });
    });
  });
}

function cleanTmp(filePath: string): void {
  try {
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
    }
  } catch {
    // Best-effort cleanup.
  }
}

function defaultMetrics(): ArchicoreMetrics {
  return {
    riskScore: 0,
    grade: "A",
    totalFiles: 0,
    totalLines: 0,
    securityFindings: 0,
  };
}

/**
 * Normalise raw CLI output into the internal ArchicoreOutput format.
 * Maps security.vulnerabilities + security.secrets → findings[],
 * and merges security.summary + metrics.summary → metrics.
 */
function normalizeOutput(raw: RawCliOutput, workspaceRoot: string): ArchicoreOutput {
  const findings: ArchicoreFinding[] = [];

  // Map vulnerabilities to findings
  for (const v of raw.security?.vulnerabilities ?? []) {
    const filePath = v.file
      ? (path.isAbsolute(v.file) ? v.file : path.join(workspaceRoot, v.file))
      : workspaceRoot;
    const severity = v.severity === "info" ? "low" : v.severity;
    findings.push({
      id: v.id ?? `${v.type}-${v.line}`,
      rule: v.type ?? "unknown",
      severity: severity ?? "low",
      message: v.description || v.title || "",
      file: filePath,
      line: v.line ?? 1,
      cwe: v.cwe,
    });
  }

  // Map secrets to findings
  for (const s of raw.security?.secrets ?? []) {
    const filePath = s.file
      ? (path.isAbsolute(s.file) ? s.file : path.join(workspaceRoot, s.file))
      : workspaceRoot;
    findings.push({
      id: `secret-${s.type}-${s.line}`,
      rule: "hardcoded-secret",
      severity: s.confidence === "high" ? "high" : "medium",
      message: `Hardcoded ${s.type} detected`,
      file: filePath,
      line: s.line ?? 1,
    });
  }

  const secSummary = raw.security?.summary;
  const metSummary = raw.metrics?.summary;

  const metrics: ArchicoreMetrics = {
    riskScore: secSummary?.riskScore ?? 0,
    grade: secSummary?.grade ?? metSummary?.grade ?? "A",
    totalFiles: metSummary?.totalFiles ?? 0,
    totalLines: metSummary?.totalLOC ?? 0,
    securityFindings: findings.length,
  };

  return { findings, metrics };
}

// ---------------------------------------------------------------------------
// Fail-on-severity check
// ---------------------------------------------------------------------------

function checkFailOnSeverity(findings: ArchicoreFinding[]): void {
  const config = vscode.workspace.getConfiguration("archicore");
  const threshold = config.get<string>("failOnSeverity", "none");
  if (threshold === "none") {
    return;
  }

  const thresholdOrder = SEVERITY_ORDER[threshold] ?? 99;
  const failing = findings.filter(
    (f) => (SEVERITY_ORDER[f.severity] ?? 99) <= thresholdOrder
  );

  if (failing.length > 0) {
    vscode.window.showWarningMessage(
      `ArchiCore: ${failing.length} finding(s) at or above "${threshold}" severity.`
    );
  }
}

// ---------------------------------------------------------------------------
// Extension lifecycle
// ---------------------------------------------------------------------------

let diagnosticCollection: vscode.DiagnosticCollection;
let statusBarItem: vscode.StatusBarItem;
let findingsProvider: FindingsProvider;

export function activate(context: vscode.ExtensionContext): void {
  // Diagnostics
  diagnosticCollection = vscode.languages.createDiagnosticCollection("archicore");
  context.subscriptions.push(diagnosticCollection);

  // Status bar
  statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 50);
  statusBarItem.command = "archicore.analyze";
  statusBarItem.tooltip = "Click to run ArchiCore analysis";
  updateStatusBar(defaultMetrics());
  statusBarItem.show();
  context.subscriptions.push(statusBarItem);

  // Tree view
  findingsProvider = new FindingsProvider();
  const treeView = vscode.window.createTreeView("archicore-findings", {
    treeDataProvider: findingsProvider,
    showCollapseAll: true,
  });
  context.subscriptions.push(treeView);

  // Commands
  context.subscriptions.push(
    vscode.commands.registerCommand("archicore.analyze", () => analyzeWorkspace())
  );
  context.subscriptions.push(
    vscode.commands.registerCommand("archicore.clear", () => clearResults())
  );

  // Auto-analyze on startup
  const config = vscode.workspace.getConfiguration("archicore");
  if (config.get<boolean>("autoAnalyze", false)) {
    analyzeWorkspace();
  }
}

export function deactivate(): void {
  diagnosticCollection?.clear();
  diagnosticCollection?.dispose();
  statusBarItem?.dispose();
}

// ---------------------------------------------------------------------------
// Core commands
// ---------------------------------------------------------------------------

async function analyzeWorkspace(): Promise<void> {
  const workspaceFolders = vscode.workspace.workspaceFolders;
  if (!workspaceFolders || workspaceFolders.length === 0) {
    vscode.window.showErrorMessage("ArchiCore: No workspace folder open.");
    return;
  }

  const workspaceRoot = workspaceFolders[0].uri.fsPath;
  const cliPath = resolveCliPath(workspaceRoot);

  await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: "ArchiCore: Analyzing workspace...",
      cancellable: true,
    },
    async (_progress, token) => {
      try {
        const output = await runCli(cliPath, workspaceRoot, token);
        applyResults(output, workspaceRoot);
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        vscode.window.showErrorMessage(`ArchiCore analysis failed: ${msg}`);
      }
    }
  );
}

function applyResults(output: ArchicoreOutput, workspaceRoot: string): void {
  // --- Diagnostics ---
  diagnosticCollection.clear();

  const diagMap = new Map<string, vscode.Diagnostic[]>();
  for (const finding of output.findings) {
    const uri = finding.file;
    if (!diagMap.has(uri)) {
      diagMap.set(uri, []);
    }

    const startLine = Math.max(0, finding.line - 1);
    const startCol = finding.column ?? 0;
    const endLine = Math.max(0, (finding.endLine ?? finding.line) - 1);
    const endCol = finding.endColumn ?? Number.MAX_SAFE_INTEGER;

    const range = new vscode.Range(startLine, startCol, endLine, endCol);
    const diag = new vscode.Diagnostic(range, finding.message, toDiagnosticSeverity(finding.severity));
    diag.source = "ArchiCore";
    diag.code = finding.cwe ? `${finding.rule} (${finding.cwe})` : finding.rule;
    diagMap.get(uri)!.push(diag);
  }

  for (const [filePath, diags] of diagMap) {
    diagnosticCollection.set(vscode.Uri.file(filePath), diags);
  }

  // --- Tree view ---
  findingsProvider.update(output.findings, workspaceRoot);

  // --- Status bar ---
  updateStatusBar(output.metrics);

  // --- Severity threshold check ---
  checkFailOnSeverity(output.findings);

  // --- Summary notification ---
  const { findings, metrics } = output;
  const counts = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
  };
  for (const f of findings) {
    if (f.severity in counts) {
      counts[f.severity as keyof typeof counts]++;
    }
  }

  const parts: string[] = [];
  if (counts.critical) parts.push(`${counts.critical} critical`);
  if (counts.high) parts.push(`${counts.high} high`);
  if (counts.medium) parts.push(`${counts.medium} medium`);
  if (counts.low) parts.push(`${counts.low} low`);

  const summary = parts.length > 0
    ? `Found ${findings.length} issue(s): ${parts.join(", ")}.`
    : "No issues found.";

  vscode.window.showInformationMessage(
    `ArchiCore: ${metrics.grade} (${metrics.riskScore}/100) - ${summary}`
  );
}

function updateStatusBar(metrics: ArchicoreMetrics): void {
  statusBarItem.text = `$(shield) ArchiCore: ${metrics.grade} (${metrics.riskScore}/100)`;
}

function clearResults(): void {
  diagnosticCollection.clear();
  findingsProvider.clear();
  updateStatusBar(defaultMetrics());
  vscode.window.showInformationMessage("ArchiCore: Results cleared.");
}
