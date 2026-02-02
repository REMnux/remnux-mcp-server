import { spawn } from "child_process";
import { copyFileSync, writeFileSync } from "fs";
import type { Connector, ExecOptions, ExecResult } from "./index.js";

// Output size limit (10MB)
const MAX_OUTPUT_SIZE = 10 * 1024 * 1024;

// Allowed environment variables for tool execution
// Only pass essential vars to prevent leaking sensitive data
const ALLOWED_ENV_VARS = [
  "PATH",
  "HOME",
  "USER",
  "SHELL",
  "TERM",
  "LANG",
  "LC_ALL",
  "TZ",
  // Tool-specific vars that may be needed
  "PYTHONPATH",
  "JAVA_HOME",
];

export class LocalConnector implements Connector {
  async execute(command: string[], options: ExecOptions = {}): Promise<ExecResult> {
    // Validate command array is not empty
    if (command.length === 0) {
      throw new Error("Command array cannot be empty");
    }

    const timeout = options.timeout || 300000;
    const [cmd, ...args] = command;

    // Filter environment variables to only allowed ones
    const filteredEnv: NodeJS.ProcessEnv = {};
    for (const key of ALLOWED_ENV_VARS) {
      if (process.env[key]) {
        filteredEnv[key] = process.env[key];
      }
    }

    return new Promise((resolve, reject) => {
      let timedOut = false;
      let stdout = "";
      let stderr = "";
      let outputTruncated = false;

      const proc = spawn(cmd, args, {
        cwd: options.cwd,
        env: filteredEnv,
        stdio: ["ignore", "pipe", "pipe"],
      });

      const timer = setTimeout(() => {
        timedOut = true;
        proc.kill("SIGKILL");
        reject(new Error(`Command timed out after ${timeout / 1000} seconds`));
      }, timeout);

      proc.stdout.on("data", (data: Buffer) => {
        if (stdout.length < MAX_OUTPUT_SIZE) {
          stdout += data.toString();
          if (stdout.length >= MAX_OUTPUT_SIZE) {
            stdout = stdout.slice(0, MAX_OUTPUT_SIZE);
            outputTruncated = true;
          }
        }
      });

      proc.stderr.on("data", (data: Buffer) => {
        if (stderr.length < MAX_OUTPUT_SIZE) {
          stderr += data.toString();
          if (stderr.length >= MAX_OUTPUT_SIZE) {
            stderr = stderr.slice(0, MAX_OUTPUT_SIZE);
            outputTruncated = true;
          }
        }
      });

      proc.on("error", (err) => {
        clearTimeout(timer);
        reject(err);
      });

      proc.on("close", (code) => {
        if (timedOut) return;
        clearTimeout(timer);

        let finalStdout = stdout.trim();
        if (outputTruncated) {
          finalStdout += "\n\n[OUTPUT TRUNCATED - exceeded 10MB limit]";
        }

        resolve({
          stdout: finalStdout,
          stderr: stderr.trim(),
          exitCode: code ?? 0,
        });
      });
    });
  }

  async executeShell(command: string, options: ExecOptions = {}): Promise<ExecResult> {
    // Execute command through bash shell to support pipes and redirects
    return this.execute(["bash", "-c", command], options);
  }

  async writeFile(remotePath: string, content: Buffer): Promise<void> {
    writeFileSync(remotePath, content);
  }

  async writeFileFromPath(remotePath: string, hostPath: string): Promise<void> {
    copyFileSync(hostPath, remotePath);
  }

  async readFileToPath(remotePath: string, hostPath: string): Promise<void> {
    copyFileSync(remotePath, hostPath);
  }

  async disconnect(): Promise<void> {
    // No persistent connection for local mode
  }
}
