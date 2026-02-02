import Docker from "dockerode";
import { writeFileSync, unlinkSync, mkdtempSync } from "fs";
import { tmpdir } from "os";
import { join, basename } from "path";
import type { Connector, ExecOptions, ExecResult } from "./index.js";

// Output size limit (10MB)
const MAX_OUTPUT_SIZE = 10 * 1024 * 1024;

export class DockerConnector implements Connector {
  private docker: Docker;
  private containerName: string;

  constructor(containerName: string) {
    // Docker container names can only contain [a-zA-Z0-9][a-zA-Z0-9_.-]*
    const sanitized = containerName.replace(/[^a-zA-Z0-9_.-]/g, "");
    if (sanitized !== containerName) {
      throw new Error(`Invalid container name: ${containerName}`);
    }
    this.docker = new Docker();
    this.containerName = containerName;
  }

  async execute(command: string[], options: ExecOptions = {}): Promise<ExecResult> {
    // Validate command array is not empty
    if (command.length === 0) {
      throw new Error("Command array cannot be empty");
    }

    const container = this.docker.getContainer(this.containerName);

    // Check container exists and is running
    const info = await container.inspect();
    if (!info.State.Running) {
      throw new Error(`Container '${this.containerName}' is not running`);
    }

    const exec = await container.exec({
      Cmd: command,
      AttachStdout: true,
      AttachStderr: true,
      WorkingDir: options.cwd || "/home/remnux",
    });

    return new Promise((resolve, reject) => {
      const timeout = options.timeout || 300000;
      let timedOut = false;
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      let activeStream: any = null;

      const timer = setTimeout(async () => {
        timedOut = true;
        // Destroy the stream to stop reading output
        if (activeStream && typeof activeStream.destroy === "function") {
          activeStream.destroy();
        }
        reject(new Error(`Command timed out after ${timeout / 1000} seconds`));
      }, timeout);

      exec.start({ hijack: true, stdin: false }, (err, stream) => {
        if (err) {
          clearTimeout(timer);
          return reject(err);
        }

        if (!stream) {
          clearTimeout(timer);
          return reject(new Error("No stream returned from exec"));
        }

        // Store stream reference for timeout cleanup
        activeStream = stream;

        let stdout = "";
        let stderr = "";
        let outputTruncated = false;

        // Docker multiplexes stdout/stderr in the stream when using hijack mode
        // Each frame has an 8-byte header: [type(1)][0][0][0][size(4 bytes BE)]
        // type: 1 = stdout, 2 = stderr
        let buffer = Buffer.alloc(0);

        const processBuffer = () => {
          // Need at least 8 bytes for the header
          while (buffer.length >= 8) {
            const streamType = buffer[0]; // 1 = stdout, 2 = stderr
            const payloadSize = buffer.readUInt32BE(4);

            // Check if we have the full frame
            if (buffer.length < 8 + payloadSize) {
              break;
            }

            const payload = buffer.slice(8, 8 + payloadSize).toString("utf8");
            buffer = buffer.slice(8 + payloadSize);

            if (streamType === 1) {
              // stdout
              if (stdout.length < MAX_OUTPUT_SIZE) {
                stdout += payload;
                if (stdout.length >= MAX_OUTPUT_SIZE) {
                  stdout = stdout.slice(0, MAX_OUTPUT_SIZE);
                  outputTruncated = true;
                }
              }
            } else if (streamType === 2) {
              // stderr
              if (stderr.length < MAX_OUTPUT_SIZE) {
                stderr += payload;
                if (stderr.length >= MAX_OUTPUT_SIZE) {
                  stderr = stderr.slice(0, MAX_OUTPUT_SIZE);
                  outputTruncated = true;
                }
              }
            }
          }
        };

        stream.on("data", (chunk: Buffer) => {
          buffer = Buffer.concat([buffer, chunk]);
          processBuffer();
        });

        stream.on("end", async () => {
          if (timedOut) return;
          clearTimeout(timer);

          // Process any remaining data
          processBuffer();

          // If demuxing didn't work (no headers), treat all data as stdout
          // This handles the case where TTY is attached or raw mode is used
          if (stdout === "" && stderr === "" && buffer.length > 0) {
            stdout = buffer.toString("utf8");
            if (stdout.length > MAX_OUTPUT_SIZE) {
              stdout = stdout.slice(0, MAX_OUTPUT_SIZE);
              outputTruncated = true;
            }
          }

          try {
            const inspectResult = await exec.inspect();

            let finalStdout = stdout.trim();
            if (outputTruncated) {
              finalStdout += "\n\n[OUTPUT TRUNCATED - exceeded 10MB limit]";
            }

            resolve({
              stdout: finalStdout,
              stderr: stderr.trim(),
              exitCode: inspectResult.ExitCode ?? 0,
            });
          } catch (_inspectErr) {
            resolve({
              stdout: stdout.trim(),
              stderr: stderr.trim(),
              exitCode: -1,
            });
          }
        });

        stream.on("error", (streamErr: Error) => {
          clearTimeout(timer);
          reject(streamErr);
        });
      });
    });
  }

  async writeFile(remotePath: string, content: Buffer): Promise<void> {
    const container = this.docker.getContainer(this.containerName);

    // Check container exists and is running
    const info = await container.inspect();
    if (!info.State.Running) {
      throw new Error(`Container '${this.containerName}' is not running`);
    }

    // Create a temp file on the host
    const tempDir = mkdtempSync(join(tmpdir(), "remnux-upload-"));
    const filename = basename(remotePath);
    const tempPath = join(tempDir, filename);

    try {
      // Write content to temp file
      writeFileSync(tempPath, content);

      // Use docker cp to copy into container
      // docker cp tempPath containerName:remotePath
      // Escape single quotes in paths for shell safety (defense-in-depth)
      const escapedTempPath = tempPath.replace(/'/g, "'\\''");
      const escapedRemotePath = remotePath.replace(/'/g, "'\\''");
      const { execSync } = await import("child_process");
      execSync(
        `docker cp '${escapedTempPath}' '${this.containerName}:${escapedRemotePath}'`,
        { stdio: "pipe" }
      );

      // Files are owned by whatever user the container runs as (typically root)
    } finally {
      // Clean up temp file
      try {
        unlinkSync(tempPath);
        const { rmdirSync } = await import("fs");
        rmdirSync(tempDir);
      } catch {
        // Ignore cleanup errors
      }
    }
  }

  async writeFileFromPath(remotePath: string, hostPath: string): Promise<void> {
    const escapedRemotePath = remotePath.replace(/'/g, "'\\''");
    const escapedHostPath = hostPath.replace(/'/g, "'\\''");
    const { execSync } = await import("child_process");
    execSync(
      `docker cp '${escapedHostPath}' '${this.containerName}:${escapedRemotePath}'`,
      { stdio: "pipe" }
    );
  }

  async readFileToPath(remotePath: string, hostPath: string): Promise<void> {
    const escapedRemotePath = remotePath.replace(/'/g, "'\\''");
    const escapedHostPath = hostPath.replace(/'/g, "'\\''");
    const { execSync } = await import("child_process");
    execSync(
      `docker cp '${this.containerName}:${escapedRemotePath}' '${escapedHostPath}'`,
      { stdio: "pipe" }
    );
  }

  async executeShell(command: string, options: ExecOptions = {}): Promise<ExecResult> {
    // Execute command through bash shell to support pipes and redirects
    return this.execute(["bash", "-c", command], options);
  }

  async disconnect(): Promise<void> {
    // Docker client doesn't maintain persistent connections
  }
}
