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
  private execUser: string;
  private execHome: string;
  private baseDirs: string[];
  private baseDirsEnsured = false;

  // execUser defaults to "remnux": the REMnux distro image is built --user=remnux,
  // so per-user tooling (the radare2 plugins r2ai/decai, the r2pm package DB, dotfile
  // config) lives under /home/remnux and is invisible to root. Running container
  // commands as remnux with HOME set makes that tooling discoverable and keeps
  // malware analysis off root.
  constructor(
    containerName: string,
    execUser = "remnux",
    samplesDir?: string,
    outputDir?: string,
  ) {
    // Docker container names can only contain [a-zA-Z0-9][a-zA-Z0-9_.-]*
    const sanitized = containerName.replace(/[^a-zA-Z0-9_.-]/g, "");
    if (sanitized !== containerName) {
      throw new Error(`Invalid container name: ${containerName}`);
    }
    this.docker = new Docker();
    this.containerName = containerName;
    // Coerce empty/falsy to remnux so an explicit "" never yields User:"" (silently
    // root) with HOME=/home/. root keeps /root; everyone else gets /home/<user>.
    this.execUser = execUser || "remnux";
    // Derive HOME/WorkingDir only for a simple username. A Docker user spec can be
    // `uid`, `uid:gid`, or `user:group`; fabricating `/home/<uid:gid>` yields a path
    // that does not exist and makes `docker exec` fail before the tool even runs.
    // root/0 → /root; a simple username → /home/<user>; a numeric uid or a compound
    // spec → "/" (which always exists) rather than a fabricated home.
    this.execHome =
      this.execUser === "root" || this.execUser === "0"
        ? "/root"
        : /^[a-z_][a-z0-9_-]*$/i.test(this.execUser)
          ? `/home/${this.execUser}`
          : "/";
    // Samples/output dirs the exec user must be able to write to. Used to repair
    // ownership for containers first used by an older version that exec'd as root.
    this.baseDirs = [samplesDir, outputDir].filter((d): d is string => !!d);
  }

  // Build the dockerode exec-create options. Pure and side-effect-free so the
  // user/HOME wiring can be unit-tested without dockerode's stream machinery.
  buildExecCreateOptions(
    command: string[],
    options: ExecOptions = {},
  ): Docker.ExecCreateOptions {
    return {
      Cmd: command,
      AttachStdout: true,
      AttachStderr: true,
      WorkingDir: options.cwd || this.execHome,
      User: this.execUser,
      // Env AUGMENTS the image environment (PATH etc. preserved); we set HOME so
      // r2/r2pm and other user tooling resolve under the exec user's home.
      Env: [`HOME=${this.execHome}`],
    };
  }

  // Wrap a command with GNU `timeout` so the container-side process is bounded and
  // actually killed on timeout (destroying the client stream does not terminate it).
  // SIGTERM at the limit, SIGKILL after a 10s grace. Pure and side-effect-free so the
  // wrapping can be unit-tested. `timeout` is coreutils (always present) and is the
  // same mechanism executeShell already uses.
  buildTimeoutWrappedCommand(command: string[], timeoutMs: number): string[] {
    const secs = Math.max(1, Math.floor(timeoutMs / 1000));
    return ["timeout", "-s", "TERM", "-k", "10s", `${secs}s`, ...command];
  }

  // Build the root `docker exec` argv that chowns a path to the exec user, or null
  // when the exec user is root (docker cp already lands files as root). Returns the
  // arguments to `docker` (run with no shell), so it is injection-safe and testable.
  buildRootChownArgv(remotePath: string): string[] | null {
    if (this.execUser === "root") return null;
    return ["exec", "-u", "0", this.containerName, "chown", this.execUser, remotePath];
  }

  // Build the root argvs that create the configured samples/output dirs and give them
  // to the exec user, so tools running as that user can write there even when an
  // earlier (run-as-root) version created the dirs root-owned. Pure/testable.
  buildEnsureDirsArgvs(): string[][] {
    if (this.execUser === "root" || this.baseDirs.length === 0) return [];
    return [
      ["exec", "-u", "0", this.containerName, "mkdir", "-p", ...this.baseDirs],
      ["exec", "-u", "0", this.containerName, "chown", this.execUser, ...this.baseDirs],
    ];
  }

  // Run `docker <argv>` via execFileSync — no shell, so values cannot inject commands.
  // Best-effort: callers swallow failures so ownership repair never blocks analysis.
  private async runDocker(argv: string[]): Promise<void> {
    const { execFileSync } = await import("child_process");
    execFileSync("docker", argv, { stdio: "pipe" });
  }

  // Idempotently make the samples/output dirs owned by the exec user. Runs once per
  // connector. Best-effort: the dirs may already be correct, or docker may be
  // unavailable to this process.
  private async ensureBaseDirsOwned(): Promise<void> {
    if (this.baseDirsEnsured) return;
    this.baseDirsEnsured = true;
    for (const argv of this.buildEnsureDirsArgvs()) {
      try {
        await this.runDocker(argv);
      } catch {
        /* best-effort */
      }
    }
  }

  // Chown a docker-cp'd path to the exec user so tools running as that user can read
  // it (docker cp preserves the host uid/mode, which may not grant access). No-op
  // when the exec user is root. Best-effort.
  private async chownToExecUser(remotePath: string): Promise<void> {
    const argv = this.buildRootChownArgv(remotePath);
    if (!argv) return;
    try {
      await this.runDocker(argv);
    } catch {
      /* best-effort */
    }
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

    // Repair samples/output ownership once before the first command, so tools running
    // as a non-root exec user can write there even on containers created root-owned.
    await this.ensureBaseDirsOwned();

    const timeout = options.timeout || 300000;
    // Bound the container-side process with GNU `timeout` (coreutils, always present,
    // already used by executeShell). Destroying the client stream on the JS timer
    // below does NOT terminate the exec'd process — without this wrapper a hung
    // command keeps running in the container, which leaks in long-lived REMnux
    // service deployments. SIGTERM at the limit, SIGKILL after a 10s grace period.
    const wrappedCommand = this.buildTimeoutWrappedCommand(command, timeout);
    const exec = await container.exec(this.buildExecCreateOptions(wrappedCommand, options));

    return new Promise((resolve, reject) => {
      let timedOut = false;
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      let activeStream: any = null;

      // Backstop only: GNU timeout (above) is the primary bound and fires first, so
      // this fires (TERM + 10s grace + 5s buffer) later only if the stream never ends.
      const timer = setTimeout(async () => {
        timedOut = true;
        // Destroy the stream to stop reading output
        if (activeStream && typeof activeStream.destroy === "function") {
          activeStream.destroy();
        }
        reject(new Error(`Command timed out after ${timeout / 1000} seconds`));
      }, timeout + 15000);

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

            const exitCode = inspectResult.ExitCode ?? 0;
            // GNU `timeout` terminated the wrapped process: 124 = timed out (SIGTERM),
            // 137 = SIGKILL after the grace period. Surface the same timeout error the
            // backstop would, having actually killed the container-side process.
            if (exitCode === 124 || exitCode === 137) {
              return reject(new Error(`Command timed out after ${timeout / 1000} seconds`));
            }

            let finalStdout = stdout.trim();
            if (outputTruncated) {
              finalStdout += "\n\n[OUTPUT TRUNCATED - exceeded 10MB limit]";
            }

            resolve({
              stdout: finalStdout,
              stderr: stderr.trim(),
              exitCode,
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

    await this.ensureBaseDirsOwned();

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

      // docker cp preserves the host file's numeric UID/GID and mode (NOT the exec
      // user), so a file that is not world/group readable on the host would be
      // unreadable by a non-root exec user. Chown the copied path to the exec user so
      // tools running as that user can read (and manage) it.
      await this.chownToExecUser(remotePath);
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
    await this.ensureBaseDirsOwned();
    const escapedRemotePath = remotePath.replace(/'/g, "'\\''");
    const escapedHostPath = hostPath.replace(/'/g, "'\\''");
    const { execSync } = await import("child_process");
    execSync(
      `docker cp '${escapedHostPath}' '${this.containerName}:${escapedRemotePath}'`,
      { stdio: "pipe" }
    );
    // docker cp preserves the host uid/mode, which may not grant the non-root exec
    // user access. Chown the copied path to the exec user so tools can read it.
    await this.chownToExecUser(remotePath);
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
    // Calculate shell timeout (slightly shorter than client timeout to fire first)
    const clientTimeoutMs = options.timeout || 300000;
    const clientTimeoutSecs = Math.floor(clientTimeoutMs / 1000);
    const shellTimeoutSecs = Math.max(clientTimeoutSecs - 5, 10); // 5s buffer, min 10s

    // Escape command for bash -c (single quotes with proper escaping)
    const escapedCmd = command.replace(/'/g, "'\\''");

    // Wrap with GNU timeout: SIGTERM first, SIGKILL after 10s grace period
    // This ensures the process actually dies even if it ignores SIGTERM
    const wrappedCmd = `timeout -s TERM -k 10s ${shellTimeoutSecs}s bash -c '${escapedCmd}'`;

    return this.execute(["bash", "-c", wrappedCmd], options);
  }

  async disconnect(): Promise<void> {
    // Docker client doesn't maintain persistent connections
  }
}
