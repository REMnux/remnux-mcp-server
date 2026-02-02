import { Client } from "ssh2";
import type { Connector, ExecOptions, ExecResult } from "./index.js";

// Output size limit (10MB)
const MAX_OUTPUT_SIZE = 10 * 1024 * 1024;

export interface SSHConfig {
  host: string;
  user: string;
  port: number;
  privateKey?: string;
  password?: string;
}

export class SSHConnector implements Connector {
  private config: SSHConfig;
  private client: Client | null = null;

  constructor(config: SSHConfig) {
    this.config = config;
  }

  private async connect(): Promise<Client> {
    if (this.client) {
      // Health check: verify the cached connection is still usable
      // ssh2 Client exposes ._sock (underlying socket) — if it's destroyed, reconnect
      const sock = (this.client as unknown as Record<string, unknown>)._sock as
        | { destroyed?: boolean }
        | undefined;
      if (sock?.destroyed) {
        this.client = null;
      } else {
        return this.client;
      }
    }

    return new Promise((resolve, reject) => {
      const client = new Client();

      client.on("ready", () => {
        this.client = client;
        resolve(client);
      });

      client.on("error", (err) => {
        this.client = null;
        reject(err);
      });

      client.on("close", () => {
        this.client = null;
      });

      // Try to connect with private key first, then password
      const connectConfig: Parameters<Client["connect"]>[0] = {
        host: this.config.host,
        port: this.config.port,
        username: this.config.user,
      };

      if (this.config.privateKey) {
        connectConfig.privateKey = this.config.privateKey;
      } else if (this.config.password) {
        connectConfig.password = this.config.password;
      } else {
        // Use SSH agent
        connectConfig.agent = process.env.SSH_AUTH_SOCK;
      }

      client.connect(connectConfig);
    });
  }

  async execute(command: string[], options: ExecOptions = {}): Promise<ExecResult> {
    const client = await this.connect();
    const timeout = options.timeout || 300000;

    // Validate command array is not empty
    if (command.length === 0) {
      throw new Error("Command array cannot be empty");
    }

    // Proper shell escaping using single quotes
    // Single quotes preserve everything literally except single quotes themselves
    // To include a single quote: end single quote, add escaped single quote, start single quote again
    const cmdString = command
      .map((arg) => `'${arg.replace(/'/g, "'\\''")}'`)
      .join(" ");

    // Also escape cwd path if provided
    const escapedCwd = options.cwd ? `'${options.cwd.replace(/'/g, "'\\''")}'` : null;
    const fullCmd = escapedCwd ? `cd ${escapedCwd} && ${cmdString}` : cmdString;

    return new Promise((resolve, reject) => {
      let timedOut = false;

      const timer = setTimeout(() => {
        timedOut = true;
        // Clean up the SSH connection on timeout
        this.client?.end();
        this.client = null;
        reject(new Error(`Command timed out after ${timeout / 1000} seconds`));
      }, timeout);

      client.exec(fullCmd, (err, stream) => {
        if (err) {
          clearTimeout(timer);
          return reject(err);
        }

        let stdout = "";
        let stderr = "";
        let outputTruncated = false;

        stream.on("data", (data: Buffer) => {
          if (stdout.length < MAX_OUTPUT_SIZE) {
            stdout += data.toString();
            if (stdout.length >= MAX_OUTPUT_SIZE) {
              stdout = stdout.slice(0, MAX_OUTPUT_SIZE);
              outputTruncated = true;
            }
          }
        });

        stream.stderr.on("data", (data: Buffer) => {
          if (stderr.length < MAX_OUTPUT_SIZE) {
            stderr += data.toString();
            if (stderr.length >= MAX_OUTPUT_SIZE) {
              stderr = stderr.slice(0, MAX_OUTPUT_SIZE);
              outputTruncated = true;
            }
          }
        });

        stream.on("close", (code: number) => {
          if (timedOut) return;
          clearTimeout(timer);

          let finalStdout = stdout.trim();
          if (outputTruncated) {
            finalStdout += "\n\n[OUTPUT TRUNCATED - exceeded 10MB limit]";
          }

          resolve({
            stdout: finalStdout,
            stderr: stderr.trim(),
            exitCode: code,
          });
        });
      });
    });
  }

  async executeShell(command: string, options: ExecOptions = {}): Promise<ExecResult> {
    const client = await this.connect();
    const timeout = options.timeout || 300000;

    // Build the full command with optional cwd
    const escapedCwd = options.cwd ? `'${options.cwd.replace(/'/g, "'\\''")}'` : null;
    const fullCmd = escapedCwd ? `cd ${escapedCwd} && ${command}` : command;

    return new Promise((resolve, reject) => {
      let timedOut = false;

      const timer = setTimeout(() => {
        timedOut = true;
        this.client?.end();
        this.client = null;
        reject(new Error(`Command timed out after ${timeout / 1000} seconds`));
      }, timeout);

      client.exec(fullCmd, (err, stream) => {
        if (err) {
          clearTimeout(timer);
          return reject(err);
        }

        let stdout = "";
        let stderr = "";
        let outputTruncated = false;

        stream.on("data", (data: Buffer) => {
          if (stdout.length < MAX_OUTPUT_SIZE) {
            stdout += data.toString();
            if (stdout.length >= MAX_OUTPUT_SIZE) {
              stdout = stdout.slice(0, MAX_OUTPUT_SIZE);
              outputTruncated = true;
            }
          }
        });

        stream.stderr.on("data", (data: Buffer) => {
          if (stderr.length < MAX_OUTPUT_SIZE) {
            stderr += data.toString();
            if (stderr.length >= MAX_OUTPUT_SIZE) {
              stderr = stderr.slice(0, MAX_OUTPUT_SIZE);
              outputTruncated = true;
            }
          }
        });

        stream.on("close", (code: number) => {
          if (timedOut) return;
          clearTimeout(timer);

          let finalStdout = stdout.trim();
          if (outputTruncated) {
            finalStdout += "\n\n[OUTPUT TRUNCATED - exceeded 10MB limit]";
          }

          resolve({
            stdout: finalStdout,
            stderr: stderr.trim(),
            exitCode: code,
          });
        });
      });
    });
  }

  async writeFile(remotePath: string, content: Buffer): Promise<void> {
    const client = await this.connect();

    return new Promise((resolve, reject) => {
      client.sftp((err, sftp) => {
        if (err) {
          return reject(new Error(`SFTP error: ${err.message}`));
        }

        const writeStream = sftp.createWriteStream(remotePath);

        writeStream.on("error", (writeErr: Error) => {
          sftp.end();
          reject(new Error(`SFTP write error: ${writeErr.message}`));
        });

        writeStream.on("close", () => {
          sftp.end();
          resolve();
        });

        writeStream.end(content);
      });
    });
  }

  async writeFileFromPath(remotePath: string, hostPath: string): Promise<void> {
    const client = await this.connect();
    const { createReadStream } = await import("fs");
    const { pipeline } = await import("stream/promises");

    return new Promise((resolve, reject) => {
      client.sftp((err, sftp) => {
        if (err) {
          return reject(new Error(`SFTP error: ${err.message}`));
        }

        const readStream = createReadStream(hostPath);
        const writeStream = sftp.createWriteStream(remotePath);

        pipeline(readStream, writeStream)
          .then(() => {
            sftp.end();
            resolve();
          })
          .catch((pipeErr) => {
            sftp.end();
            reject(new Error(`SFTP write error: ${pipeErr.message}`));
          });
      });
    });
  }

  async readFileToPath(remotePath: string, hostPath: string): Promise<void> {
    const client = await this.connect();
    const { createWriteStream } = await import("fs");
    const { pipeline } = await import("stream/promises");

    return new Promise((resolve, reject) => {
      client.sftp((err, sftp) => {
        if (err) {
          return reject(new Error(`SFTP error: ${err.message}`));
        }

        const readStream = sftp.createReadStream(remotePath);
        const writeStream = createWriteStream(hostPath);

        pipeline(readStream, writeStream)
          .then(() => {
            sftp.end();
            resolve();
          })
          .catch((pipeErr) => {
            sftp.end();
            reject(new Error(`SFTP read error: ${pipeErr.message}`));
          });
      });
    });
  }

  async disconnect(): Promise<void> {
    if (this.client) {
      this.client.end();
      this.client = null;
    }
  }
}
