export interface ExecOptions {
  timeout?: number;
  cwd?: string;
}

export interface ExecResult {
  stdout: string;
  stderr: string;
  exitCode: number;
}

export interface Connector {
  execute(command: string[], options?: ExecOptions): Promise<ExecResult>;
  executeShell(command: string, options?: ExecOptions): Promise<ExecResult>;
  writeFile(remotePath: string, content: Buffer): Promise<void>;
  writeFileFromPath(remotePath: string, hostPath: string): Promise<void>;
  readFileToPath(remotePath: string, hostPath: string): Promise<void>;
  disconnect(): Promise<void>;
}

export interface ConnectorConfig {
  mode: "docker" | "ssh" | "local";
  container?: string;
  host?: string;
  user?: string;
  port?: number;
  password?: string;
}

export async function createConnector(config: ConnectorConfig): Promise<Connector> {
  switch (config.mode) {
    case "docker":
      const { DockerConnector } = await import("./docker.js");
      return new DockerConnector(config.container || "remnux");

    case "ssh":
      const { SSHConnector } = await import("./ssh.js");
      if (!config.host) throw new Error("SSH mode requires --host");
      return new SSHConnector({
        host: config.host,
        user: config.user || "remnux",
        port: config.port || 22,
        ...(config.password ? { password: config.password } : {}),
      });

    case "local":
      const { LocalConnector } = await import("./local.js");
      return new LocalConnector();

    default:
      throw new Error(`Unknown connection mode: ${config.mode}`);
  }
}
