import type { Connector } from "../connectors/index.js";
import type { SessionState } from "../state/session.js";

export interface HandlerConfig {
  samplesDir: string;
  outputDir: string;
  timeout: number;
  noSandbox: boolean;
  mode: "docker" | "ssh" | "local";
  transport?: "stdio" | "http";
}

export interface HandlerDeps {
  connector: Connector;
  config: HandlerConfig;
  sessionState: SessionState;
}
