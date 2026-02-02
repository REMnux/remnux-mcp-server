import { z } from "zod";

export const runToolSchema = z.object({
  command: z.string().describe("Command to execute (can include pipes, e.g., 'strings sample.exe | grep -i password')"),
  input_file: z.string().optional().describe("Input file path (relative to samples dir, or absolute path in local mode) - appended to command"),
  timeout: z.number().optional().describe("Timeout in seconds (default: 300)"),
});
export type RunToolArgs = z.infer<typeof runToolSchema>;

export const getFileInfoSchema = z.object({
  file: z.string().describe("File path relative to samples directory, or absolute path in local mode"),
});
export type GetFileInfoArgs = z.infer<typeof getFileInfoSchema>;

export const listFilesSchema = z.object({
  directory: z.enum(["samples", "output"]).default("samples").describe("Which directory to list"),
});
export type ListFilesArgs = z.infer<typeof listFilesSchema>;

export const extractArchiveSchema = z.object({
  archive_file: z.string().describe("Path to archive file relative to samples directory (e.g., 'sample.zip')"),
  password: z.string().optional().describe("Optional password to try first. If not provided, tries common passwords from built-in list."),
  output_subdir: z.string().optional().describe("Optional subdirectory name for extracted files. Defaults to archive filename without extension."),
});
export type ExtractArchiveArgs = z.infer<typeof extractArchiveSchema>;

export const uploadFromHostSchema = z.object({
  host_path: z.string().describe("Absolute path on the host filesystem to the file to upload"),
  filename: z.string().optional().describe("Override filename in samples dir (defaults to basename of host_path)"),
  overwrite: z.boolean().optional().default(false).describe("Whether to overwrite if file exists. Default: false"),
});
export type UploadFromHostArgs = z.infer<typeof uploadFromHostSchema>;

export const downloadFileSchema = z.object({
  file_path: z.string().describe("File path relative to the output directory"),
  output_path: z.string().describe("Directory on host to save the downloaded file"),
  archive: z.boolean().optional().default(true).describe(
    "Wrap the file in a password-protected archive before transfer (default: true). " +
    "Protects against AV/EDR triggers on the host. Pass false for harmless files like text reports."
  ),
});
export type DownloadFileArgs = z.input<typeof downloadFileSchema>;

export const analyzeFileSchema = z.object({
  file: z.string().describe("Filename relative to samples directory, or absolute path in local mode"),
  timeout_per_tool: z.number().optional().describe("Timeout per tool in seconds (default: 60)"),
  depth: z.enum(["quick", "standard", "deep"]).optional().default("standard").describe(
    "Analysis depth: 'quick' (fast triage tools only), 'standard' (default, all category tools), 'deep' (standard + expensive tools like full decompilation)"
  ),
});
export type AnalyzeFileArgs = z.input<typeof analyzeFileSchema>;

export const checkToolsSchema = z.object({});
export type CheckToolsArgs = z.infer<typeof checkToolsSchema>;

export const suggestToolsSchema = z.object({
  file: z.string().describe("Filename relative to samples directory, or absolute path in local mode"),
  depth: z.enum(["quick", "standard", "deep"]).optional().default("standard").describe(
    "Filter recommendations by depth tier: 'quick' (triage only), 'standard' (default), 'deep' (all tools)"
  ),
});
export type SuggestToolsArgs = z.input<typeof suggestToolsSchema>;

export const downloadFromUrlSchema = z.object({
  url: z.string().url().describe("URL to download (http or https only)"),
  filename: z.string().optional().describe(
    "Override filename in samples dir. If omitted, derived from URL path."
  ),
  headers: z.array(z.string()).optional().describe(
    "Custom HTTP headers as 'Name: value' strings. " +
    "Example: ['User-Agent: Mozilla/5.0', 'X-Auth-Token: abc123']"
  ),
  method: z.enum(["curl", "thug"]).optional().default("curl").describe(
    "Download method. 'curl' (default) for direct HTTP download. " +
    "'thug' for sites requiring JavaScript execution (uses thug honeyclient)."
  ),
  overwrite: z.boolean().optional().default(false).describe(
    "Whether to overwrite if file exists. Default: false"
  ),
  timeout: z.number().optional().describe(
    "Download timeout in seconds (default: server timeout)"
  ),
});
export type DownloadFromUrlArgs = z.input<typeof downloadFromUrlSchema>;

export const extractIOCsSchema = z.object({
  text: z.string().describe("Text to extract IOCs from (e.g., output from run_tool or analyze_file)"),
  include_noise: z.boolean().optional().default(false).describe("Include low-confidence known-good IOCs"),
});
export type ExtractIOCsArgs = z.infer<typeof extractIOCsSchema>;
