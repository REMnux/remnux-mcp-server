/**
 * Shared stderr noise filtering for tool output.
 *
 * Strips common non-actionable warnings from tool stderr so they don't
 * clutter responses or confuse the AI agent.
 */

export function filterStderrNoise(stderr: string): string {
  return stderr
    // Volatility 3 progress bars
    .replace(/^Progress:\s+[\d.]+\s+.*$/gm, "")
    // Python SyntaxWarning / DeprecationWarning lines
    .replace(/^.*(?:SyntaxWarning|DeprecationWarning):.*$/gm, "")
    // Python version compatibility notices
    .replace(/^.*(?:This version of|requires Python).*$/gm, "")
    // Python source context lines (indented code following warnings)
    .replace(/^\s+\^+\s*$/gm, "")
    // webcrack per-transform debug logs (emitted to stderr on every run).
    // Non-TTY runs prefix an ISO timestamp; TTY runs use the debug lib's
    // indented "  webcrack:ns ... +12ms" format — strip both.
    .replace(/^(?:\d{4}-\d{2}-\d{2}T[\d:.]+Z )?\s*webcrack:.*$/gm, "")
    .trim();
}
