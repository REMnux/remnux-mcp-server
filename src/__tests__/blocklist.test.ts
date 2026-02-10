/**
 * Security tests for blocklist.ts
 *
 * Threat model: REMnux is disposable. These tests verify that anti-injection
 * patterns block prompt injection attacks while allowing all legitimate
 * malware analysis commands — including destructive ones.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdirSync, rmdirSync, writeFileSync, unlinkSync, symlinkSync, existsSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";
import {
  BLOCKED_PATTERNS,
  DANGEROUS_PIPE_PATTERNS,
  isPathSafe,
  isSymlink,
  validateFilePath,
  isCommandSafe,
} from "../security/blocklist.js";

describe("BLOCKED_PATTERNS", () => {
  // Helper to check if any pattern matches
  const isBlocked = (input: string): boolean =>
    BLOCKED_PATTERNS.some(({ pattern }) => pattern.test(input));

  describe("Control character injection (anti-injection)", () => {
    it("should block null bytes", () => {
      // Null bytes truncate paths in C-based functions - actual injection vector
      expect(isBlocked("file\x00name")).toBe(true);
    });

    it("should allow newlines and carriage returns (container handles isolation)", () => {
      // Newlines enable multi-command execution, but:
      // 1. AI can already do this via multiple tool calls
      // 2. Container isolation is the security boundary
      expect(isBlocked("strings sample.exe\nfile sample.exe")).toBe(false);
      expect(isBlocked("test\rcommand")).toBe(false);
    });
  });

  describe("Shell expansion (now allowed — container isolation)", () => {
    it("should allow backtick command substitution", () => {
      expect(isBlocked("`whoami`")).toBe(false);
      expect(isBlocked("file `id`")).toBe(false);
    });

    it("should allow $() command substitution", () => {
      expect(isBlocked("$(whoami)")).toBe(false);
      expect(isBlocked("--output=$(id)")).toBe(false);
    });

    it("should allow ${} variable expansion", () => {
      expect(isBlocked("${PATH}")).toBe(false);
      expect(isBlocked("file${IFS}injection")).toBe(false);
    });

    it("should allow simple $VAR (for-loops and legitimate shell)", () => {
      expect(isBlocked("echo $SECRET")).toBe(false);
      expect(isBlocked('for f in extracted/*; do file "$f"; done')).toBe(false);
      expect(isBlocked("file --output=$HOME/file")).toBe(false);
    });

    it("should allow special variables ($?, $$, $0 — read-only)", () => {
      expect(isBlocked('echo "Exit: $?"')).toBe(false);
      expect(isBlocked("echo $$")).toBe(false);
      expect(isBlocked("echo $!")).toBe(false);
      expect(isBlocked("echo $0")).toBe(false);
      expect(isBlocked("echo $@")).toBe(false);
      expect(isBlocked("echo $#")).toBe(false);
      expect(isBlocked("echo $1")).toBe(false);
    });
  });

  describe("Catastrophic command guard (protects analysis session)", () => {
    it("should block rm -rf / (root wipe)", () => {
      expect(isBlocked("rm -rf /")).toBe(true);
      expect(isBlocked("rm -rf /*")).toBe(true);
      expect(isBlocked("rm -Rf /")).toBe(true);
    });

    it("should allow rm -rf on subdirectories", () => {
      expect(isBlocked("rm -rf subdir/")).toBe(false);
      expect(isBlocked("rm -rf /tmp/analysis")).toBe(false);
    });

    it("should block mkfs", () => {
      expect(isBlocked("mkfs /dev/sda")).toBe(true);
      expect(isBlocked("mkfs.ext4 /dev/sda1")).toBe(true);
    });
  });

  describe("Deliberately NOT blocked (container is disposable)", () => {
    // Process substitution REMOVED (2026-02): Same threat class as pipe-to-interpreter
    // (already allowed). Container/VM isolation handles the risk.
    it("should allow <() process substitution (container isolation)", () => {
      expect(isBlocked("diff <(cat file1) <(cat file2)")).toBe(false);
      expect(isBlocked("cat <(echo test)")).toBe(false);
    });

    it("should allow >() process substitution (container isolation)", () => {
      expect(isBlocked("cat file | tee >(wc -l)")).toBe(false);
    });

    it("should allow heredocs containing comparison operators with parentheses", () => {
      // Previously false-positive: < (expr) in Python code matched process substitution regex
      expect(isBlocked("python3 << 'EOF'\nif x < (y + 1):\n    pass\nEOF")).toBe(false);
      expect(isBlocked("python3 << 'EOF'\nif x > (y - 1):\n    pass\nEOF")).toBe(false);
    });

    // eval/exec/source REMOVED (2026-02): Same threat class as pipe-to-interpreter
    // (already allowed). Container/VM isolation handles the risk.
    it("should allow eval (container isolation)", () => {
      expect(isBlocked("eval 'echo hello'")).toBe(false);
      expect(isBlocked("eval malicious")).toBe(false);
    });

    it("should allow exec (container isolation)", () => {
      expect(isBlocked("exec /bin/sh")).toBe(false);
      expect(isBlocked("find . -name '*.exe' -exec file {} \\;")).toBe(false);
      expect(isBlocked("find /path -exec strings {} \\;")).toBe(false);
    });

    it("should allow source (container isolation)", () => {
      expect(isBlocked("source /tmp/script.sh")).toBe(false);
      expect(isBlocked("source script.sh")).toBe(false);
    });

    it("should allow grep for eval/exec/source (search, not execution)", () => {
      expect(isBlocked("strings sample.exe | grep -iE '(eval|exec|source)'")).toBe(false);
      expect(isBlocked("grep -c exec /tmp/script.sh")).toBe(false);
      expect(isBlocked("grep -i eval /path/to/file")).toBe(false);
    });

    it("should allow sudo (container isolation handles this)", () => {
      expect(isBlocked("sudo apt install")).toBe(false);
    });

    it("should allow chmod/chown", () => {
      expect(isBlocked("chmod 777 file")).toBe(false);
      expect(isBlocked("chown root file")).toBe(false);
    });

    it("should allow apt/pip/npm install", () => {
      expect(isBlocked("apt install nmap")).toBe(false);
      expect(isBlocked("pip install yara-python")).toBe(false);
      expect(isBlocked("npm install")).toBe(false);
    });

    it("should allow systemctl/service", () => {
      expect(isBlocked("systemctl restart docker")).toBe(false);
      expect(isBlocked("service ssh start")).toBe(false);
    });

    it("should allow /etc, /proc, /sys, /dev access", () => {
      expect(isBlocked("cat /etc/passwd")).toBe(false);
      expect(isBlocked("cat /proc/self/maps")).toBe(false);
      expect(isBlocked("ls /sys/kernel")).toBe(false);
      expect(isBlocked("dd if=/dev/sda bs=512 count=1")).toBe(false);
    });

    it("should allow mount, iptables, crontab", () => {
      expect(isBlocked("mount /dev/sda /mnt")).toBe(false);
      expect(isBlocked("iptables -L")).toBe(false);
      expect(isBlocked("crontab -l")).toBe(false);
    });

    it("should allow nohup, screen, tmux", () => {
      expect(isBlocked("nohup command &")).toBe(false);
      expect(isBlocked("screen -ls")).toBe(false);
      expect(isBlocked("tmux new")).toBe(false);
    });

    it("should allow dd (forensics tool)", () => {
      expect(isBlocked("dd if=/dev/sda of=disk.img bs=4096")).toBe(false);
    });
  });

  describe("Legitimate analysis commands", () => {
    it("should allow standard analysis tools", () => {
      expect(isBlocked("file sample.exe")).toBe(false);
      expect(isBlocked("strings sample.exe")).toBe(false);
      expect(isBlocked("olevba document.doc")).toBe(false);
      expect(isBlocked("capa sample.exe")).toBe(false);
      expect(isBlocked("pdfid.py document.pdf")).toBe(false);
    });

    it("should allow safe piped commands", () => {
      expect(isBlocked("strings sample.exe | grep password")).toBe(false);
      expect(isBlocked("oledump.py sample.doc | head -20")).toBe(false);
      expect(isBlocked("hexdump -C sample.bin | grep -i magic")).toBe(false);
    });

    it("should allow vol3 commands", () => {
      expect(isBlocked("vol3 -f image.raw windows.info")).toBe(false);
      expect(isBlocked("vol3 -f image.raw windows.pslist")).toBe(false);
    });

    it("should allow for-loops with $var (iterating over extracted files)", () => {
      // This was previously blocked but is essential for analysis workflows
      expect(isBlocked('for f in extracted/*; do file "$f"; done')).toBe(false);
      expect(isBlocked('for i in *.dll; do strings "$i" | grep -i import; done')).toBe(false);
    });

    it("should allow python one-liners with newlines", () => {
      // Newlines inside quoted strings are safe - needed for python -c analysis
      expect(isBlocked('python3 -c "import re\\nprint(re.findall(r\\"Set (\\\\w+)=\\", open(\\"/tmp/test.txt\\").read()))"')).toBe(false);
    });
  });
});

describe("DANGEROUS_PIPE_PATTERNS", () => {
  const isDangerousPipe = (input: string): boolean =>
    DANGEROUS_PIPE_PATTERNS.some(({ pattern }) => pattern.test(input));

  // Pipe-to-interpreter patterns were REMOVED in 2026-02
  // Container/VM isolation is the security boundary, not pipe blocking.
  // These tests document that pipes to interpreters are NOW ALLOWED.

  describe("Pipes to interpreters (now allowed - container isolation)", () => {
    it("should allow pipe to sh/bash", () => {
      expect(isDangerousPipe("cat file | sh")).toBe(false);
      expect(isDangerousPipe("cat file | bash")).toBe(false);
    });

    it("should allow pipe to python", () => {
      expect(isDangerousPipe("cat file | python")).toBe(false);
      expect(isDangerousPipe("cat file | python3")).toBe(false);
    });

    it("should allow pipe to other interpreters", () => {
      expect(isDangerousPipe("cat file | perl")).toBe(false);
      expect(isDangerousPipe("cat file | ruby")).toBe(false);
      expect(isDangerousPipe("cat file | node")).toBe(false);
      expect(isDangerousPipe("cat file | php")).toBe(false);
      expect(isDangerousPipe("cat file | lua")).toBe(false);
      expect(isDangerousPipe("cat file | zsh")).toBe(false);
      expect(isDangerousPipe("cat file | fish")).toBe(false);
    });

    it("should allow heredocs piped to interpreters", () => {
      expect(isDangerousPipe("cat << 'EOF' | python3\nprint('hello')\nEOF")).toBe(false);
      expect(isDangerousPipe("cat << 'EOF' | bash\necho hello\nEOF")).toBe(false);
    });
  });

  describe("Safe analysis pipes (always allowed)", () => {
    it("should allow pipe to tee (saving output)", () => {
      expect(isDangerousPipe("strings sample.exe | tee /output/strings.txt")).toBe(false);
    });

    it("should allow pipe to xargs (batch operations)", () => {
      expect(isDangerousPipe("find . -name '*.dll' | xargs file")).toBe(false);
    });

    it("should allow pipe to dd (byte carving)", () => {
      expect(isDangerousPipe("cat image.raw | dd bs=512 count=1")).toBe(false);
    });

    it("should allow pipe to sudo/su (container isolation)", () => {
      expect(isDangerousPipe("echo password | sudo tee /etc/file")).toBe(false);
    });

    it("should allow curl/wget piped", () => {
      expect(isDangerousPipe("curl http://example.com | grep title")).toBe(false);
    });

    it("should allow pipe to env", () => {
      expect(isDangerousPipe("cat data | env")).toBe(false);
    });

    it("should allow grep pipes", () => {
      expect(isDangerousPipe("strings sample.exe | grep password")).toBe(false);
    });

    it("should allow head/tail pipes", () => {
      expect(isDangerousPipe("oledump.py sample.doc | head -20")).toBe(false);
      expect(isDangerousPipe("strings sample.exe | tail -50")).toBe(false);
    });

    it("should allow sort/uniq/wc/cut pipes", () => {
      expect(isDangerousPipe("strings sample.exe | sort | uniq")).toBe(false);
      expect(isDangerousPipe("strings sample.exe | wc -l")).toBe(false);
      expect(isDangerousPipe("file sample.bin | cut -d: -f2")).toBe(false);
    });
  });
});

describe("isCommandSafe", () => {
  describe("should reject empty and whitespace commands", () => {
    it("rejects empty command", () => {
      const result = isCommandSafe("");
      expect(result.safe).toBe(false);
      expect(result.error).toBe("Empty command");
    });

    it("rejects whitespace-only command", () => {
      const result = isCommandSafe("   ");
      expect(result.safe).toBe(false);
    });
  });

  describe("shell expansion and code execution (container isolation)", () => {
    it("allows simple $VAR (for-loops and legitimate shell)", () => {
      // Simple $var is now allowed - see threat model review
      const result = isCommandSafe("echo $SECRET");
      expect(result.safe).toBe(true);
    });

    it("allows special variables like $? (read-only, no injection risk)", () => {
      expect(isCommandSafe('echo "Exit: $?"').safe).toBe(true);
      expect(isCommandSafe("tmpfile=/tmp/out.$$").safe).toBe(true);
    });

    it("allows ${} variable expansion (container isolation)", () => {
      expect(isCommandSafe("echo ${PATH}").safe).toBe(true);
    });

    it("allows eval (container isolation)", () => {
      expect(isCommandSafe("eval 'echo hello'").safe).toBe(true);
    });

    it("allows pipe to bash (container isolation)", () => {
      expect(isCommandSafe("cat script.sh | bash").safe).toBe(true);
    });

    it("allows pipe to python (container isolation)", () => {
      expect(isCommandSafe("cat script.py | python").safe).toBe(true);
    });
  });

  describe("should accept all legitimate commands", () => {
    it("accepts analysis tools", () => {
      expect(isCommandSafe("strings sample.exe").safe).toBe(true);
      expect(isCommandSafe("olevba document.doc").safe).toBe(true);
      expect(isCommandSafe("capa sample.exe").safe).toBe(true);
    });

    it("accepts safe piped commands", () => {
      expect(isCommandSafe("strings sample.exe | grep password").safe).toBe(true);
      expect(isCommandSafe("oledump.py sample.doc | head -20").safe).toBe(true);
    });

    it("accepts tee, xargs, dd pipes", () => {
      expect(isCommandSafe("strings sample.exe | tee /output/out.txt").safe).toBe(true);
      expect(isCommandSafe("find . -name '*.dll' | xargs file").safe).toBe(true);
      expect(isCommandSafe("cat image.raw | dd bs=512 count=1 of=mbr.bin").safe).toBe(true);
    });

    it("accepts system commands (container is disposable)", () => {
      expect(isCommandSafe("sudo apt install nmap").safe).toBe(true);
      expect(isCommandSafe("chmod +x script.sh").safe).toBe(true);
      expect(isCommandSafe("cat /etc/passwd").safe).toBe(true);
      expect(isCommandSafe("dd if=/dev/sda of=disk.img bs=4096").safe).toBe(true);
    });
  });
});

describe("isPathSafe", () => {
  const baseDir = "/home/remnux/files/samples";

  describe("should reject unsafe paths", () => {
    it("rejects absolute paths", () => {
      expect(isPathSafe("/etc/passwd", baseDir)).toBe(false);
      expect(isPathSafe("/tmp/test", baseDir)).toBe(false);
    });

    it("rejects path traversal with ../", () => {
      expect(isPathSafe("../../../etc/passwd", baseDir)).toBe(false);
      expect(isPathSafe("subdir/../../../etc/passwd", baseDir)).toBe(false);
    });

    it("rejects null bytes", () => {
      expect(isPathSafe("file\x00.txt", baseDir)).toBe(false);
    });

    it("rejects shell special characters", () => {
      expect(isPathSafe("file;rm -rf /", baseDir)).toBe(false);
      expect(isPathSafe("file|cat /etc/passwd", baseDir)).toBe(false);
      expect(isPathSafe("file&whoami", baseDir)).toBe(false);
      expect(isPathSafe("file`id`", baseDir)).toBe(false);
      expect(isPathSafe("file$(whoami)", baseDir)).toBe(false);
    });

    it("rejects newlines", () => {
      expect(isPathSafe("file\nrm -rf /", baseDir)).toBe(false);
      expect(isPathSafe("file\rcommand", baseDir)).toBe(false);
    });

    it("rejects home directory references", () => {
      expect(isPathSafe("~/secrets", baseDir)).toBe(false);
    });
  });

  describe("should accept safe paths", () => {
    it("accepts simple filenames", () => {
      expect(isPathSafe("sample.exe", baseDir)).toBe(true);
      expect(isPathSafe("malware.bin", baseDir)).toBe(true);
    });

    it("accepts relative paths within sandbox", () => {
      expect(isPathSafe("subdir/sample.exe", baseDir)).toBe(true);
    });

    it("accepts filenames with safe special chars", () => {
      expect(isPathSafe("file-name.txt", baseDir)).toBe(true);
      expect(isPathSafe("file_name.txt", baseDir)).toBe(true);
      expect(isPathSafe("file.name.txt", baseDir)).toBe(true);
    });
  });

  describe("edge cases", () => {
    it("handles empty string", () => {
      expect(isPathSafe("", baseDir)).toBe(false);
    });

    it("handles path that normalizes to traversal", () => {
      expect(isPathSafe("foo/../../bar", baseDir)).toBe(false);
    });
  });
});

describe("isSymlink and validateFilePath", () => {
  const tempDir = join(tmpdir(), `remnux-test-${Date.now()}`);
  const regularFile = join(tempDir, "regular.txt");
  const symlinkFile = join(tempDir, "link.txt");
  const targetFile = join(tempDir, "target.txt");

  beforeEach(() => {
    mkdirSync(tempDir, { recursive: true });
    writeFileSync(targetFile, "target content");
    writeFileSync(regularFile, "regular content");
    try {
      symlinkSync(targetFile, symlinkFile);
    } catch (_e) {
      // Symlink might fail on some systems
    }
  });

  afterEach(() => {
    try {
      if (existsSync(symlinkFile)) unlinkSync(symlinkFile);
      if (existsSync(regularFile)) unlinkSync(regularFile);
      if (existsSync(targetFile)) unlinkSync(targetFile);
      if (existsSync(tempDir)) rmdirSync(tempDir);
    } catch (_e) {
      // Ignore cleanup errors
    }
  });

  describe("isSymlink", () => {
    it("returns false for regular files", () => {
      expect(isSymlink(regularFile)).toBe(false);
    });

    it("returns true for symlinks", () => {
      if (existsSync(symlinkFile)) {
        expect(isSymlink(symlinkFile)).toBe(true);
      }
    });

    it("throws for non-existent files", () => {
      expect(() => isSymlink("/nonexistent/path")).toThrow();
    });
  });

  describe("validateFilePath", () => {
    it("accepts regular files", () => {
      const result = validateFilePath("regular.txt", tempDir);
      expect(result.safe).toBe(true);
    });

    it("accepts non-existent files", () => {
      const result = validateFilePath("newfile.txt", tempDir);
      expect(result.safe).toBe(true);
    });

    it("rejects path traversal", () => {
      const result = validateFilePath("../../../etc/passwd", tempDir);
      expect(result.safe).toBe(false);
    });
  });
});
