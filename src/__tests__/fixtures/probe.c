/*
 * Synthetic ground-truth fixture for verify_string_usage.
 *
 * Build (ELF):  gcc -O0 -no-pie -o probe probe.c
 *
 * Two clearly-labeled strings with KNOWN cross-reference status, so the golden
 * test can assert exact xref_status values against a real radare2 without
 * depending on any private sample:
 *   - PROBE_LIVE_... is passed to puts() -> referenced by code -> referenced_from_code
 *   - PROBE_DEAD_... is kept but never referenced by code      -> no_code_xrefs_detected
 *
 * Contains NO private data; safe to commit.
 */
#include <stdio.h>

/* Kept by the linker (used) but never referenced by any instruction. */
__attribute__((used)) static const char probe_dead[] = "PROBE_DEAD_STRING_NO_CODE_XREF_0001";

int main(void) {
    /* Literal referenced directly by code (compiler emits a lea/mov of its address). */
    puts("PROBE_LIVE_STRING_REFERENCED_BY_CODE_0001");
    return 0;
}
