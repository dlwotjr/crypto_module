#pragma once

/* Run all test vectors in a KAT file.
 * mode    : ARIA_ECB_MODE / ARIA_CBC_MODE / ARIA_CTR_MODE / ARIA_CFB64_MODE / ARIA_OFB_MODE
 * keyBits : 128 / 192 / 256
 * Returns number of failed test vectors (0 = all passed).
 */
int kat_run_file(const char *filepath, int mode, int keyBits);
