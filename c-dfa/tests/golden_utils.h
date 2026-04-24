/**
 * golden_utils.h - Shared golden file utilities for tests
 *
 * Provides portable path resolution and file loading for golden file comparisons.
 */

#ifndef GOLDEN_UTILS_H
#define GOLDEN_UTILS_H

#include <stdbool.h>

/**
 * Get path to golden directory.
 * Auto-detects working directory for both CTest and direct runs.
 * When run via CTest: working dir is c-dfa/, so use "golden/<subdir>"
 * When run directly from build/tests/: use "../golden/<subdir>"
 */
const char* golden_get_dir(const char* subdir);

/**
 * Load golden file into malloc'd string.
 * Returns NULL if file cannot be opened.
 */
char* golden_load(const char* dir, const char* filename);

#endif /* GOLDEN_UTILS_H */
