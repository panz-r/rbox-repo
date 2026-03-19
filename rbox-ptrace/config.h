/*
 * config.h - Portability definitions for readonlybox-ptrace
 *
 * This header provides fallbacks and portability definitions for
 * systems that may lack certain GNU/Linux or glibc extensions.
 */

#ifndef CONFIG_H
#define CONFIG_H

/* Fallback for PATH_MAX if not defined */
#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

/* Fallback for __WALL (Linux-specific waitpid flag)
 * If not defined by the system headers, use the typical Linux value.
 * Note: This value could theoretically vary, but on all Linux kernels
 * to date, __WALL is 0x40000000. */
#ifndef __WALL
#define __WALL 0x40000000
#endif

/* Determine if we have clearenv() from glibc */
#ifdef __GLIBC__
#define HAVE_CLEARENV 1
#else
#define HAVE_CLEARENV 0
#endif

#endif /* CONFIG_H */
