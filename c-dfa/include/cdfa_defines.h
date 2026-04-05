/**
 * cdfa_defines.h - Compiler and platform attribute macros
 */

#ifndef CDFA_DEFINES_H
#define CDFA_DEFINES_H

#if defined(__GNUC__) || defined(__clang__)
#define ATTR_UNUSED __attribute__((unused))
#define ATTR_MAYBE_UNUSED __attribute__((unused))

#define ATTR_NONNULL(...) __attribute__((nonnull(__VA_ARGS__)))

#else
#define ATTR_UNUSED
#define ATTR_MAYBE_UNUSED
#define ATTR_NONNULL(...)
#endif

#define ATTR_NONNULL_ALL __attribute__((nonnull))

#endif // CDFA_DEFINES_H
