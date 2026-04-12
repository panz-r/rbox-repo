#ifndef EDGE_CASE_GEN_H
#define EDGE_CASE_GEN_H

#include "testgen.h"
#include <random>

EdgeCaseResult generateEdgeCase(EdgeCaseType type, std::mt19937& rng);

#endif // EDGE_CASE_GEN_H