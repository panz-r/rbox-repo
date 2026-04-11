#ifndef PATTERN_SERIALIZER_H
#define PATTERN_SERIALIZER_H

#include <string>
#include <memory>

struct PatternNode;

std::string serializePattern(std::shared_ptr<PatternNode> node);

#endif // PATTERN_SERIALIZER_H
