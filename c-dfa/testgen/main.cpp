#include <iostream>
#include <string>
#include <cstring>
#include <sys/stat.h>
#include <libgen.h>
#include "testgen.h"

void printUsage(const char* prog) {
    std::cout << "Usage: " << prog << " [options]\n";
    std::cout << "\nOptions:\n";
    std::cout << "  -n N          Number of tests (default: 100)\n";
    std::cout << "  -o DIR        Output directory (default: output)\n";
    std::cout << "  -s SEED       Random seed\n";
    std::cout << "  -c LEVEL      Complexity: simple, medium, complex, mixed (default: mixed)\n";
    std::cout << "  -r            Run tests through c-dfa\n";
    std::cout << "  -k            Keep generated files\n";
    std::cout << "  -h            Show this help\n";
}

int main(int argc, char* argv[]) {
    Options opts;
    bool run_tests = false;
    bool keep_files = false;
    std::string output_dir = "output";
    
    // Parse arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-n") == 0 && i + 1 < argc) {
            opts.num_tests = std::stoi(argv[++i]);
        } else if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            output_dir = argv[++i];
        } else if (strcmp(argv[i], "-s") == 0 && i + 1 < argc) {
            opts.seed = std::stoi(argv[++i]);
        } else if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) {
            std::string c = argv[++i];
            if (c == "simple") opts.complexity = Complexity::SIMPLE;
            else if (c == "medium") opts.complexity = Complexity::MEDIUM;
            else if (c == "complex") opts.complexity = Complexity::COMPLEX;
            else if (c == "mixed") opts.complexity = Complexity::MEDIUM;  // Default to medium for mixed
        } else if (strcmp(argv[i], "-r") == 0) {
            run_tests = true;
        } else if (strcmp(argv[i], "-k") == 0) {
            keep_files = true;
        } else if (strcmp(argv[i], "-h") == 0) {
            printUsage(argv[0]);
            return 0;
        }
    }
    
    opts.output_dir = output_dir;
    opts.run_tests = run_tests;
    opts.keep_files = keep_files;
    
    std::cout << "TestGen - Grammar-based test case generator for c-dfa\n";
    std::cout << "====================================================\n\n";
    
    // Create output directory
    mkdir(output_dir.c_str(), 0755);
    
    // Generate test cases
    TestGenerator gen(opts);
    std::cout << "Generating " << opts.num_tests << " test cases...\n";
    auto tests = gen.generate();
    std::cout << "Generated " << tests.size() << " test cases\n\n";
    
    // Write files
    std::string pattern_file = output_dir + "/patterns.txt";
    std::string expectations_file = output_dir + "/expectations.json";
    
    gen.writePatternFile(tests, pattern_file);
    gen.writeExpectations(tests, expectations_file);
    
    std::cout << "\nGenerated files:\n";
    std::cout << "  Pattern file: " << pattern_file << "\n";
    std::cout << "  Expectations: " << expectations_file << "\n";
    
    if (run_tests) {
        gen.runTests(pattern_file, expectations_file);
    } else {
        std::cout << "\nSkipping test run (use -r to execute)\n";
        std::cout << "\nTo test manually:\n";
        std::cout << "  cd ..\n";
        std::cout << "  ./tools/nfa_builder " << pattern_file << " test.nfa\n";
        std::cout << "  ./tools/nfa2dfa_advanced test.nfa test.dfa\n";
        std::cout << "  ./tools/dfa_eval_wrapper test.dfa '<input>'\n";
    }
    
    return 0;
}
