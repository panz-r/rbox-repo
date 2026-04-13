#include <iostream>
#include <string>
#include <cstring>
#include <sys/stat.h>
#include <unistd.h>
#include <libgen.h>
#include "testgen.h"
#include "command_utils.h"

void printUsage(const char* prog) {
    std::cout << "Usage: " << prog << " [options]\n";
    std::cout << "\nOptions:\n";
    std::cout << "  -n N          Number of tests (default: 100, max 4 for combined testing)\n";
    std::cout << "  -o DIR        Output directory (default: output)\n";
    std::cout << "  -s SEED       Random seed\n";
    std::cout << "  -c LEVEL      Complexity: simple, medium, complex, mixed (default: mixed)\n";
    std::cout << "  -m N          Mutations per test case (default: 10, 0 to disable)\n";
    std::cout << "  -r            Run tests through c-dfa\n";
    std::cout << "  -k            Keep generated files\n";
    std::cout << "  -h, --help    Show this help\n";
}

int main(int argc, char* argv[]) {
    Options opts;
    bool run_tests = false;
    bool keep_files = false;
    std::string output_dir = "output";
    
    // Parse arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-n") == 0 || strcmp(argv[i], "--num-tests") == 0) {
            if (i + 1 < argc) opts.num_tests = std::stoi(argv[++i]);
        } else if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            output_dir = argv[++i];
        } else if (strcmp(argv[i], "-s") == 0 && i + 1 < argc) {
            opts.seed = std::stoi(argv[++i]);
        } else if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) {
            std::string c = argv[++i];
            if (c == "simple") opts.complexity = Complexity::SIMPLE;
            else if (c == "medium") opts.complexity = Complexity::MEDIUM;
            else if (c == "complex") opts.complexity = Complexity::COMPLEX;
            else if (c == "mixed") opts.complexity = Complexity::MEDIUM;
        } else if (strcmp(argv[i], "-m") == 0 || strcmp(argv[i], "--mutations") == 0) {
            if (i + 1 < argc) opts.mutations_per_test = std::stoi(argv[++i]);
        } else if (strcmp(argv[i], "-r") == 0) {
            run_tests = true;
        } else if (strcmp(argv[i], "-k") == 0) {
            keep_files = true;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            printUsage(argv[0]);
            return 0;
        }
    }
    
    opts.output_dir = output_dir;
    opts.run_tests = run_tests;
    opts.keep_files = keep_files;
    
    std::cout << "TestGen - Grammar-based test case generator for c-dfa\n";
    std::cout << "====================================================\n\n";
    
    // Get current working directory for passing to runTests
    char cwd[1024];
    if (getcwd(cwd, sizeof(cwd)) == nullptr) {
        std::cerr << "Cannot get current directory\n";
        return 1;
    }
    std::string cwd_str = cwd;
    
    // Create output directory
    mkdir(output_dir.c_str(), 0755);
    
    // Calculate how many files we need (4 tests per file, limited by capture tags)
    int tests_per_file = 4;
    int num_files = (opts.num_tests + tests_per_file - 1) / tests_per_file;
    
    std::cout << "Generating " << opts.num_tests << " test cases in " << num_files << " file(s)...\n\n";
    
    int total_passed = 0;
    int total_failed = 0;
    int total_skipped = 0;
    int file_num = 0;
    
    for (int file_num = 0; file_num < num_files; file_num++) {
        // Adjust seed for each batch
        opts.seed = opts.seed + file_num * tests_per_file;
        
        // Generate test cases for this batch (max 8 for more complex combined DFAs)
        TestGenerator gen(opts);
        int num_in_batch = std::min(tests_per_file, opts.num_tests - file_num * tests_per_file);
        gen.setTestsPerBatch(tests_per_file);
        auto tests = gen.generate();
        
        std::cout << "--- Batch " << (file_num + 1) << ": " << tests.size() << " test cases ---\n";
        
        // Write files with batch number
        std::string batch_suffix = (num_files > 1) ? "_" + std::to_string(file_num) : "";
        std::string pattern_file = output_dir + "/patterns" + batch_suffix + ".txt";
        std::string expectations_file = output_dir + "/expectations" + batch_suffix + ".json";
        
        gen.writePatternFile(tests, pattern_file);
        gen.writeExpectations(tests, expectations_file);
        
        std::cout << "  Pattern file: " << pattern_file << "\n";
        
        if (run_tests) {
            int batch_passed = 0, batch_failed = 0, batch_skipped = 0;
            gen.runTests(tests, cwd_str, getToolsDir(), pattern_file, expectations_file,
                        &batch_passed, &batch_failed, &batch_skipped);
            total_passed += batch_passed;
            total_failed += batch_failed;
            total_skipped += batch_skipped;
        }
    }
    
    if (!run_tests) {
        std::cout << "\nSkipping test run (use -r to execute)\n";
    } else {
        std::cout << "\n=== TOTAL: " << total_passed << " passed, " << total_failed << " failed, " << total_skipped << " skipped ===\n";
    }
    
    return 0;
}
