// Leak detection off at build time (leaks are not the bug class fuzzed here); ASan and UBSan stay on.
extern "C" int __lsan_is_turned_off() { return 1; }
