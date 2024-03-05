all : clfuzz

CXXFLAGS += -Wall -Wextra -std=c++17 -I include/ -I . -I fuzzing-headers/include -DFUZZING_HEADERS_NO_IMPL

driver.o : driver.cpp
	$(CXX) $(CXXFLAGS) driver.cpp -c -o driver.o
executor.o : executor.cpp config.h
	$(CXX) $(CXXFLAGS) executor.cpp -c -o executor.o
util.o : util.cpp
	$(CXX) $(CXXFLAGS) util.cpp -c -o util.o
entry.o : entry.cpp extra_options.h
	$(CXX) $(CXXFLAGS) entry.cpp -c -o entry.o
operation.o : operation.cpp
	$(CXX) $(CXXFLAGS) operation.cpp -c -o operation.o
tests.o : tests.cpp
	$(CXX) $(CXXFLAGS) tests.cpp -c -o tests.o
datasource.o : datasource.cpp
	$(CXX) $(CXXFLAGS) datasource.cpp -c -o datasource.o
repository_tbl.h : gen_repository.py
	python gen_repository.py
repository.o : repository.cpp repository_tbl.h
	$(CXX) $(CXXFLAGS) repository.cpp -c -o repository.o
options.o : options.cpp
	$(CXX) $(CXXFLAGS) options.cpp -c -o options.o
components.o : components.cpp config.h
	$(CXX) $(CXXFLAGS) components.cpp -c -o components.o
wycheproof.o : wycheproof.cpp
	$(CXX) $(CXXFLAGS) wycheproof.cpp -c -o wycheproof.o
crypto.o : crypto.cpp
	$(CXX) $(CXXFLAGS) crypto.cpp -c -o crypto.o
input_generator.o : input_generator.cpp config.h
	$(CXX) $(CXXFLAGS) input_generator.cpp -c -o input_generator.o
numbers.o : numbers.cpp
	$(CXX) $(CXXFLAGS) -O0 numbers.cpp -c -o numbers.o
mutatorpool : mutatorpool.cpp
	$(CXX) $(CXXFLAGS) mutatorpool.cpp -c -o mutatorpool.o
ecc_diff_fuzzer_importer.o : ecc_diff_fuzzer_importer.cpp
	$(CXX) $(CXXFLAGS) ecc_diff_fuzzer_importer.cpp -c -o ecc_diff_fuzzer_importer.o
botan_importer.o : botan_importer.cpp
	$(CXX) $(CXXFLAGS) botan_importer.cpp -c -o botan_importer.o

third_party/cpu_features/build/libcpu_features.a :
	cd third_party/cpu_features && rm -rf build && mkdir build && cd build && cmake .. && make

clfuzz : driver.o executor.o util.o entry.o tests.o operation.o datasource.o repository.o options.o components.o wycheproof.o crypto.o input_generator.o numbers.o mutatorpool.o ecc_diff_fuzzer_importer.o botan_importer.o third_party/cpu_features/build/libcpu_features.a
	test $(LIBFUZZER_LINK)
	$(CXX) $(CXXFLAGS) driver.o executor.o util.o entry.o tests.o operation.o datasource.o repository.o options.o components.o wycheproof.o crypto.o input_generator.o numbers.o mutatorpool.o ecc_diff_fuzzer_importer.o botan_importer.o $(shell find modules -type f -name module.a) $(LIBFUZZER_LINK) third_party/cpu_features/build/libcpu_features.a $(LINK_FLAGS) -o clfuzz

clean:
	rm -rf driver.o executor.o util.o entry.o operation.o tests.o datasource.o repository.o options.o components.o wycheproof.o crypto.o numbers.o mutatorpool.o mutator.o ecc_diff_fuzzer_importer.o botan_importer.o cryptofuzz emptyResultCount.txt validResultCount.txt executionCount.txt runningCount.txt getModuleCount.txt getUnexistedModuleCount.txt getValidModuleCount.txt enterRunningCount.txt

cleanTxtMarks:
	rm -rf emptyResultCount.txt executionCount.txt runningCount.txt getModuleCount.txt getUnexistedModuleCount.txt getValidModuleCount.txt enterRunningCount.txt validResultCount.txt saved_seeds/*
