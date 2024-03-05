# CLFuzz

CLFuzz is a generation-based fuzzer on cryptographic algorithms. It extracts the semantic information including cryptographic-specific constraints and function signatures of targeted algorithms, and conducts a three-stage cross-check for bug detection.

## Project Structure

Introduction of some files and directories

- `README.md`: basic information about CLFuzz
- `entry.cpp`: the fuzzing entry
- `driver.cpp`: driver for invoking targeted algorithms
- `input_generator.cpp`: the input generator for generating high-quality test input
- `recyclepool.cpp `:  the oracle recycling pools
- `modules/`: the driver for targeted libraries

## Instruction

### STEP 1:  Prepare for the Environment

Set the sanitizers and fuzzing engine link.

```
export CFLAGS="-fsanitize=address,undefined,fuzzer-no-link -O2 -g"
export CXXFLAGS="-fsanitize=address,undefined,fuzzer-no-link -D_GLIBCXX_DEBUG -O2 -g"
export LIBFUZZER_LINK="-fsanitize=fuzzer"
```

### STEP 1:  Generate Headers

Run:

```
python gen_repository.py
```

### STEP 2: Build the Modules

To build the driver for each targeted module, follow the steps:

1. Compile the library into a static library file.
2. Specify the required environment variables.
3. Enter the directory for each library under `modules/`
4. Make the driver

For example, when building Cryptopp, the steps are:

1. Compile Cryptopp:

```
git clone --depth 1 https://github.com/weidai11/cryptopp/
cd cryptopp/
make libcryptopp.a -j$(nproc)
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_CRYPTOPP"
export LIBCRYPTOPP_A_PATH=`realpath libcryptopp.a`
export CRYPTOPP_INCLUDE_PATH=`realpath .`
```

2. Build the Driver:

```
cd CLFuzz/modules/cryptopp/
make
```

### STEP 3: Build CLFuzz

Enter the root location of CLFuzz and execute:

```
make
```

This operation will generate the executable file `CLFuzz`.

Execute it through:

```
./CLFuzz
```

For some supported options, see [Libfuzzer](https://llvm.org/docs/LibFuzzer.html).