# Intriguer: Field-Level Constraint Solving for Hybrid Fuzzing

Intriguer is a concolic execution engine for hybrid fuzzing.
The key idea of Intriguer is a field-level constraint solving, which optimizes symbolic execution with field-level information.

## Installation

### Environment

Tested on Ubuntu 16.04 x64 (32bit binaries)

### Requirements

install deps
```console
$ sudo apt-get update
$ sudo apt-get install -y libc6 libstdc++6 linux-libc-dev gcc-multilib llvm-dev llvm-5.0 g++ g++-multilib
```

install z3

```console
$ git submodule init
$ git submodule update

$ cd third_party/z3
$ rm -rf build
$ python scripts/mk_make.py
$ cd build
$ make -j$(nproc)
$ sudo make install
```

### Build Execution Monitor

```console
$ export PIN_ROOT=/path-to-intriguer/third_party/pin-3.7-97619-0d0c92f4f/

$ cd pintool
$ make -j$(nproc)
$ TARGET=ia32 make -j$(nproc)
```

### Build Trace Analyzer

```console
$ cd traceAnalyzer
$ make -j$(nproc)
```

### Build Fuzzer

```console
$ cd intriguer_afl
$ make -j$(nproc)
```


## Running Intriguer

### Single Core

```console
$ export INTRIGUER_ROOT="Intriguer directory"
$ export INTRIGUER_CMD="command line for Intriguer (Non-instrumented)"
$ export AFL_CMD="command line for AFL (Instrumented)"
$ export INPUT="input directory"
$ export OUTPUT="output directory"

$ $INTRIGUER_ROOT/intriguer_afl/afl-fuzz -i $INPUT -o $OUTPUT -- $AFL_CMD
```

### Three Cores

```console
$ export INTRIGUER_ROOT="Intriguer directory"
$ export INTRIGUER_CMD="command line for Intriguer (Non-instrumented)"
$ export INTRIGUER_MULTICORE=1
$ export AFL_DIR="AFL directory (Vanilla)"
$ export AFL_CMD="command line for AFL (Instrumented)"
$ export INPUT="input directory"
$ export OUTPUT="output directory"

$ $AFL_DIR/afl-fuzz -M afl-master -i $INPUT -o $OUTPUT -- $AFL_CMD
$ $AFL_DIR/afl-fuzz -S afl-slave -i $INPUT -o $OUTPUT -- $AFL_CMD
$ $INTRIGUER_ROOT/intriguer_afl/afl-fuzz -S intriguer -i $INPUT -o $OUTPUT -- $AFL_CMD
```


## Authors


* Mingi Cho imgc@yonsei.ac.kr
* Seoyoung Kim kseoy4046@yonsei.ac.kr
* Taekyoung Kwon taekyoung@yonsei.ac.kr


## Publication

```
Intriguer: Field-Level Constraint Solving for Hybrid Fuzzing

@inproceedings{cho2019intriguer,
  title={{Intriguer: Field-Level Constraint Solving for Hybrid Fuzzing}},
  author={Mingi Cho and Seoyoung Kim and Taekyoung Kwon},
  booktitle={Proceedings of the 2019 ACM SIGSAC Conference on Computer and Communications Security (CCS)},
  pages={515--530},
  year={2019}
}
```
