# Interceptor

A small tracer written in C that attaches to a running x86-64 Linux process and changes what it executes: it sets
breakpoints, calls functions inside the traced process, injects new code into its memory and redirects an existing
function to it with a trampoline. It is built on `ptrace`, `libelf` and `/proc`.

I wrote it in the fall of 2020, as a systems programming project during the first year of my Master's at the
University of Rennes 1. Working on it is where "everything is a file" stopped being a slogan for me. The whole address
space of another process is a file, `/proc/<pid>/mem`, that you can seek into, read and write. Its memory layout is a
text file, `/proc/<pid>/maps`.

## How it works

1. Find the PID of the target program (`pgrep`) and its binary (`/proc/<pid>/exe`).
2. Read the ELF header and symbol table with `libelf` to get the offset and size of the target function.
3. For position-independent executables, read the load address from `/proc/<pid>/maps` and add it to the offset.
4. `PTRACE_ATTACH` to the process, then read and write its code through `/proc/<pid>/mem`.
5. Do one of the operations below, then restore the original instructions and registers and detach.

The operations follow the five challenges of the assignment (`src/challenge1` to `src/challenge5`):

- **Breakpoint**: write an `int3` (`0xCC`) at the start of the function and wait for the process to stop on it.
- **Indirect call**: at the breakpoint, set `rax` to the address of another function and `rdi` to the argument,
  write `call *%rax` followed by `int3`, let the process run, then read the return value and put everything back.
  The argument can be passed by value or by reference (on the tracee's stack).
- **Code injection**: call `posix_memalign` and `mprotect` inside the tracee to get an executable page, copy the bytes
  of a function from the tracer (`func4`) into it, and call it once.
- **Trampoline**: same injection, then overwrite the start of the traced function with a jump to the injected code, so
  every later call runs `func4` instead.
- **Threads**: `interceptor_thread` is a variant that traces a multithreaded program (`hello_there_thread`).

## Build

Linux on x86-64, with CMake, a C compiler, `libelf` and `binutils` (`objdump`).

```shell
# Debian / Ubuntu
sudo apt install build-essential cmake libelf-dev binutils

cmake -S . -B build
cmake --build build
```

The binaries are written to `bin/`.

Attaching to a process that isn't a child of the tracer needs `CAP_SYS_PTRACE` or
`kernel.yama.ptrace_scope = 0`. Running as root works too. Alternatively, use the container, which builds everything
and adds the capability:

```shell
docker-compose run --rm interceptor
```

## Run

`bin/hello_there` is the example target. It calls `func1(i)` (`i + 1`) in a loop and prints the result every second.
Start it in one terminal:

```shell
cd bin
./hello_there &
```

Then run the tracer from `bin/` in another terminal (or in the same shell):

```shell
# Call func2 (i + 3) once with 123, by value
./interceptor hello_there -i func1 func2 -p 123

# Call func3 (*i + 5) once with 123, by reference
./interceptor hello_there -i func1 func3 -r -p 123

# Inject func4 (i + 10) and call it once
./interceptor hello_there -t func1 -a -p 123

# Inject func4 and replace func1 with it from now on
./interceptor hello_there -t func1 -p 123
```

The tracer prints each step: addresses found, memory before and after every write, signals received by the tracee.
Exit codes are listed in `includes/errorcodes.h` (`0` means no error). `./interceptor -h` prints the usage.

Only one instance of the target program can be running, otherwise the tracer refuses to pick one.
