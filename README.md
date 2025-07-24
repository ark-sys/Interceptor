# WELCOME TO INTERCEPTOR

A simple tracer based on ptrace and a bit of libelf.

## CONTEXT

The goal of this project is to modify the code of a program on the fly. To do this, we need to trace the program's execution in memory, modify its instructions and registers during execution, and, once all operations are completed, restore its previous state.

This program will fetch the PID of the program to be traced (there must be only one instance of this program running; otherwise, it will trigger an error).

With the PID, we can access its memory space via `/proc/pid/mem`.

If the file is dynamically linked (DYN type symbol detected), we will access `/proc/pid/maps` to retrieve the memory start address (since, in this scenario, addresses will be at random locations in memory), which we will add to the evaluated functions.

Once we know the addresses of the functions and have access to the memory file relative to a PID, we can perform various operations such as:
- Setting breakpoints
- Setting indirect calls to help us call other functions
- Directly writing functions into some areas of memory
- Changing arguments of some functions

The program will display every operation during runtime and any signals received by the tracee.

You can also use `echo $?` to check the return value from interceptor (`0 == NO ERROR`; check `errorcodes.h` for more error codes).

## DOWNLOAD AND INSTALL INSTRUCTIONS

(CMake is required for compilation)
- From the terminal, type:
    - `git clone git@gitlab.istic.univ-rennes1.fr:16012048/Interceptor.git`
    - `mkdir build ; cd build`
    - `cmake .. ; make`

### RUN INTERCEPTOR

To check the program execution with the provided examples, you will need two terminals.
- In Terminal 1, move to the `bin` folder (in the root directory) and type:
    - `hello_there`

This program will run endlessly, printing and incrementing integers starting from 0.
You can also press CTRL+C to exit cleanly (and print a funny message).

- In Terminal 2, move to the `bin` folder and follow the command usage:
    - Command usage: `Usage : ./interceptor <program_name> <OPTION> <function_name> <OPTION_PARAMETER>`

e.g.:
- `./interceptor hello_there -i func1 func2 -p 123`
- `./interceptor hello_there -ri func1 func3 -p 123`
- `./interceptor hello_there -t func11 123`
- `./interceptor hello_there -at func1 123`

    - `program_name`: name of the ELF binary you want to trace.
    - `function_name`: name of the function to be intercepted (the one called in a loop in the tracee).

    `<OPTION>` can be:
        - `-i <function_name> <function_to_call>` for indirect call.
            - `function_to_call`: name of the function that will be called indirectly.

            By default, the function will be called with the argument passed by value.
            Add `-r` to call the function with the argument passed by reference.

        - `-at <function_name>` for function injection + indirect call.
            - `func4` will be injected into the tracee's memory space, and a single indirect call will be placed to it.

        - `-t <function_name>` for trampoline.
            - `func4` will be injected into the tracee's memory space and continuously called due to the jump instruction.

    `<OPTION_PARAMETER>`: Provide a parameter for either option with
        - `-p <integer>`

Available functions (to be called):
- `func2`: Located in the traced program's memory; it will set the parameter value to the `hello_there` output. Parameter is passed by value.
- `func3`: Same as above. Parameter is passed by reference.
- `func4`: Located in interceptor's program memory; it will set the parameter value to the `hello_there` output. Parameter is passed by value.

Type `interceptor -h` for help from the terminal.

##### If you are interested in how interceptor works, I suggest you read the [DESIGN.md](./DESIGN.md) file.
