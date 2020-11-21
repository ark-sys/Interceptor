


# WELCOME TO INTERCEPTOR

A simple tracer based on ptrace and a little bit of libelf.

## CONTEXT

The goal of this Linux program is to modify code on the fly of some program. In order to do that we need to trace the program execution in memory, modify its instructions and registers during execution and once all operations are completed we have to restore it's previous state.

This program will fetch the pid of the running program to be traced (the instance of this program must be unique otherwise it will trigger an error)

Then thanks to the pid we can access its memory space via `/proc/pid/mem` 

If the file is compiled with the -pie option, DYN type symbol will be detected. In this case we will access `/proc/pid/maps` to retrieve memory start address (since in this scenario addresses will be in a random place in memory) that we will add to the evaluated functions

Once we know the address of the functions and we have access to the memory file relative to a pid than we can do all sorts of operations such as :
- Set breakpoints
- Set indirect calls that will help us to call other functions
- Directly write functions in some areas in memory
- Change argument of some functions
  
The program will display every operations during runtime and live signals received by the tracee.

You can also `echo $?` to check return value from interceptor (0 == NO ERROR)


## DOWNLOAD AND INSTALL INSTRUCTIONS:

(cmake is required for compilation)
- From terminal type
	- `clone git@gitlab.istic.univ-rennes1.fr:16012048/Interceptor.git`
	- `cd build`
    - `cmake .. ; make`

### RUN INTERCEPTOR

In order to check the program execution with the provided examples you will need two terminals.
- In Terminal 1, move to bin folder and type
	- `hello_there`
	
This program will run endlessly and print and increment integers starting from 0. 
You can also CTRL+C to exit cleanly (and print a funny message)
    
- In Terminal 2, move to bin folder and follow command usage:    
    - Command usage `./interceptor [binary file] [function to be traced] [function to be called] [parameter for the function to be called]`

e.g.: `./interceptor hello_there func1 func2 123`  or `./interceptor hello_there func1 func3 123`
    
Available functions (to be called) :
- func2 : located in the traced program memory, it will set the parameter value to 'hello_there' output. Parameter is passed by value.
- func3 : same as above. Parameter is passed by reference.
- func4 : located in interceptor's program memory, it will set the parameter value to 'hello_there' output. Parameter is passed by value
 
Type `interceptor -h` or `interceptor --help` for help from terminal

##### If you are interested in how interceptor work I suggest you to read the [DESIGN.md](./DESIGN.md) file
