cmake_minimum_required(VERSION 3.0)

project(interceptor)

set(CMAKE_VERBOSE_MAKEFILE on)

find_package(Threads REQUIRED)

set(CMAKE_USE_PTHREADS_INIT true)
set(CMAKE_USE_PTHREADS_INIT ON)

set(SRCS src/utility.c src/challenge2/indirectcall.c src/challenge1/breakpoint.c src/elfscan.c src/interceptor.c src/challenge4/trampoline.c src/challenge3/memcache.c)
set(SRCS_THREAD src/utility.c src/challenge2/indirectcall.c src/challenge1/breakpoint.c src/elfscan.c src/challenge5/interceptor_thread.c src/challenge4/trampoline.c src/challenge3/memcache.c src/challenge5/thread_helper.c includes/thread_helper.h)
set(HEADERS includes/common.h includes/errorcodes.h includes/elfscan.h includes/interceptor.h)

include_directories(
        $(PROJECT_SOURCE_DIR)/includes/
)

# Set executable path to bin
set(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/bin/)


# Create binary executable for interceptor, this is the main for the tracer
add_executable(${PROJECT_NAME} ${SRCS} ${HEADERS})
target_link_libraries(${PROJECT_NAME} -lelf)
target_compile_options(${PROJECT_NAME} PRIVATE  -Wall -Wextra -Werror=float-equal -Wuninitialized -Wunused-variable -Wdouble-promotion -pedantic -Wmissing-prototypes -Wmissing-declarations -Werror=undef)

# Create binary executable for interceptor_thread, this version can trace multi threaded programs
add_executable(${PROJECT_NAME}_thread ${SRCS_THREAD} ${HEADERS})
target_link_libraries(${PROJECT_NAME}_thread -lelf)
target_compile_options(${PROJECT_NAME}_thread PRIVATE  -Wall -Wextra -Werror=float-equal -Wuninitialized -Wunused-variable -Wdouble-promotion -pedantic -Wmissing-prototypes -Wmissing-declarations -Werror=undef)

# Multi threaded version of tracee
add_executable(hello_there_thread examples/hello_there_thread.c)
target_compile_options(hello_there_thread PRIVATE -O0 -Wunused-variable)
target_link_libraries(hello_there_thread Threads::Threads -fPIC)

# tracee
add_executable(hello_there examples/hello_there.c)
target_compile_options(hello_there PRIVATE -O0 -Wunused-variable)
target_link_libraries(hello_there  -fPIC)

# trace with libraries statically linked
add_executable(hello_there_static examples/hello_there.c)
target_link_libraries(hello_there_static -static)
