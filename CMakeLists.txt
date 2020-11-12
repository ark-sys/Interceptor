cmake_minimum_required(VERSION 3.13)

project(Interceptor)

set(CMAKE_VERBOSE_MAKEFILE on)

find_package(Threads REQUIRED)

set(CMAKE_USE_PTHREADS_INIT true)
set(CMAKE_USE_PTHREADS_INIT ON)

set(SRCS src/memory.c src/utility.c src/indirectcall.c src/breakpoint.c src/elfscan.c src/interceptor.c)
set(HEADERS includes/common.h includes/errorcodes.h includes/memory.h includes/elfscan.h includes/interceptor.h)

include_directories(
        $(PROJECT_SOURCE_DIR)/includes/
)

set(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/bin/)

add_executable(interceptor ${SRCS} ${HEADERS} src/elfscan.c)
target_link_libraries(interceptor Threads::Threads m -lelf )
target_compile_options(interceptor PRIVATE  -Wall -Wextra -Werror=float-equal -Wuninitialized -Wunused-variable -Wdouble-promotion -pedantic -Wmissing-prototypes -Wmissing-declarations -Werror=undef)

add_executable(hello_there examples/hello_there.c)
target_compile_options(hello_there PRIVATE  -O0 -Wunused-variable)
target_link_options(hello_there PRIVATE -fPIC)