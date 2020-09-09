# makefile for rc_mpu, builds example programs

# directories
SRCDIR		:= src
BINDIR		:= bin
INCLUDEDIR	:= includes

# basic definitions for rules
EXAMPLES	:= $(shell find $(SRCDIR) -type f -name *.c)
TARGETS		:= $(EXAMPLES:$(SRCDIR)/%.c=$(BINDIR)/%)
INCLUDES	:= $(shell find $(INCLUDEDIR) -name '*.h')
SOURCES		:= $(shell find $(SRCDIR) -type f -name *.c)

# compiler and linker programs
CC		:= gcc

# compile flags
WFLAGS		:= -Wall -Wextra -Werror=float-equal -Wuninitialized \
	-Wunused-variable -Wdouble-promotion -pedantic -Wmissing-prototypes \
	-Wmissing-declarations -Werror=undef
CFLAGS		:= -O0 -lm -g -pthread -I$(INCLUDEDIR)

# commands
RM	:= rm -rf

all : $(TARGETS)

debug :
	$(MAKE) $(MAKEFILE) DEBUGFLAG="-g -D DEBUG"
	@echo " "
	@echo "Make Debug Complete"
	@echo " "

clean :
	@$(RM) $(BINDIR)
	@echo "Examples Clean Complete"


$(BINDIR)/% : $(SRCDIR)/%.c
	@mkdir -p $(BINDIR)
	@$(CC) -o $@ $< $(CFLAGS) $(WFLAGS)  $(DEBUGFLAG)
	@echo "made: $@"
