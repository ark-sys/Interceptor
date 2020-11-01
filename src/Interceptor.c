#include "../includes/my_include.h"

/* Structure needed to store variables used in different sections of the program */
static struct program_vars_t program_vars;

/* Byte code instruction of 'trap' */
static const unsigned char trap_instruction = 0xCC;

/* Indirect call instruction */
static const unsigned char indirect_call[3] = {0xFF, 0xD0, trap_instruction};

/* Jump instruction */
static const unsigned char jump_instruction[2] = {0x48, 0xB8};

static void print_usage(void){
  fprintf(stderr, "%s\n", "Usage : ./Interceptor [program_name] [function_name]");
}

/* Return the pid of a program. */
static ErrorCode get_pid(const char * argument_1)
{
  ErrorCode errCode = NO_ERROR;

  FILE* command_1_fd;
  FILE* command_2_fd;

  char command[COMMAND_SIZE];
  char pid_buffer[LINE_SIZE];

  /* Check if the file exists and is accessible */
  if (access(argument_1, F_OK) != -1){
      fprintf(stdout, "Opening binary: <%s>\n", argument_1);

      /* Store the program name for later use */
      snprintf(program_vars.traced_program_name, POS_SIZE, "%s", argument_1);

      /* pgrep -c <program_name> , check how many instances of the program are running */
      snprintf(command, COMMAND_SIZE, "pgrep -c %s", argument_1);
      command_1_fd = popen(command, "r");
      /* Check the command execution status */
          if(command_1_fd == NULL)
          {
              perror("Failed to run command.");
              errCode = NULL_POINTER;
          } else {
              /* Read the line and check that we are actually reading characters */
              if (fgets(pid_buffer, LINE_SIZE, command_1_fd) == NULL)
              {
                  perror("Failed to read command output.");
                  errCode = NULL_POINTER;
              } else {
                  /* No programs have been found running */
                  if (atoi(pid_buffer) == 0){
                      errCode = PROGRAM_NOT_RUNNING;
                  } else
                      /* One instance of the program has been found */
                      if (atoi(pid_buffer) == 1){
                      /* pgrep <program_name>
                       * actually get the PID of the program that we want to trace
                       * */
                      snprintf(command, COMMAND_SIZE, "pgrep %s", argument_1);
                      command_2_fd = popen(command, "r");
                      if (command_2_fd == NULL){
                          perror("Failed to run command.");
                          errCode = NULL_POINTER;
                      } else {
                          if (fgets(pid_buffer, LINE_SIZE, command_2_fd) == NULL){
                              perror("Failed to read PID.");
                              errCode = NULL_POINTER;
                          } else {
                              /* The PID is converted and stored in a global structure for later use */
                              program_vars.traced_program_id = atoi(pid_buffer);
                          }
                          pclose(command_2_fd);
                      } //END if on command_2_fd

                  } /* Multiple instances of the program have been found */
                      else {
                          fprintf(stdout, "%d instances of binary <%s> have been found.\n Please select which one you want to trace\n", atoi(pid_buffer), argument_1);
                          //#todo add prompt selection in case multiple instances have been found
                          errCode= ERROR;
                      }
              } //END if on first fgets
              pclose(command_1_fd);
          } //END if on command_1_fd
  } else {
      /* On access failure, print help */
      print_usage();
      errCode = FILE_NOT_FOUND;
  } // END ifelse acces()


  return errCode;
}

/* Parses the traced program memory file and returns the address of function passed as argument; return value is the second argument */
static ErrorCode get_function_address(const char * function_name, unsigned long * function_address)
{
  ErrorCode errCode = NO_ERROR;
  FILE * binary_dump_fd;

  char command[COMMAND_SIZE];
  char readline[LINE_SIZE];

//  /* Store the function name for later use */
//  snprintf(program_vars.traced_function_name, FUNCTION_SIZE, "%s", argument_2);

   /* Prepare the command that has to be called in order to parse the binary */
   /* Command alias in bash : objdump -t <program_name> | grep -w <function_name> | cut -d " " -f1 */
  snprintf(command, COMMAND_SIZE, "objdump -t %s | grep -w %s | cut -d \" \" -f1", program_vars.traced_program_name, function_name);

  binary_dump_fd = popen(command, "r");
  if(binary_dump_fd == NULL)
  {
    fprintf(stderr, "%s\n", "Failed to open binary dump.");
    errCode = NULL_POINTER;
  } else {

      /* Check if we are correctly reading lines */
      if (fgets(readline, LINE_SIZE, binary_dump_fd) == NULL)
      {
          errCode = NULL_POINTER;
      } else {

          /* Check if the content that we got has a good format (like a function's address)*/
          if(strtol(readline, NULL, 16) == 0){
              errCode = FUNCTION_NOT_FOUND;

          } else {
              /* Get a correct representation of the address from char* to unsigned long*/
              *function_address = (unsigned long)strtol(readline, NULL, 16);
          }
      }

    pclose(binary_dump_fd);
  }

  return errCode;
}

static ErrorCode get_registers_backup(void){
    ErrorCode errorCode = NO_ERROR;
    if(ptrace(PTRACE_GETREGS, program_vars.traced_program_id, NULL, &program_vars.registers) < 0){
        fprintf(stderr,"%s\n", "Failed to save current registers state.");
        errorCode = ERROR;
    }
    return errorCode;
}
static ErrorCode set_breakpoint(const unsigned long address_position){
    ErrorCode errorCode = NO_ERROR;
    char path_to_mem[128];

    struct user_regs_struct regs;

    int wait_status;
    FILE * mem_file_fd;

    fprintf(stdout,"Setting breakpoint at 0x%08lx\n", address_position);

    /* Prepare path to memory file and open it with some error checking */
    snprintf(path_to_mem, 128, "/proc/%d/mem", program_vars.traced_program_id);
    mem_file_fd = fopen(path_to_mem, "r+");
    if(mem_file_fd == NULL){
        errorCode = NULL_POINTER;
        perror("Failed to open mem file.");
    } else {
        /* Get file position at offset "address_position", so we can write at the first instruction of the traced function */
        if (fseek(mem_file_fd, (long)address_position, SEEK_SET) != 0){
            errorCode = ERROR;
            perror("Failed to get offset.");
        } else {
            /* Write the trap instruction at the beginning of the trace function */
            if(fwrite(&trap_instruction, 1,1, mem_file_fd) == 0){
                errorCode = ERROR;
                perror("Failed to write trap.");
            } else {
                fprintf(stdout, "Written instruction: 0x%02x at address 0x%08lx\n", trap_instruction, (long)address_position);

            }
        }
        /* If everything went fine, close the file to apply changes */
        fclose(mem_file_fd);

        /* Check that no error have been made in the previous part */
        if(errorCode == NO_ERROR){

            /* Restart the process and wait that it continues */
            if(ptrace(PTRACE_CONT, program_vars.traced_program_id, NULL, NULL) < 0){
                perror("Failed to resume execution of program.");
                errorCode = ERROR;
            } else {
                /* Check that the process actually changed its state */
                if(program_vars.traced_program_id != waitpid(program_vars.traced_program_id, &wait_status,WCONTINUED)){
                    perror("Error waitpid.");
                    errorCode = ERROR;
                } else {

                    /* Get current content from instruction pointer register */
                    if(ptrace(PTRACE_GETREGS, program_vars.traced_program_id, NULL, &regs) < 0){
                        perror("Failed to get registers for PID.");
                        errorCode = ERROR;
                    }else{

                        fprintf(stdout, "RIP before breakpoint = 0x%08llx\n", regs.rip);
                        /* Set current instruction as the beginning of the traced function */
                        regs.rip = address_position;
                        if (ptrace(PTRACE_SETREGS, program_vars.traced_program_id, NULL, &regs) < 0){
                            perror("Failed to set registers for PID.");
                            errorCode = ERROR;
                        } else {

                            /* Check if we correctly stepped back by one instruction */
                            if(ptrace(PTRACE_GETREGS, program_vars.traced_program_id, NULL, &regs) < 0){
                                perror("Failed to get registers for PID.");
                                errorCode = ERROR;
                            } else {
                                fprintf(stdout, "RIP after breakpoint = 0x%08llx\n", regs.rip);
                            } // End of PTRACE_GETREGS section 2

                        } // End of PTRACE_SETREGS section

                    } // End of PTRACE_GETREGS section 1

                } // End of waitpid section

            } // End of PTRACE_CONT section

        } // End of check on errorCode

    }// End of if on mem_file_fd

    return errorCode;
}

static ErrorCode call_function(const unsigned long function_to_call){
    ErrorCode errorCode = NO_ERROR;
    struct user_regs_struct regs;
    int wait_status;

    FILE * mem_file_fd;
    char path_to_mem[64];

    snprintf(path_to_mem, 64, "/proc/%d/mem", program_vars.traced_program_id);

    errorCode = get_registers_backup();
    if (errorCode != NO_ERROR){
        fprintf(stderr,"%s\n", "Failed to get registers backup.");
    } else {
        errorCode = set_breakpoint(program_vars.function_address);
        if (errorCode != NO_ERROR){
            fprintf(stderr, "%s\n", "Failed to set breakpoint.");
        } else {
            fprintf(stdout, "Calling function at address 0x%lx\n", function_to_call);
            /* Get current register state for the traced program */
            if(ptrace(PTRACE_GETREGS, program_vars.traced_program_id, NULL, &regs) < 0){
                errorCode = ERROR;
            } else {
                /* Set current register with the new function and parameter to call
                 * rax -> address of the function to be called
                 * rip -> address of the current function
                 * */
                regs.rax = function_to_call;
                regs.rip = program_vars.function_address;

                if(ptrace(PTRACE_SETREGS, program_vars.traced_program_id, NULL, &regs) < 0){
                    fprintf(stderr, "%s\n", "Failed to set new registers");
                    errorCode = ERROR;
                } else {
                    if(ptrace(PTRACE_CONT, program_vars.traced_program_id, NULL, NULL) < 0){
                        fprintf(stderr, "%s\n","Failed to resume execution of program.");
                        errorCode = ERROR;
                    } else {
                        if(program_vars.traced_program_id != waitpid(program_vars.traced_program_id,&wait_status, WCONTINUED)){
                            fprintf(stderr, "Error waitpid at line %d\n", __LINE__);
                            errorCode = ERROR;
                        }
                    }
                }
            }
        }
    }

    return errorCode;
}
int main(int argc, char *argv[]) {
  // printf("\e[1;1H\e[2J");
  if(argc != 3){
    print_usage();
    fprintf(stderr, "Error! line:%d:%s\n",__LINE__,ErrorCodetoString(INVALID_ARGUMENT));
    return INVALID_ARGUMENT;
  }

  ErrorCode errCode;

  /* Get program name from argument_1, check for errors and store name in global struct */
  /* Get the PID of current instance of the program */
  errCode = get_pid(argv[1]);
  if(errCode != NO_ERROR){
    fprintf(stderr, "Error! line:%d:%s\n",__LINE__,ErrorCodetoString(errCode));
    return errCode;
  }else{
    fprintf(stdout, "<%s> PID: %d\n",argv[1], program_vars.traced_program_id);
  }

  /* Look for the address of the target function in the binary dump */
  errCode = get_function_address(argv[2], &program_vars.function_address);
  if(errCode != NO_ERROR){
    fprintf(stderr, "Error! line:%d:%s\n",__LINE__,ErrorCodetoString(errCode));
    return errCode;
  }else{
    fprintf(stdout, "Tracing function <%s> at address: %lu\n",argv[2], program_vars.function_address);
  }

  /*
   * START OPERATIONS ON CURRENT PID
   */

    int wait_status;

    if(ptrace(PTRACE_ATTACH, program_vars.traced_program_id, NULL, NULL) < 0){
        fprintf(stderr, "Error during PTRACE_ATTACH at line %d\n", __LINE__);
    }

    if (program_vars.traced_program_id != waitpid(program_vars.traced_program_id, &wait_status,0)){
        fprintf(stderr, "Error waitpid at line %d\n", __LINE__);
    }

    unsigned long addr_func_to_call;
    errCode = get_function_address("func2", &addr_func_to_call);
    if (errCode != NO_ERROR){
        fprintf(stderr, "%s\n","Failed to get address for func2");
    }

    errCode = call_function(addr_func_to_call);
    if (errCode != NO_ERROR){
        fprintf(stderr, "%s\n","Failed to call func2");
    }

//    if(program_vars.traced_program_id != waitpid(program_vars.traced_program_id, &wait_status, WCONTINUED))
//    {
//        fprintf(stderr,"%s\n", "not good");
//    }


    if (ptrace(PTRACE_CONT, program_vars.traced_program_id, NULL, NULL) < 0){
        fprintf(stderr, "%s\n", "Failed to continue." );
    }

    if(program_vars.traced_program_id != waitpid(program_vars.traced_program_id, &wait_status,WCONTINUED)){
        fprintf(stderr, "Error waitpid at line %d\n", __LINE__);
    }


    if(ptrace(PTRACE_DETACH, program_vars.traced_program_id, NULL, NULL) < 0){
        fprintf(stderr, "Error during PTRACE_DETACH at line %d\n", __LINE__);
    }
    return errCode;
}
