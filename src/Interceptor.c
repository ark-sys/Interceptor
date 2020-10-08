#include "../includes/my_include.h"
/* Structure needed to store variables used in different sections of the program */
struct program_vars_t program_vars;

/* Byte code instruction of 'trap' */
static const unsigned char trap_instruction = 0xCC;

static void print_usage(void){
  fprintf(stderr, "%s\n", "Usage : ./Interceptor [program_name] [function_name]");
}

/* Return the pid of a program. */
static ErrorCode get_pid(const char * argument_1)
{
  ErrorCode errCode = NO_ERROR;

  FILE* traced_program_fd;

  char command[COMMAND_SIZE];
  char pid_buffer[PID_SIZE];

  if (access(argument_1, F_OK) != -1){
      fprintf(stdout, "Opening binary: <%s>\n", argument_1);

      snprintf(program_vars.traced_program_name, POS_SIZE, "%s", argument_1);

      /* pgrep <program_name> */
      snprintf(command, COMMAND_SIZE, "pgrep %s", argument_1);

      traced_program_fd = popen(command, "r");

          if(traced_program_fd == NULL)
          {
              errCode = FILE_NOT_FOUND;

          } else {
              fgets(pid_buffer, PID_SIZE, traced_program_fd);
              program_vars.traced_program_id = atol(pid_buffer);
              if(program_vars.traced_program_id == 0){
                  errCode = PROGRAM_NOT_RUNNING;
              }
              pclose(traced_program_fd);
          }
  }else{
      print_usage();
      errCode = FILE_NOT_FOUND;
  }


  return errCode;
}

/* Return the function position in the program binary*/
static ErrorCode get_function_address(const char * argument_2)
{
  ErrorCode errCode = NO_ERROR;
  FILE * binary_dump_fd;

  char command[COMMAND_SIZE];
  char readline[LINE_SIZE];

  snprintf(program_vars.traced_function_name, FUNCTION_SIZE, "%s", argument_2);

   /* Prepare the command that has to be called in order to parse the binary */
   /* Command alias in bash : objdump -t <program_name> | grep <function_name> | cut -d " " -f1 */
  snprintf(command, COMMAND_SIZE, "objdump -t %s | grep %s | cut -d \" \" -f1", program_vars.traced_program_name, program_vars.traced_function_name);

  binary_dump_fd = popen(command, "r");
  if(binary_dump_fd == NULL)
  {
    fprintf(stderr, "%s\n", "Failed to open binary dump.");
    errCode = NULL_POINTER;
  } else {

      fgets(readline, LINE_SIZE, binary_dump_fd);
      if(atol(readline) == 0){
        errCode = FUNCTION_NOT_FOUND;
      } else {
        /* Get a correct representation of the address from char* to unsigned long*/
        program_vars.function_address = (unsigned long)strtol(readline, NULL, 16);
      }

    pclose(binary_dump_fd);
  }

  return errCode;
}


static ErrorCode set_breakpoint(void){
    ErrorCode errorCode = NO_ERROR;
    char path_to_mem[128];
   // char backup_instruction;

    struct user_regs_struct regs;

    int wait_status;
    FILE * mem_file_fd;

    fprintf(stdout,"%s\n", "Setting breakpoint...");

    /*ptrace(PTRACE_GETREGS, program_vars.traced_program_id, NULL, &regs);

    fprintf(stdout, "Current RIP = 0x%016llx\n", regs.rip);

    unsigned data = ptrace(PTRACE_PEEKTEXT, program_vars.traced_program_id, (void *)program_vars.function_address, 0);
    fprintf(stdout, "Original data at 0x%016lx: 0x%016x\!n", program_vars.function_address, data);

    long data_with_trap = (data & 0xFFFFFFFFFFFFFF00) | 0xCC;
    ptrace(PTRACE_POKETEXT, program_vars.traced_program_id, (void*)program_vars.function_address, (void*)data_with_trap);

    long readback_data = ptrace(PTRACE_PEEKTEXT, program_vars.traced_program_id, (void*)program_vars.function_address, 0);
    fprintf(stdout,"After trap,set breakpoint, data at 0x%016lx: 0x%016lx\n", program_vars.function_address, readback_data);
*/

    snprintf(path_to_mem, 128, "/proc/%d/mem", program_vars.traced_program_id);
    mem_file_fd = fopen(path_to_mem, "r+");
    if(mem_file_fd == NULL){
        errorCode = NULL_POINTER;
    } else {
        if (fseek(mem_file_fd, (long)program_vars.function_address, SEEK_SET) != 0){
            errorCode = ERROR;
        } else {
            if(fwrite(&trap_instruction, 1,1, mem_file_fd) == 0){
                errorCode = ERROR;
            } else {
                fprintf(stdout, "Written instruction: %c at address %ld\n", trap_instruction, (long)program_vars.function_address);
            }
        }
        fclose(mem_file_fd);
    }

//    printf("Process stopped.\nPress <ENTER> to continue.");
//    getchar();

    if(ptrace(PTRACE_CONT, program_vars.traced_program_id, NULL, NULL) < 0){
        fprintf(stdout, "PTRACE_CONT failed\n");
    }
    if(program_vars.traced_program_id != waitpid(program_vars.traced_program_id, &wait_status,WCONTINUED)){
        fprintf(stdout, "Error waitpid at line %d\n", __LINE__);
    }

    /* Get current content from instruction pointer register */
    ptrace(PTRACE_GETREGS, program_vars.traced_program_id, NULL, &regs);
    fprintf(stdout, "RIP before breakpoint = 0x%016llx\n", regs.rip);

    /* Set current instruction as the beginning of the traced function */
    regs.rip = program_vars.function_address;
    ptrace(PTRACE_SETREGS, program_vars.traced_program_id, NULL, &regs);

    /* Check if we correctly stepped back by one instruction */
    ptrace(PTRACE_GETREGS, program_vars.traced_program_id, NULL, &regs);
    fprintf(stdout, "RIP after breakpoint = 0x%016llx\n", regs.rip);


    return errorCode;
}

int main(int argc, char *argv[]) {
  // printf("\e[1;1H\e[2J");
  if(argc != 3){
    print_usage();
    fprintf(stderr, "Error! line:%d:%s\n",__LINE__,ErrorCodetoString(INVALID_ARGUMENT));
    return INVALID_ARGUMENT;
  }

  /* Get program name from argument_1, check for errors and store name in global struct */
  ErrorCode errCode;

  /* Get the PID of current instance of the program */
  errCode = get_pid(argv[1]);
  if(errCode != NO_ERROR){
    fprintf(stderr, "Error! line:%d:%s\n",__LINE__,ErrorCodetoString(errCode));
    return errCode;
  }else{
    fprintf(stdout, "<%s> PID: %d\n",argv[1], program_vars.traced_program_id);
  }

  /* Look for the address of the target function in the binary dump */
  errCode = get_function_address(argv[2]);
  if(errCode != NO_ERROR){
    fprintf(stderr, "Error! line:%d:%s\n",__LINE__,ErrorCodetoString(errCode));
    return errCode;
  }else{
    fprintf(stdout, "Tracing function <%s> at address: %lu\n",program_vars.traced_function_name, program_vars.function_address);
  }

  /*
   * START OPERATIONS ON CURRENT PID
   */

    int wait_status;

    if(ptrace(PTRACE_ATTACH, program_vars.traced_program_id, NULL, NULL)<0){
        fprintf(stderr, "Error during PTRACE_ATTACH at line %d\n", __LINE__);
    }

    if (program_vars.traced_program_id != waitpid(program_vars.traced_program_id, &wait_status,0)){
        fprintf(stderr, "Error waitpid at line %d\n", __LINE__);
    }

    errCode = set_breakpoint();


    if(ptrace(PTRACE_DETACH, program_vars.traced_program_id, NULL, NULL)<0){
        fprintf(stderr, "Error during PTRACE_DETACH at line %d\n", __LINE__);
    }
    return errCode;
}
