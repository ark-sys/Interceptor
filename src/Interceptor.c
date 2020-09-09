#include "my_include.h"

/* Structure needed to store variables used in different sections of the program */
struct program_vars_t program_vars;

/* Byte code instruction of 'trap' */
static const unsigned char trap_instruction = 0xCC;

static void __print_usage(void){
  fprintf(stderr, "%s\n", "Usage : ./Interceptor [program_name] [function_name]");
}
/* Return the pid of a program. */
static ErrorCode get_pid(void)
{
  FILE* traced_program_fd;

  int command_len = strlen("pgrep ") + program_vars.program_name_s + 1;
  char *command = malloc(sizeof(char)*command_len);
  if(command == NULL)
  {
    return MALLOC_FAILED;
  }

  snprintf(command, command_len, "pgrep %s", program_vars.traced_program_name);

  traced_program_fd = popen(command, "r");
  if(traced_program_fd == NULL)
  {
    return COMMAND_NOT_FOUND;
  }

  program_vars.traced_pid_string = malloc(sizeof(char) * PID_SIZE);

  fgets(program_vars.traced_pid_string, PID_SIZE, traced_program_fd);
  program_vars.traced_pid_string_s = strlen(program_vars.traced_pid_string);
  program_vars.traced_program_id = atol(program_vars.traced_pid_string);


  pclose(traced_program_fd);
  free(command);

  return NO_ERROR;
}

static ErrorCode get_program_mainaddress(void)
{
  ErrorCode errCode = NO_ERROR;
  char program_baseaddress_pos[64];
  FILE * program_maps_fd;

  /* Create the command that will get us the position of the beginning of the main during runtime */
  int program_pos_len = strlen("/proc//maps") + program_vars.traced_pid_string_s + 1;
  char * program_pos  = malloc(sizeof(char)* program_pos_len);
  if(program_pos == NULL){
    errCode = MALLOC_FAILED;
  }
  snprintf(program_pos, program_pos_len, "/proc/%s/maps", program_vars.traced_pid_string);

  /* Open the file and do some error checking */
  program_maps_fd = popen(program_pos, "r");
  if(program_maps_fd == NULL){
    fprintf(stderr, "Failed to open maps for PID %s\n", program_vars.traced_pid_string);
    errCode = FILE_NOT_FOUND;
  }

  /* Parse the file and evaluate the address of main */
  char * readline = malloc(sizeof(char) * 128);
  if (readline == NULL) {
    errCode = MALLOC_FAILED;
  }
  while(fgets(readline, 128, program_maps_fd)){
    if((strstr(readline, program_vars.traced_program_name) != NULL) && (strstr(readline, "r--p") != NULL)){
      strtok(readline, "-");
      snprintf(program_baseaddress_pos, 64, "%s", readline);
      break;
    }
  }
  program_vars.program_main_address = atol(program_baseaddress_pos);
  pclose(program_maps_fd);
  free(program_pos);
  free(readline);
  return errCode;
}

/* Return the function position in the program binary*/
static ErrorCode get_function_address(const char * argument_2)
{
  ErrorCode errCode = NO_ERROR;
  FILE * binary_dump_fd;

  /* Compute length of the function name passed as argument and store the value for future use, store the function name aswell */
  program_vars.traced_function_s = strlen(argument_2)+1;
  program_vars.traced_function_name = malloc(sizeof(char) * program_vars.traced_function_s);
  snprintf(program_vars.traced_function_name, program_vars.traced_function_s, "%s", argument_2);

  /* Prepare the command that has to be called in order to parse the binary */
      /* Command alias in bash : objdump -t <program_name> | grep <function_name> | cut -d " " -f1 */

  /*If failed to malloc, return immediatly to main */
  int command_len = strlen("objdump -t ")+program_vars.program_name_s+strlen(" | grep ")+program_vars.traced_function_s+ strlen(" | cut -d \" \" -f1")+1;
  char * command = malloc(sizeof(char)*command_len);
  if(command == NULL){
    return MALLOC_FAILED;
  }

  snprintf(command, command_len, "objdump -t %s | grep %s | cut -d \" \" -f1", program_vars.traced_program_name, program_vars.traced_function_name);

  binary_dump_fd = popen(command, "r");
  if(binary_dump_fd == NULL)
  {
    fprintf(stderr, "%s\n", "Failed to open binary dump.");
    errCode = NULL_POINTER;
  }
  char *readline = malloc(sizeof(char)*64);
  fgets(readline, 64, binary_dump_fd);
  if(strlen(readline) == 0){
    errCode = FUNCTION_NOT_FOUND;
  }
  program_vars.function_address = program_vars.program_main_address + atol(readline);


  pclose(binary_dump_fd);
  free(command);
  free(readline);
  return errCode;
}

/* Check if the program passed as argument exists and allocate dynamical memory for a reference to its name */
static ErrorCode get_program_name(const char * argument_1)
{
  /* Do some sanity check to see if the arguments exists */
  if(access(argument_1, F_OK) != -1){
    fprintf(stdout, "Opening file: <%s>...\n", argument_1);
    /* Compute length of the program name passed as argument and store the value for future use, store the program name aswell */
    program_vars.program_name_s = strlen(argument_1)+1;
    program_vars.traced_program_name = malloc(sizeof(char) * program_vars.program_name_s);
    if (program_vars.traced_program_name == NULL) {
      return MALLOC_FAILED;
    }
    snprintf(program_vars.traced_program_name, program_vars.program_name_s, "%s", argument_1);
  } else {
    __print_usage();
    return FILE_NOT_FOUND;
  }
  return NO_ERROR;
}

static void free_memory(void)
{
  if(program_vars.traced_pid_string){
    free(program_vars.traced_pid_string);
  }
  if(program_vars.traced_program_name){
    free(program_vars.traced_program_name);
  }
  if(program_vars.traced_function_name){
    free(program_vars.traced_function_name);
  }
}

int main(int argc, char const *argv[]) {
  if(argc != 3){
    fprintf(stderr, "Error %d:%s\n",__LINE__,ErrorCodetoString(INVALID_ARGUMENT));
    __print_usage();
    return INVALID_ARGUMENT;
  }


  ErrorCode errCode;
  errCode = get_program_name(argv[1]);
  if(errCode != NO_ERROR){
    fprintf(stderr, "Error! line:%d:%s\n",__LINE__,ErrorCodetoString(errCode));
    free_memory();
    return errCode;
  }

  errCode = get_pid();
  if(errCode != NO_ERROR){
    fprintf(stderr, "Error! line:%d:%s\n",__LINE__,ErrorCodetoString(errCode));
    free_memory();
    return errCode;
  }else{
    fprintf(stdout, "Program <%s> PID: %d\n",program_vars.traced_program_name, program_vars.traced_program_id);
  }

  errCode = get_program_mainaddress();
  if(errCode != NO_ERROR){
    fprintf(stderr, "Error! line:%d:%s\n",__LINE__,ErrorCodetoString(errCode));
    free_memory();
    return errCode;
  }

  errCode = get_function_address(argv[2]);
  if(errCode != NO_ERROR){
    fprintf(stderr, "Error! line:%d:%s\n",__LINE__,ErrorCodetoString(errCode));
    free_memory();
    return errCode;
  }else{
    fprintf(stdout, "Tracing function <%s> at address: %lu\n",program_vars.traced_function_name, program_vars.function_address);
  }





  free_memory();
  return errCode;
}
