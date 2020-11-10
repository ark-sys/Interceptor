#include "../includes/elfscan.h"

/*
 *
 * */
ErrorCode check_elf_type(const char * program_name, int *result) {
    ErrorCode errorCode = NO_ERROR;

    Elf64_Ehdr *ehdr;
    Elf *elf;
    int fd;

    /* Open the input file */
    if ((fd = open(program_name, O_RDONLY)) == -1) {
        perror("Failed to open file.");
        errorCode = FILE_NOT_FOUND;
    } else {
        /* Obtain the ELF descriptor */
        (void) elf_version(EV_CURRENT);
        if ((elf = elf_begin(fd, ELF_C_READ, NULL)) == NULL) {
            perror("Failed to get ELF begin section.");
            errorCode = ERROR;
        } else {

            /* Get header for current elf */
            if ((ehdr = elf64_getehdr(elf)) == NULL) {
                perror("Failed to get data section for Elf64 header");
                errorCode = ERROR;

            } else {
                switch (*result = ehdr->e_type) {
                    case ET_DYN:
                        fprintf(stdout, "DYN type detected.\n");
                        break;
                    case ET_EXEC:
                        fprintf(stdout, "EXEC type detected.\n");
                        break;
                    default:
                        fprintf(stderr, "Failed to get ELF type detected.\n");
                        errorCode = ERROR;
                        break;
                }

            }
            elf_end(elf);
        }
        close(fd);
    }

    return errorCode;
}

ErrorCode get_symbol_table(){

}
