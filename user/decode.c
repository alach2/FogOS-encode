#include "base64.h"
#include "arcfour.h"
#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"
#include "kernel/fcntl.h"

/**
 * This function reads Base64 encoded data from the specified file descriptor in chunks, decodes it back to its original form, and
 * prints the decoded content to the console with its size.
 *
 * @param fd The file descriptor from which the encoded content is read
 *
 */
void
b64_decode(int fd)
{
  unsigned char buffer[1024];
  unsigned char result[1024];
  int n;

  while ((n = read(fd, buffer, 1024)) > 0) {
    int size = base64_decode(buffer, result, n);
    printf("Your decoded secret is %s of size %d", result, size);
  }
  printf("\n");
}

/**
 * This function reads command-line arguments to determine whether the arguments invoke the Base64 decoding function.
 * It processes the specified input file accordingly.
 *
 * @param argc The number of command-line arguments
 * @param argv The command-line arguments
 * @return This function prints an error message and exits or closes and exits
 *
 */
int
main(int argc, char *argv[])
{
  char *crypto_option = argv[1];
  char *file_name = argv[2];

  int fd = open(file_name, O_RDONLY);
  if (fd < 0) {
    printf("ERROR, could not open the file %s\n", file_name);
    exit(1);
  }

  if (strcmp(crypto_option, "-b") == 0) {
    b64_decode(fd);
  }

  close(fd);
  exit(1);

}
