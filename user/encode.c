#include "sha256.h"
#include "base64.h"
#include "arcfour.h"
#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"
#include "kernel/fcntl.h"

/**
 * This function initializes the SHA256 context, reads data from the specified file descriptor in chunks, updates the SHA256 context
 * with the read data, and finally outputs the resulting hash to the console.
 *
 * @param fd The file descriptor from which data is read.
 *
 */
void
sha256_encode(int fd)
{
  SHA256_CTX ctx;
  sha256_init(&ctx);

  unsigned char buffer[1024];
  unsigned char hash_result[SHA256_BLOCK_SIZE];
  int n;

  while ((n = read(fd, buffer, 1024)) > 0) {
    sha256_update(&ctx, buffer, n);
  }

  sha256_final(&ctx, hash_result);

  printf("Your encoded secret is... ");
  for (int i = 0; i < SHA256_BLOCK_SIZE; i++) {
    printf("%h", hash_result[i]);
  }
  printf("\n");
}

/**
 * This function reads data from the specified file descriptor in
 * chunks, encodes it using Base64, and writes the encoded data to "encrypted.txt". The output file is created or overwriten.
 *
 * @param fd The file descriptor from which data is read
 * CITE https://www.codequoi.com/en/handling-a-file-by-its-descriptor-in-c/#:~:text=For%20example%2C%20we%20can%20open%20a%20file%20in,in%20truncated%20write%20mode%2C%20we%20could%20do%3A%20open%28%22path%2Fto%2Ffile%22%2CO_WRONLY%7CO_TRUNC%29%3B
 *
 */
void
b64_encode(int fd)
{
  unsigned char buffer[1024];
  unsigned char result[2048];
  int n;

  int output_fd = open("encrypted.txt", O_WRONLY | O_CREATE | O_TRUNC);
  if (output_fd < 0) {
    printf("ERROR, could not open the output file encrypted.txt\n");
    return;
  }

  while ((n = read(fd, buffer, 1024)) > 0) {
    int size = base64_encode(buffer, result, n, 1);
    printf("Saving your secret to encrypted.txt of size %d\n", size);
        write(output_fd, result, size);
    }

  close(output_fd);
}

/**
 * This function sets up the ARCFOUR state with a key,
 * it then reads data from the specified file descriptor in chunks, and
 * generates a keystream to encrypt the data.
 * The encrypted data is output to the console.
 *
 * @param fd The file descriptor from which data is read
 *
 */
void
arcfour_encode(int fd)
{
  unsigned char state[256];
  const unsigned char *key = (const unsigned char *)"beebop";
  int key_length = strlen((const char *)key);

  arcfour_key_setup(state, key, key_length);

  unsigned char buffer[1024];
  unsigned char keystream[1024];
  int n;

  printf("Your encoded secret is... ");
  while ((n = read(fd, buffer, 1024)) > 0) {
    arcfour_generate_stream(state, keystream, n);

    for (int i = 0; i < n; i++) {
      buffer[i] ^= keystream[i];
      printf("%h", buffer[i]);
    }

  printf("\n");
  }
}

/**
 * The main function reads the command-line arguments to determine which
 * encoding method to use (SHA256, Base64, or ARCFOUR) and processes
 * the specified input file accordingly.
 *
 * @param argc The number of command-line arguments
 * @param argv The command-line arguments
 * @return If there is an error, it prints an error message, else it closes and exits
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

  if (strcmp(crypto_option, "-s") == 0) {
    sha256_encode(fd);
  } else if (strcmp(crypto_option, "-b") == 0) {
    b64_encode(fd);
  } else if (strcmp(crypto_option, "-a") == 0) {
    arcfour_encode(fd);
  }
  close(fd);
  exit(1);

}
