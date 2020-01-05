/* Encrypts, then decrypts, 2 MB of memory and verifies that the
   values are as they should be. */

#include <string.h>
#include "tests/arc4.h"
#include "tests/lib.h"
#include "tests/main.h"

#define PGSIZE (4096)
#define SIZE (400 * 4096)

static char buf[SIZE];

void test_main(void)
{

  struct arc4 arc4;
  unsigned int i;
  printf("setting buff\n");
  for (i = 0 * PGSIZE; i < SIZE; i += 100)
  {
    //  printf("PGNR i: %u\n", i);
    buf[i] = 'a';
    /*if (i % PGSIZE == 0)
    {
      printf("PGNR i: %u\n", i);
      //printf("PGNR i/s: %d, SIZE: %d: %d\n", i / PGSIZE, SIZE - 1);
      printf("PGNR: %u\n", i / PGSIZE);
    }*/
  }

  printf("getting buff\n");
  //printf("%c\n", buf[390*PGSIZE]);
  for (i = 0 * PGSIZE; i < SIZE; i += 100)
    if (buf[i] != 'a')
      printf("%c, %d\n", buf[i], i/PGSIZE);
  printf("\n\nze end\n");
  /* Initialize to 0x5a. */
  msg("initialize");

  for (size_t i = 0; i < SIZE; i++)
  {
    buf[i] = 0x5a;
  }

  /* Check that it's all 0x5a. */
  msg("read pass");
  for (i = 0; i < SIZE; i++)
    if (buf[i] != 0x5a)
      fail("byte %zu != 0x5a", i);

  /* Encrypt zeros. */
  msg("read/modify/write pass one");
  arc4_init(&arc4, "foobar", 6);
  arc4_crypt(&arc4, buf, SIZE);

  /* Decrypt back to zeros. */
  msg("read/modify/write pass two");
  arc4_init(&arc4, "foobar", 6);
  arc4_crypt(&arc4, buf, SIZE);

  /* Check that it's all 0x5a. */
  msg("read pass");
  for (i = 0; i < SIZE; i++)
    if (buf[i] != 0x5a)
      fail("byte %zu != 0x5a", i);
}
