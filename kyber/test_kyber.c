#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include "kem.h"


#define NTESTS 10

static int test_keys(void)
{
  uint8_t pk[CRYPTO_PUBLICKEYBYTES];
  uint8_t sk[CRYPTO_SECRETKEYBYTES];
  uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
  uint8_t key_a[CRYPTO_BYTES] ;
  uint8_t key_b[CRYPTO_BYTES] ;

  //Alice generates a public key 

  crypto_kem_keypair(pk, sk);



  //Bob derives a secret key and creates a response
  trigger_high();
  crypto_kem_enc(ct, key_b, pk);
  printf("Key_b: ");
  for (int x = 0; x < CRYPTO_BYTES; x++) {
      printf("%02X ", key_b[x]);
  }
  trigger_low();
  printf("\n");

  //Alice uses Bobs response to get her shared key
  crypto_kem_dec(key_a, ct, sk);

  printf("Key_a: ");
  for (int x = 0; x < CRYPTO_BYTES; x++) {
      printf("%02X ", key_a[x]);
  }
  printf("\n");

  if(memcmp(key_a, key_b, CRYPTO_BYTES)) {
    printf("ERROR keys\n");
    return 1;
  }
  
  return 0;
}



static int test_invalid_sk_a(void)
{
  uint8_t pk[CRYPTO_PUBLICKEYBYTES];
  uint8_t sk[CRYPTO_SECRETKEYBYTES];
  uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
  uint8_t key_a[CRYPTO_BYTES];
  uint8_t key_b[CRYPTO_BYTES];

  //Alice generates a public key
  crypto_kem_keypair(pk, sk);

  //Bob derives a secret key and creates a response
  crypto_kem_enc(ct, key_b, pk);

  //Replace secret key with random values
  randombytes(sk, CRYPTO_SECRETKEYBYTES);

  //Alice uses Bobs response to get her shared key
  crypto_kem_dec(key_a, ct, sk);

  if(!memcmp(key_a, key_b, CRYPTO_BYTES)) {
    printf("ERROR invalid sk\n");
    return 1;
  }

  return 0;
}



static int test_invalid_ciphertext(void)
{
  uint8_t pk[CRYPTO_PUBLICKEYBYTES];
  uint8_t sk[CRYPTO_SECRETKEYBYTES];
  uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
  uint8_t key_a[CRYPTO_BYTES];
  uint8_t key_b[CRYPTO_BYTES];
  uint8_t b=0;
  size_t pos=0;

  do {
    randombytes(&b, sizeof(uint8_t));
  } while(!b);
  randombytes((uint8_t *)&pos, sizeof(size_t));

  //Alice generates a public key
  crypto_kem_keypair(pk, sk);


  //Bob derives a secret key and creates a response
  crypto_kem_enc(ct, key_b, pk);
  
  //Change some byte in the ciphertext (i.e., encapsulated key)
  ct[pos % CRYPTO_CIPHERTEXTBYTES] ^= b;

  //Alice uses Bobs response to get her shared key
  crypto_kem_dec(key_a, ct, sk);
  
  
  if(!memcmp(key_a, key_b, CRYPTO_BYTES)) {
    printf("ERROR invalid ciphertext\n");
    return 1;
  }

  return 0;
}

int main(void)
{
  unsigned int i;
  int r;
  srand(time(NULL)); //SEMILLA NUMEROS ALEATORIOS.

  for(i=0;i<NTESTS;i++) {
    printf("Test Keys\n");
    r  = test_keys();
    //sleep(100);
    /*
    printf("Test Invalid SK_A\n");
    r |= test_invalid_sk_a();
    printf("Test Invalid Ciphertest\n");
    r |= test_invalid_ciphertext();
    */
    if (r) {
        printf("ERROR en el numero %i", i);
        return 1;
        
    }
  }

  //printf("CRYPTO_SECRETKEYBYTES:  %d\n",CRYPTO_SECRETKEYBYTES);
  //printf("CRYPTO_PUBLICKEYBYTES:  %d\n",CRYPTO_PUBLICKEYBYTES);
  //printf("CRYPTO_CIPHERTEXTBYTES: %d\n",CRYPTO_CIPHERTEXTBYTES);

  return 0;
}
