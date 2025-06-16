/*
    This file is part of the ChipWhisperer Example Targets
    Copyright (C) 2012-2017 NewAE Technology Inc.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "simpleserial.h"
#include "hal.h"

#include "kem.h"

#define NTESTS 10
#define BUFFER_LEN 63
#define VARIABLE_TYPE_LEN 1
#define OFFSET_LEN 2
#define TOTAL_DATA_LEN 1
#define DATA_LEN BUFFER_LEN-VARIABLE_TYPE_LEN-OFFSET_LEN-TOTAL_DATA_LEN

uint8_t pk[CRYPTO_PUBLICKEYBYTES];
uint8_t sk[CRYPTO_SECRETKEYBYTES];
uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
uint8_t ss[CRYPTO_BYTES];
uint8_t pk_temp[CRYPTO_PUBLICKEYBYTES];
uint8_t sk_temp[CRYPTO_SECRETKEYBYTES];
uint8_t ct_temp[CRYPTO_CIPHERTEXTBYTES];
uint8_t ss_temp[CRYPTO_BYTES];

// 0: pk, 1: sk, 2: ct, 3: ss, 4: pk_temp, 5: sk_temp, 6: ct_temp, 7:ss_temp
uint8_t* variables[8] = {pk, sk, ct, ss, pk_temp, sk_temp, ct_temp, ss_temp};

uint8_t generate_key(uint8_t* pt, uint8_t len)
{
	// Generar par de llaves
    trigger_high();
    crypto_kem_keypair(pk, sk);
    trigger_low();

    simpleserial_put('r', BUFFER_LEN, pk);
	return 0x00;
}

uint8_t encapsulate(uint8_t* pt, uint8_t len)
{
    // Encapsular mensaje
	trigger_high();
	crypto_kem_enc(ct, ss, pk);
	trigger_low();
    
    simpleserial_put('r', BUFFER_LEN, pk);
	return 0x00;
}

uint8_t decapsulate(uint8_t* pt, uint8_t len)
{
    // Desencapsular mensaje
	trigger_high();
	crypto_kem_dec(ss, ct, sk);
	trigger_low();
    
    simpleserial_put('r', BUFFER_LEN, ss);
	return 0x00;
}

uint8_t temp_decapsulate(uint8_t* pt, uint8_t len)
{
    // Desencapsular mensaje
	trigger_high();
	crypto_kem_dec(ss_temp, ct_temp, sk_temp);
	trigger_low();
    
    simpleserial_put('r', BUFFER_LEN, ss);
	return 0x00;
}

uint8_t clock_signal(uint8_t* pt, uint8_t len)
{
    // Trigger vacío para comparar una señal vacía
    trigger_high();
    trigger_low();

    uint8_t puntero[70] = {
        0x43, 0x6f, 0x6d, 0x61, 0x6e, 0x64, 0x6f, 0x20, 
        0x27, 0x63, 0x27, 0x20, 0x63, 0x6f, 0x72, 0x72, 
        0x65, 0x63, 0x74, 0x61, 0x6d, 0x65, 0x6e, 0x74, 
        0x65, 0x20, 0x65, 0x6a, 0x65, 0x63, 0x75, 0x74, 
        0x61, 0x64, 0x6f,
        0x43, 0x6f, 0x6d, 0x61, 0x6e, 0x64, 0x6f, 0x20, 
        0x27, 0x63, 0x27, 0x20, 0x63, 0x6f, 0x72, 0x72, 
        0x65, 0x63, 0x74, 0x61, 0x6d, 0x65, 0x6e, 0x74, 
        0x65, 0x20, 0x65, 0x6a, 0x65, 0x63, 0x75, 0x74, 
        0x61, 0x64, 0x6f};
    
    simpleserial_put('r', BUFFER_LEN, puntero);
    return 0x00;
}


uint8_t prueba(uint8_t* pt, uint8_t len)
{
    // Trigger vacío para comparar una señal vacía
    trigger_high();
    trigger_low();

    uint8_t puntero_prueba[35] = {
        0x43, 0x6f, 0x6d, 0x61, 0x6e, 0x64, 0x6f, 0x20, 
        0x27, 0x70, 0x27, 0x20, 0x63, 0x6f, 0x72, 0x72, 
        0x65, 0x63, 0x74, 0x61, 0x6d, 0x65, 0x6e, 0x74, 
        0x65, 0x20, 0x65, 0x6a, 0x65, 0x63, 0x75, 0x74, 
        0x61, 0x64, 0x6f};
    
    simpleserial_put('r', 35, puntero_prueba);
    return 0x00;
}

uint8_t insert_variable(uint8_t* pt, uint8_t len)
{
    // Insertar valores en sk
    int variable_type = pt[0];
    int offset = pt[2] | pt[1] << 8;
    int total_data = pt[3];
    uint8_t* ptr = variables[variable_type];
    int i;
    for (i = 0; i < total_data; i++){
        ptr[offset+i] = pt[VARIABLE_TYPE_LEN+OFFSET_LEN+TOTAL_DATA_LEN+i];
    }
    return 0x00;
}

uint8_t return_variable(uint8_t* pt, uint8_t len)
{
    // Devolver puntero desde offset especificado
    int variable_type = pt[0];
    int offset = pt[2] | pt[1] << 8;
    int total_data = pt[3];
    uint8_t* ptr = variables[variable_type];
    uint8_t new_ptr[BUFFER_LEN];
    memset(new_ptr, 0x00, BUFFER_LEN);
    int i;
    for (i = 0; i < total_data; i++){
        new_ptr[i] = ptr[offset+i];
    }
    simpleserial_put('r', BUFFER_LEN, new_ptr);

    return 0x00;
}

int main(void)
{
    // Inicializar chipwhisperer
    platform_init();
	init_uart();
	trigger_setup();

	simpleserial_init();

    // Inicializar kyber
    // unsigned int i;
    // int r;
    // srand(time(NULL)); //SEMILLA NUMEROS ALEATORIOS.

    /*
    for(i=0;i<NTESTS;i++) {
        r  = test_keys();
        //sleep(100);
        // r |= test_invalid_sk_a();
        // r |= test_invalid_ciphertext();
        if (r) {
            return 1;
            
        }
    }
    */
    
	simpleserial_addcmd('g', BUFFER_LEN, generate_key);
	simpleserial_addcmd('e', BUFFER_LEN, encapsulate);
	simpleserial_addcmd('d', BUFFER_LEN, decapsulate);
	simpleserial_addcmd('t', BUFFER_LEN, temp_decapsulate);
    simpleserial_addcmd('c', BUFFER_LEN, clock_signal);
    simpleserial_addcmd('i', BUFFER_LEN, insert_variable);
    simpleserial_addcmd('r', BUFFER_LEN, return_variable);
    simpleserial_addcmd('p', 1, prueba);

	while(1)
		simpleserial_get();
}