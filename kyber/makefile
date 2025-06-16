# Target file name (without extension).
TARGET = simpleserial-kyber

# Lista de todos los archivos fuente
SRC += simpleserial-kyber.c

SRC += cbd.c fips202.c indcpa.c kem.c ntt.c poly.c polyvec.c reduce.c rng.c \
       sha256.c symmetric-shake.c verify.c

# -----------------------------------------------------------------------------

ifeq ($(CRYPTO_OPTIONS),)
CRYPTO_OPTIONS = NONE
endif

# Agregar soporte para SimpleSerial (usa funciones como simpleserial_get() y trigger_x())
include ../simpleserial/Makefile.simpleserial

# Ruta al núcleo de firmware ChipWhisperer
FIRMWAREPATH = ../.
include $(FIRMWAREPATH)/Makefile.inc
