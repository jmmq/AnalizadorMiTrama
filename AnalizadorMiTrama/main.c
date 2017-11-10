#include <stdio.h>
#include "mitrama.h"

int main()
{
    unsigned char trama[36]={(INGLES<<5)+1,'H','o','l','a',0,8,16,(AES<<6)+(CHEKSUM<<4),0x1b,0x07,
                             (PULSOS_BINARIOS<<6)+(INALAMBRICO<<5)+(BLUETOOTH<<3)};
    unsigned char trama2[36]={0x21,0x68,0x65,0x6C,0x6C,0x6f,0x49,0x58,0xF0,0x12/*0XB3*/,0XB0};
    struct tramaInfo info;
    analizaTrama(&info,trama);
    printTramaBinaria(&info,trama);
    printTramaHex(&info,trama);
    printTramaInfo(&info,trama);
    printf("XOR Byte: %02X\n",calcularByteXOR(&info,trama));
    printf("Cheksum bytes: %04X\n",calcularCampoCheksum(&info,trama));
    return 0;
}
