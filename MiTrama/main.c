#include <stdio.h>
#include "mitrama.h"

int main()
{
    unsigned char cheksum[16]={(INGLES<<5)+1,'H','o','l','a',0,8,16,(AES<<6)+(CHEKSUM<<4),0x1b,0x08,(PULSOS_BINARIOS<<6)+(INALAMBRICO<<5)+(BLUETOOTH<<3)};
    unsigned char xor[16]={0x21,0x68,0x65,0x6C,0x6C,0x6f,0x49,0x58,0xF0,0x13,0XB0};
    unsigned char bit[16]={(FRANCES<<5)+1,'H','E','l','L','o',9,17,(RSA<<6)+(BIT_DE_PARIDAD<<4)+(PAR<<1),(NEGATIVOS<<6)+(ALAMBRICO<<5)+(COAXIAL<<3)};
    struct tramaInfo info;
    analizaTrama(&info,cheksum);
    analizaTrama(&info,xor);
    analizaTrama(&info,bit);
    return 0;
}