#include"mitrama.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
const unsigned char mlenFactor=5;
const char idiomas[][10]={"Espanol","Ingles","Aleman","Portugues","Frances"};
const char cifrados[][4]={"AES","DES","RSA"};
const char tiposCtrError[][16]={"Bit de paridad","CRC","Cheksum","XOR por bytes"};
const char tiposParidad[][6]={"Par","Impar"};
const char codigosLinea[][16]={"Pulsos binarios","Retorno a cero","Negativos"};
const char tiposMedios[][13]={"Alambrico","Inalambrico"};
const char mediosAl[][13]={"Fibra optica","Coaxial","UTP"};
const char mediosIn[][10]={"Bluetooth","Ifrarojo","WIFI","LIFI"};
const char existeError[][3]={"No","Si"};
void analizaTrama(struct tramaInfo *info,unsigned char trama[]){
    usuario(info,trama);
    chequeo(info,trama);
    logica(info,trama);
    error(info,trama);
    printTramaBinaria(info,trama);
    printTramaHex(info,trama);
    printTramaInfo(info,trama);
    printf("------------------------\n");
}
void usuario(struct tramaInfo *info,unsigned char trama[]){
    idioma(info,trama);
    mlen(info,trama);
    idDestino(info,trama);
    idOrigen(info,trama);
}
void chequeo(struct tramaInfo *info,unsigned char trama[]){
    cifrado(info,trama);
    controlError(info,trama);
    if(info->controlError==BIT_DE_PARIDAD){
        tipoParidad(info,trama);
    }
}
void tipoParidad(struct tramaInfo *info,unsigned char trama[]){
    info->tipoParidad=(trama[info->mlen+3]&2)>>1;
}

void logica(struct tramaInfo *info, unsigned char trama[]){
    codLinea(info,trama);
    tipoMedio(info,trama);
    medio(info,trama);
}
void idioma(struct tramaInfo *info,unsigned char trama[]){
    info->idioma=(trama[0]&224)>>5;
}
void mlen(struct tramaInfo *info,unsigned char trama[]){
    info->mlen=(trama[0]&31)*mlenFactor;
}
void idDestino(struct tramaInfo *info,unsigned char trama[]){
    info->idDestino=trama[1+info->mlen];
}
void idOrigen(struct tramaInfo *info,unsigned char trama[]){
    info->idOrigen=trama[info->mlen+2];
}
void cifrado(struct tramaInfo *info,unsigned char trama[]){
    info->cifrado=(trama[info->mlen+3])>>6;
}
void controlError(struct tramaInfo *info,unsigned char trama[]){
    info->controlError=(trama[info->mlen+3]&48)>>4;
}
void codLinea(struct tramaInfo *info,unsigned char trama[]){
    info->codLinea=((trama[info->mlen+extraBytesCtrlError(info)+4])&192)>>6;
}
void tipoMedio(struct tramaInfo *info,unsigned char trama[]){
    info->tipoMedio=(trama[info->mlen+extraBytesCtrlError(info)+4]&32)>>5;
}
void medio(struct tramaInfo *info,unsigned char trama[]){
    info->medio=(trama[info->mlen+extraBytesCtrlError(info)+4]&24)>>3;
}
void mensaje(struct tramaInfo *info, unsigned char trama[]){
    info->mensaje=&trama[1];
}
unsigned char extraBytesCtrlError(struct tramaInfo *info){
    switch (info->controlError) {
    case BIT_DE_PARIDAD:
        return 0;
    case CRC:
        return 1;
    case CHEKSUM:
        return 2;
    case XOR_POR_BYTES:
        return 1;
    }
    return 0;
}
void printTramaInfo(struct tramaInfo *info,unsigned char trama[]){
    if(validarIdioma(info)){
        printf("Idioma: %s\n",idiomas[info->idioma]);
    }else{
        printf("Idioma: ---\n");
    }
    printf("Longitud mensaje: %i bytes\n",info->mlen);
    printf("ID Destino: 0x%02x\n",info->idDestino);
    printf("Grupo: %d\n",trama[info->mlen+1]>>6);
    printf("No. lista: %d\n",trama[info->mlen+1]&0x4f);

    printf("ID Origen: 0x%02x\n",info->idOrigen);
    printf("Grupo: %d\n",trama[info->mlen+2]>>6);
    printf("No. lista: %d\n",trama[info->mlen+2]&0x4f);

    printf("Mensaje: ");
    for(int i=0;i<info->mlen;i++){
        printf("%c",trama[i+1]);
    }
    printf("\n");
    printf("Mensaje hex: ");
    for(int i=0;i<info->mlen;i++){
        printf("%02x ",trama[i+1]);
    }
    printf("\n");
    if(validarCifrado(info)){
        printf("Cifrado: %s\n",cifrados[info->cifrado]);
    }else{
        printf("Cifrado: ---\n");
    }
    printf("Control de error: %s\n",tiposCtrError[info->controlError]);
    if(info->controlError==BIT_DE_PARIDAD){
        printf("Tipo de paridad: %s\n",tiposParidad[info->tipoParidad]);
    }
    printf("FCS de la trama: ");
    switch (info->controlError) {
    case BIT_DE_PARIDAD:
        printf("%d",trama[info->mlen+3]&1);
        break;
    case CRC:
        printf("%02X",trama[info->mlen+4]);
        break;
    case CHEKSUM:
        printf("%02X%02X",trama[info->mlen+4],trama[info->mlen+5]);
        break;
    case XOR_POR_BYTES:
        printf("%02X",trama[info->mlen+4]);
        break;
    }
    printf("\n");
    printf("FCS calculado: ");
    switch (info->controlError) {
    case BIT_DE_PARIDAD:
        if(info->error){
            printf("%d",(~trama[info->mlen+3])&1);
        }else{
            printf("%d",trama[info->mlen+3]&1);
        }
        break;
    case CRC:
        printf("%02X",trama[info->mlen+4]);
        break;
    case CHEKSUM:
         printf("%04X",calcularCampoCheksum(info,trama));
        break;
    case XOR_POR_BYTES:
        printf("%02X",calcularByteXOR(info,trama));
        break;
    }
    printf("\n");
    if(validarCodLinea(info)){
        printf("Codigo de linea: %s\n",codigosLinea[info->codLinea]);
    }else{
        printf("Codigo de linea: ---\n");
    }
    printf("Tipo de medio: %s\n",tiposMedios[info->tipoMedio]);
    if(info->tipoMedio==ALAMBRICO){
        if(validarMedioAl(info)){
            printf("Medio de transmision: %s\n",mediosAl[info->medio]);
        }else{
            printf("Medio de transmision: ---\n");
        }
    }else{
        printf("Medio de transmision: %s\n",mediosIn[info->medio]);
    }
    printf("Existe error: %s\n",existeError[info->error]);
}
unsigned char validarIdioma(struct tramaInfo *info){
    if(info->idioma>4){
        return 0;
    }
    return 1;
}
unsigned char validarCifrado(struct tramaInfo *info){
    if(info->cifrado>2){
        return 0;
    }
    return 1;
}
unsigned char validarCodLinea(struct tramaInfo *info){
    if(info->codLinea>2){
        return 0;
    }
    return 1;
}
unsigned char validarMedioAl(struct tramaInfo *info){
    if(info->tipoMedio==ALAMBRICO){
        if(info->medio>UTP){
            return 0;
        }
        return 1;
    }
    return 0;
}
void error(struct tramaInfo *info, unsigned char trama[]){
    switch (info->controlError) {
    case BIT_DE_PARIDAD:
        errorBitParidad(info,trama);
        break;
    case CRC:
        errorCRC(info,trama);
        break;
    case CHEKSUM:
        errorChecksum(info,trama);
        break;
    case XOR_POR_BYTES:
        errorXOR(info,trama);
        break;
    default:
        break;
    }
}
void errorBitParidad(struct tramaInfo *info, unsigned char trama[]){
    int unos=contarUnos(info,trama);
    if(info->tipoParidad==PAR){
        info->error=unos%2;
    }else{
        if(unos%2==0)
            info->error=1;
        else
            info->error=0;
    }
}
void errorXOR(struct tramaInfo *info, unsigned char trama[]){
    unsigned char byte=trama[0];
    for(int i=1;i<getTotalLen(info);i++){
        byte^=trama[i];
    }
    if(byte==0){
        info->error=0;
    }else{
        info->error=1;
    }
}
void errorCRC(struct tramaInfo *info, unsigned char trama[]){
    info->error=0;
}
void errorChecksum(struct tramaInfo *info, unsigned char trama[]){
    int temp=0;
    for(int i=1;i<getTotalLen(info);i+=2){
        temp+=trama[i]<<8;
        temp+=trama[i+1];
        if(temp&0x10000){
            temp&=0xffff;
            temp++;
        }
    }
    temp=~temp;
    temp&=0xffff;
    if(temp==0){
        info->error=0;
    }else{
        info->error=1;
    }
}
int contarUnos(struct tramaInfo *info, unsigned char trama[]){
    unsigned char unos=0;
    unsigned char i;
    unsigned char s;
    for(i=0;i<getTotalLen(info);i++)
    {
        for(s=128;s>0;s>>=1) {
            if(trama[i]&s)
                unos++;
        }
    }
    return unos;
}
int getTotalLen(struct tramaInfo *info){
    return info->mlen+extraBytesCtrlError(info)+5;
}
void printTramaBinaria(struct tramaInfo *info, unsigned char trama[]){
    unsigned char i;
    unsigned char s;
    printf("Trama(en binario): {");
    for(i=0;i<getTotalLen(info);i++)
    {
        for(s=128;s>0;s>>=1) {
            if(trama[i]&s)
                printf("1");
            else
                printf("0");
        }
        if(i<getTotalLen(info)-1)
            printf(" ");
    }
    printf("}\n");
}
unsigned char calcularByteXOR(struct tramaInfo *info, unsigned char trama[]){
    if(info->controlError==XOR_POR_BYTES){
        unsigned char byte=trama[0];
        for(int i=1;i<getTotalLen(info);i++){
            if(i!=(info->mlen+4))
                byte^=trama[i];
        }
        return byte;
    }
    return 0;
}
void printTramaHex(struct tramaInfo *info,unsigned char trama[]){
    unsigned char i;
    printf("Trama(en hexadecimal): {");
    for(i=0;i<getTotalLen(info);i++)
    {
        printf("%02X",trama[i]);
        if(i<getTotalLen(info)-1)
            printf(" ");
    }
    printf("}\n");
}
int calcularCampoCheksum(struct tramaInfo *info, unsigned char trama[]){
    if(info->controlError==CHEKSUM){
        int temp=0;
        for(int i=1;i<getTotalLen(info);i+=2){
            if(i!=(info->mlen+4)){
                if(i==(info->mlen+3)){
                    temp+=trama[i]<<8;
                }else if(i==(info->mlen+5)){
                    temp+=trama[i+1];
                }else{
                    temp+=trama[i]<<8;
                    temp+=trama[i+1];
                }
                if(temp&0x10000){
                    temp&=0xffff;
                    temp++;
                }
            }
        }
        int cheksum=(temp^0xffff)&0xffff;
        return cheksum;
    }
    return 0;
}