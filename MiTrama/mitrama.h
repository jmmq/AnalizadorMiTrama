#ifndef REDES_H
#define REDES_H
/*
[(Idioma 3b)(mlen 5b)]
[Mensaje mlen*5 Bytes]
.
.
.
[ID Destino]
[ID Origen]
[(Cifrado 2b)(Control de error 2 b)(2b)(Tipo Paridad 1b)(Bit de paridad 1b)]
[(Codigo de linea 2b)(Medio de transmisión 3b)(3b)]
 */
enum enumIdiomas{ESPANOL,INGLES,PORTUGUES,FRANCES};
enum enumCifrados{AES,DES,RSA};
enum enumControlError{BIT_DE_PARIDAD,CRC,CHEKSUM,XOR_POR_BYTES};
enum enumTiposParidad{PAR,IMPAR};
enum enumCodigosLinea{PULSOS_BINARIOS,RETORNO_A_CERO,NEGATIVOS};
enum enumTiposMedios{ALAMBRICO,INALAMBRICO};
enum enumMediosAl{FIBRA_OPTICA,COAXIAL,UTP};
enum enumMediosIn{BLUETOOTH,INFRARROJO,WIFI,LIFI};
struct tramaInfo{
    unsigned char idioma;
    unsigned char mlen;
    unsigned char idDestino;
    unsigned char idOrigen;
    unsigned char *mensaje;
    unsigned char cifrado;
    unsigned char controlError;
    unsigned char codLinea;
    unsigned char tipoMedio;
    unsigned char medio;
    unsigned char tipoParidad;
    unsigned char bitParidad;
    unsigned char error;
};
void analizaTrama(struct tramaInfo *info,unsigned char trama[]);
void usuario(struct tramaInfo *info,unsigned char trama[]);
void chequeo(struct tramaInfo *info,unsigned char trama[]);
void logica(struct tramaInfo *info,unsigned char trama[]);
void idioma(struct tramaInfo *info, unsigned char trama[]);
void mlen(struct tramaInfo *info,unsigned char trama[]);
void mensaje(struct tramaInfo *info,unsigned char trama[]);
void idDestino(struct tramaInfo *info,unsigned char trama[]);
void idOrigen(struct tramaInfo *info,unsigned char trama[]);
void cifrado(struct tramaInfo *info,unsigned char trama[]);
void controlError(struct tramaInfo *info,unsigned char trama[]);
void codLinea(struct tramaInfo *info,unsigned char trama[]);
void tipoMedio(struct tramaInfo *info,unsigned char trama[]);
void error(struct tramaInfo *info,unsigned char trama[]);
void errorBitParidad(struct tramaInfo *info,unsigned char trama[]);
void errorXOR(struct tramaInfo *info,unsigned char trama[]);
void errorCRC(struct tramaInfo *info,unsigned char trama[]);
unsigned char calcularByteXOR(struct tramaInfo *info,unsigned char trama[]);
int calcularCampoCheksum(struct tramaInfo *info,unsigned char trama[]);
void errorChecksum(struct tramaInfo *info,unsigned char trama[]);
void medio(struct tramaInfo *info,unsigned char trama[]);
int contarUnos(struct tramaInfo *info,unsigned char trama[]);
void tipoParidad(struct tramaInfo *info,unsigned char trama[]);
unsigned char extraBytesCtrlError(struct tramaInfo *info);
void printTramaInfo(struct tramaInfo *info,unsigned char trama[]);
unsigned char validarIdioma(struct tramaInfo *info);
unsigned char validarCifrado(struct tramaInfo *info);
unsigned char validarCodLinea(struct tramaInfo *info);
unsigned char validarMedioAl(struct tramaInfo *info);
int getTotalLen(struct tramaInfo *info);
void printTramaBinaria(struct tramaInfo *info,unsigned char trama[]);
void printTramaHex(struct tramaInfo *info,unsigned char trama[]);
#endif // REDES_H