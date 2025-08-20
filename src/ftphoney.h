/*
  Biblioteca do Honeypot
  Declarações e definições das funções que serão
                          usadas pelo algoritmo.
*/
#ifndef _FTPHONEY_H
#define _FTPHONEY_H
#include <sys/socket.h>

#define BACKLOG 10
#define BUFSIZE 1024
#define LOGPATH "./logs/"
#define LOGFPATH "./logs/honeypot.log"

int die(const char *fmt, ...);
/* Criar diretório de logs */
void makeLogdir(void);
/* Escrever logs de forma formatada */
void writeLog(const char *clientIP, const char *fmt, ...);
/* Enviar ao cliente uma resposta formatada */
ssize_t sendReply(int sock, const char *fmt, ...);
/* Executar o handler dos comandos e operações */
void handleClient(int clientSock, struct sockaddr_in *peer);
/* Enviar signal() */
void setupSignals(void);
#endif
