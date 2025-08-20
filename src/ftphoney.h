/*
  Biblioteca do Honeypot
  Declarações e definições das funções que serão
                          usadas pelo algoritmo.
*/
#ifndef _FTPHONEY_H
#define _FTPHONEY_H
#include <sys/socket.h>

int die(const char *fmt, ...);
void makeLogdir(void);
void writeLog(const char *clientIP, const char *fmt, ...);
ssize_t sendReply(int sock, const char *fmt, ...);
void handleClient(int clientSock, struct sockaddr_in *peer);
void setupSignals(void);
#endif
