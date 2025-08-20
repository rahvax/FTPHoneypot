/*
  Algoritmo das funções declaradas no header.
  Aqui será o foco de todo o algoritmo e será
  linkado na compilação pelo Make.
*/
#define _GNU_SOURCE
#include <asm-generic/socket.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <stdarg.h>

#define BACKLOG 10
#define BUFSIZE 1024
#define LOGPATH "./logs/"
#define LOGFPATH "./logs/honeypot.log"


int die(const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  return -1;
}

void makeLogdir(void) {
  if (access(LOGPATH, F_OK) != 0) {
    if (mkdir(LOGPATH, 0700) != 0)
      perror("[X] erro ao criar PATH de logs");
  }
}

void writeLog(const char *clientIP, const char *fmt, ...) {
  FILE *fp = NULL;
  time_t t = time(NULL);
  struct tm tm;
  char timestr[64];
  va_list ap;
  
  makeLogdir();
  if (!(fp = fopen(LOGFPATH, "a"))) {
    perror("[X] erro ao abrir ou criar arquivo");
    return;
  }

  gmtime_r(&t, &tm);
  strftime(timestr, sizeof(timestr), "[%dT/%m/%Y %H:%M:%SZ]", &tm);
  fprintf(fp, "[%s] %s ", timestr, clientIP);

  va_start(ap, fmt);
  vfprintf(fp, fmt, ap);
  va_end(ap);

  fprintf(fp, "\n");
  fclose(fp);
}

ssize_t sendReply(int sock, const char *fmt, ...) {
  char buffer[1024];
  va_list ap;
  int n = 0;

  va_start(ap, fmt);
  n = vsnprintf(buffer, sizeof(buffer) - 3, fmt, ap);
  va_end(ap);

  if (n < 0)
    return -1;
  if (n >= (int)sizeof(buffer) - 3)
    n = sizeof(buffer) - 3;
  buffer[n] = '\r';
  buffer[n + 1] = '\n';
  buffer[n+2] = '\0';
  return send(sock, buffer, n+2, 0);
}

void handleClient(int clientSock, struct sockaddr_in *peer) {
  char clientIP[INET_ADDRSTRLEN], buffer[BUFSIZ],
       username[256] = {0}, password[256] = {0};
  ssize_t len;

  inet_ntop(AF_INET, &(peer->sin_addr), clientIP, sizeof(clientIP));
  writeLog(clientIP, "NEW CONNECTION");
  sendReply(clientSock, "220 Honeypot - Rahvax");

  while ((len = recv(clientSock, buffer, sizeof(buffer) - 1, 0)) > 0) {
    buffer[len] = '\0';
    char *line = buffer, *next, cmd[16] = {0}, arg[1024] = {0};
    
    while (line && *line) {
      next=strchr(line, '\n');
      if (next) {
        *next = '\0';
        if (next > line && *(next - 1) == '\r')
          *(next-1)='\0';
      }
      while (*line == ' ' || *line == '\t')
        line++;
      if (*line == '\0') {
        if (next)
          line = next + 1;
        else
          break;
        continue;
      }

      writeLog(clientIP, "RECV: %s", line);
      sscanf(line, "%15s %1023[^\r\n]", cmd, arg);

      for (char *p = cmd; *p; ++p)
        if (*p >= 'a' && *p <= 'z')
          *p -= 32;
      if (!strcmp(cmd, "USER")) {
        strncpy(username, arg, sizeof(username)-1);
        sendReply(clientSock, "331 Password required for %s",
                  username[0] ? username : "anonymous");
        writeLog(clientIP, "USER: %s", username);
      }
      else if (!strcmp(cmd, "PASS")) {
        strncpy(password, arg, sizeof(password) - 1);
        sendReply(clientSock, "230 User logged in, proceed.");
        writeLog(clientIP, "PASS: %s", password);
        writeLog(clientIP, "CREDENTIALS: %s:%s", username[0]?username:"(none)", password[0]?password:"(none)");
      }
      else if (!strcmp(cmd, "SYST")) 
        sendReply(clientSock, "215 UNIX Type: L8");
      else if (!strcmp(cmd, "PWD") || !strcmp(cmd, "XPWD"))
        sendReply(clientSock, "257 \"/\" is current directory");
      else if (!strcmp(cmd, "TYPE"))
	sendReply(clientSock, "200 Type set to %s", arg[0]?arg:"A");
      else if (!strcmp(cmd, "LIST")) {
        sendReply(clientSock,
                  "150 Here comes the directory listing.\n-rw-r--r-- 1 root "
                  "root 1024 Jan 01 2025 esterEgg.txt\n226 Diretory send OK.");
        writeLog(clientIP, "LIST requested (arg='%s)", arg);
      }
      else if (!strcmp(cmd, "RETR")) {
        sendReply(clientSock, "550 Failed to open file.");
        writeLog(clientIP, "RETR attempt: %s", arg);
      }
      else if (!strcmp(cmd, "STOR")) {
        sendReply(clientSock, "550 Permission denied.");
        writeLog(clientIP, "STOR attempt: %s", arg);
      }
      else if (!strcmp(cmd, "QUIT")) {
        sendReply(clientSock, "221 Goodbye.");
        writeLog(clientIP, "Client QUIT");
        close(clientSock);
        return ;
      } else if (!strcmp(cmd, "STOP")) {
        sendReply(clientSock, "221 Stopped Honeypot.");
        writeLog(clientIP, "Stopped Honeypot");
        close(clientSock);
        return;
      }
      else {
        sendReply(clientSock, "502 Command not implemented on HONEYPOT.");
        writeLog(clientIP, "UNKNOW CMD: %s %s", cmd, arg);
      }

      if (next)
        line = next + 1;
      else break;
    }
  }

  if (len == 0)
    writeLog(clientIP, "CONNECTION CLOSED BY PEER");
  else if (len < 0)
    writeLog(clientIP, "RECV ERROR: %s", strerror(errno));
  close(clientSock);
}

void setupSignals(void) {
  signal(SIGCHLD, SIG_IGN);
}

