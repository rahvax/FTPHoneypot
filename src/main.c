/*
  FTP Honeypot
  by: Rahvax

  * aqui é o arquivo principal, só uso para realizar chamadas
                          das funções e passar os argumentos.
*/
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "ftphoney.h"

int main(int argc, char **argv) {
  int port = 2121, srv = 0, opt = 1;
  struct sockaddr_in sa;

  if (argc >= 2)
    port = atoi(argv[1]);

  srv = socket(AF_INET, SOCK_STREAM, 0);
  if (srv < 0)
    die("socket: %s\n", strerror(errno));
  setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
  memset(&sa, 0, sizeof(sa));
  sa.sin_family = AF_INET;
  sa.sin_addr.s_addr = INADDR_ANY;
  sa.sin_port = htons(port);

  if (bind(srv, (struct sockaddr *)&sa, sizeof(sa)) < 0)
    die("bind %s\n", strerror(errno));
  if (listen(srv, BACKLOG) < 0)
    die("listen: %s\n", strerror(errno));

  setupSignals();
  makeLogdir();
  fprintf(stdout, "Honeypot listening on port %i\n", port);

  while (1) {
    struct sockaddr_in peer;
    socklen_t plen = sizeof(peer);
    int client = accept(srv, (struct sockaddr *)&peer, &plen);
    pid_t pid;
    
    if (client < 0) {
      if (errno == EINTR)
        continue;
      perror("[X]: erro em accept");
      continue;
    }
    pid = fork();
    if (pid < 0) {
      perror("[X]: erro em fork");
      close(client);
      continue;
    } else if (pid == 0) {
      close(srv);
      handleClient(client, &peer);
      return 0;
    } else
      close (client);
  }
  close (srv);
  return 0;
}
