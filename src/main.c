/*
 * Honeypot Educacional
 * aqui é o arquivo principal, só uso para realizar chamadas
   das funções e passar os argumentos.

 * o honeypot utiliza SOCKET TCP para fingir ser um FTP,
   sem realmente abrir um server FTP.
			                         by: @rahvax
*/
#include <stdlib.h>
#include "ftphoney.h"

int main(int argc, char **argv) {
  int port = 2121;

  if (argc >= 2)
    port = atoi(argv[1]);
  startServer(port);

  return 0;
}
