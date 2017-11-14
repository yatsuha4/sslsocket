/***********************************************************************//**
	@file
***************************************************************************/
#include "Context.hpp"
#include "Socket.hpp"
/***********************************************************************//**
	@brief 
***************************************************************************/
int main(int argc, const char** argv) {
  static const std::string HELLO("hello!\n");
  auto context = std::make_shared<sslsocket::Context>();
  if(argc > 1 && strcmp(argv[1], "server") == 0) {
    auto server = context->createSocket();
    auto port = server->listen(4433);
    if(port != 0) {
      printf("listen: %d\n", port);
      while(auto client = server->accept()) {
        printf("accept\n");
        client->send(HELLO.c_str(), HELLO.size());
      }
    }
  }
  else {
    auto client = context->createSocket();
    if(client->open("localhost", 4433)) {
      char buff[HELLO.size()];
      auto size = client->recv(buff, sizeof(buff));
      for(int i = 0; i < size; i++) {
        printf("[%d]'%c'\n", i, buff[i]);
      }
      //client->send(HELLO.c_str(), HELLO.size());
    }
  }
  return 0;
}
/***********************************************************************//**
	$Id$
***************************************************************************/
