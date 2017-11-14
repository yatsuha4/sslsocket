/***********************************************************************//**
	@file
***************************************************************************/
#pragma once

namespace sslsocket {
/***********************************************************************//**
	@brief ソケット
***************************************************************************/
class Socket {
 private:
  static const int INVALID_FD = -1;

 private:
  std::weak_ptr<Context> context_;
  int fd_;
  SSL* ssl_;

 public:
  Socket(std::shared_ptr<Context> context);
  Socket(std::shared_ptr<Context> context, int fd, SSL* ssl);
  ~Socket();

  bool open(const char* host, int port);

  int listen(int port = 0);
  std::shared_ptr<Socket> accept();
  void close();

  size_t recv(void* buff, size_t size);
  size_t send(const void* buff, size_t size);

 private:
  std::shared_ptr<Context> getContext() const;
};
/***********************************************************************//**
	$Id$
***************************************************************************/
}
