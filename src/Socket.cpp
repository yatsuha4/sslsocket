/***********************************************************************//**
	@file
***************************************************************************/
#include "Context.hpp"
#include "Socket.hpp"

namespace sslsocket {
/***********************************************************************//**
	@brief コンストラクタ
	@param[in] context コンテキスト
***************************************************************************/
Socket::Socket(std::shared_ptr<Context> context)
  : context_(context), 
    fd_(INVALID_FD), 
    ssl_(nullptr)
{
}
/***********************************************************************//**
	@brief 
***************************************************************************/
Socket::Socket(std::shared_ptr<Context> context, int fd, SSL* ssl)
  : context_(context), 
    fd_(fd), 
    ssl_(ssl)
{
}
/***********************************************************************//**
	@brief デストラクタ
***************************************************************************/
Socket::~Socket() {
  close();
}
/***********************************************************************//**
	@brief 
***************************************************************************/
bool Socket::open(const char* host, int port) {
  close();
  struct sockaddr_in address;
  address.sin_family = AF_INET;
  struct hostent* entry = gethostbyname(host);
  if(!entry) {
    return false;
  }
  memcpy(&address.sin_addr, entry->h_addr_list[0], entry->h_length);
  address.sin_port = htons(port);
  fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
  if(connect(fd_, reinterpret_cast<struct sockaddr*>(&address), 
             sizeof(address)) < 0) {
    close();
    return false;
  }
  ssl_ = getContext()->createClientSsl(fd_);
  return true;
}
/***********************************************************************//**
	@brief 
***************************************************************************/
int Socket::listen(int port) {
  close();
  fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  if(bind(fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
    close();
    return 0;
  }
  if(port == 0) {
    socklen_t size = sizeof(addr);
    if(getsockname(fd_, reinterpret_cast<struct sockaddr*>(&addr), 
                   &size) == 0) {
      port = ntohs(addr.sin_port);
    }
    else {
      close();
      return 0;
    }
  }
  ::listen(fd_, 1);
  return port;
}
/***********************************************************************//**
	@brief 
***************************************************************************/
std::shared_ptr<Socket> Socket::accept() {
  auto fd = ::accept(fd_, nullptr, nullptr);
  auto ssl = getContext()->createServerSsl(fd);
  auto socket = std::make_shared<Socket>(getContext(), fd, ssl);
  if(SSL_accept(ssl) <= 0) {
    ERR_print_errors_fp(stderr);
    return nullptr;
  }
  return socket;
}
/***********************************************************************//**
	@brief 
***************************************************************************/
void Socket::close() {
  if(ssl_) {
    SSL_shutdown(ssl_);
    SSL_free(ssl_);
    ssl_ = nullptr;
  }
  if(fd_ >= 0) {
    ::close(fd_);
    fd_ = INVALID_FD;
  }
}
/***********************************************************************//**
	@brief 
***************************************************************************/
size_t Socket::recv(void* buff, size_t size) {
  size_t recvSize = 0;
  if(ssl_) {
    while(recvSize < size) {
      auto s = SSL_read(ssl_, buff, int(size - recvSize));
      if(s < 0) {
        ERR_print_errors_fp(stderr);
        break;
      }
      buff = static_cast<char*>(buff) + s;
      recvSize += s;
    }
  }
  return recvSize;
}
/***********************************************************************//**
	@brief 
***************************************************************************/
size_t Socket::send(const void* buff, size_t size) {
  size_t sendSize = 0;
  if(ssl_) {
    while(sendSize < size) {
      auto s = SSL_write(ssl_, buff, int(size - sendSize));
      if(s < 0) {
        ERR_print_errors_fp(stderr);
        break;
      }
      buff = static_cast<const char*>(buff) + s;
      sendSize += s;
    }
  }
  return sendSize;
}
/***********************************************************************//**
	@brief 
***************************************************************************/
std::shared_ptr<Context> Socket::getContext() const {
  return context_.lock();
}
/***********************************************************************//**
	$Id$
***************************************************************************/
}
