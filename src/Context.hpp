/***********************************************************************//**
	@file
***************************************************************************/
#pragma once

namespace sslsocket {
/***********************************************************************//**
	@brief コンテキスト
***************************************************************************/
class Context
  : public std::enable_shared_from_this<Context>
{
 private:
  SSL_CTX* clientCtx_;
  SSL_CTX* serverCtx_;
  EVP_PKEY* pkey_;
  RSA* rsa_;
  X509* x509_;

 public:
  Context();
  ~Context();

  std::shared_ptr<Socket> createSocket();

  SSL* createClientSsl(int fd);
  SSL* createServerSsl(int fd);

 private:
  SSL_CTX* getClientCtx();
  SSL_CTX* getServerCtx();
  void setupCertificate();
};
/***********************************************************************//**
	$Id$
***************************************************************************/
}
