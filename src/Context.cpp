/***********************************************************************//**
	@file
***************************************************************************/
#include "Context.hpp"
#include "Socket.hpp"

namespace sslsocket {
/***********************************************************************//**
	@brief デフォルトコンストラクタ
***************************************************************************/
Context::Context()
  : clientCtx_(nullptr), 
    serverCtx_(nullptr), 
    pkey_(nullptr), 
    rsa_(nullptr), 
    x509_(nullptr)
{
  SSL_load_error_strings();
  SSL_library_init();
  OpenSSL_add_all_algorithms();
}
/***********************************************************************//**
	@brief デストラクタ
***************************************************************************/
Context::~Context() {
  if(clientCtx_) {
    SSL_CTX_free(clientCtx_);
  }
  if(serverCtx_) {
    SSL_CTX_free(serverCtx_);
  }
  if(x509_) {
    X509_free(x509_);
  }
  if(rsa_) {
    RSA_free(rsa_);
  }
  if(pkey_) {
    EVP_PKEY_free(pkey_);
  }
}
/***********************************************************************//**
	@brief ソケットを生成する
	@return 生成したソケット
***************************************************************************/
std::shared_ptr<Socket> Context::createSocket() {
  return std::make_shared<Socket>(shared_from_this());
}
/***********************************************************************//**
	@brief 
***************************************************************************/
SSL* Context::createClientSsl(int fd) {
  auto ssl = SSL_new(getClientCtx());
  SSL_set_fd(ssl, fd);
  SSL_connect(ssl);
  return ssl;
}
/***********************************************************************//**
	@brief 
***************************************************************************/
SSL* Context::createServerSsl(int fd) {
  auto ssl = SSL_new(getServerCtx());
  SSL_set_fd(ssl, fd);
  SSL_use_certificate(ssl, x509_);
  SSL_use_PrivateKey(ssl, pkey_);
  return ssl;
}
/***********************************************************************//**
	@brief 
***************************************************************************/
SSL_CTX* Context::getClientCtx() {
  if(!clientCtx_) {
    clientCtx_ = SSL_CTX_new(SSLv23_client_method());
  }
  return clientCtx_;
}
/***********************************************************************//**
	@brief 
***************************************************************************/
SSL_CTX* Context::getServerCtx() {
  if(!serverCtx_) {
    setupCertificate();
    serverCtx_ = SSL_CTX_new(SSLv23_server_method());
  }
  return serverCtx_;
}
/***********************************************************************//**
	@brief 証明書のセットアップ
***************************************************************************/
void Context::setupCertificate() {
  BIGNUM* bn = BN_new();
  {
    auto ret = BN_set_word(bn, RSA_F4);
    assert(ret == 1);
  }
  rsa_ = RSA_new();
  {
    auto ret = RSA_generate_key_ex(rsa_, 2048, bn, nullptr);
    assert(ret == 1);
  }
  pkey_ = EVP_PKEY_new();
  {
    auto ret = EVP_PKEY_set1_RSA(pkey_, rsa_);
    assert(ret == 1);
  }
  BN_free(bn);

  x509_ = X509_new();
  X509_gmtime_adj(X509_get_notBefore(x509_), 0);
  X509_gmtime_adj(X509_get_notAfter(x509_), 60 * 60 * 24);
  X509_set_pubkey(x509_, pkey_);
  X509_sign(x509_, pkey_, EVP_sha1());
}
/***********************************************************************//**
	$Id$
***************************************************************************/
}
