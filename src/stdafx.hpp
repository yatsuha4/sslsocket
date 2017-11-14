/***********************************************************************//**
	@file
***************************************************************************/
#include <arpa/inet.h>
#include <assert.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <netdb.h>

#include <iostream>
#include <memory>

#include "openssl/bn.h"
#include "openssl/err.h"
#include "openssl/ssl.h"
#include "openssl/x509.h"
/***********************************************************************//**
	@brief 
***************************************************************************/
namespace sslsocket {
class Context;
class Socket;
}
/***********************************************************************//**
	$Id$
***************************************************************************/
