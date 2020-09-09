// NewServer.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include "pch.h"
#include <iostream>
#include <winsock.h>
#include <stdio.h>
#include <iostream>
#include <fstream>
#include <stdio.h>  
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <openssl/bio.h>
#include <openssl/des.h>
#include <openssl/buffer.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdlib.h>
#include <string.h>
#pragma comment(lib, "libeay32.lib")
#pragma comment(lib, "ssleay32.lib")
#pragma comment(lib, "ws2_32.lib")


int main()
{
	int err;
	int listen_sd;
	int sd;
	struct sockaddr_in sock_server;
	struct sockaddr_in sock_temp;
	int client_len;
	SSL_CTX* ctx;
	SSL* ssl;
	X509* client_cert;
	char* str;
	char buf[4096];
	const SSL_METHOD *meth;
	WSADATA wsaData;

	//绑定socket库
	WSAStartup(MAKEWORD(2, 2), &wsaData);
	

	//打印调试信息
	SSL_load_error_strings();

	//ssl库初始化
	SSL_library_init();
	//OpenSSL_add_ssl_algorithms();

	//选择协议
	meth = SSLv23_server_method();

	//申请SSL会话环境
	ctx = SSL_CTX_new(meth);


	//加载CA证书
	SSL_CTX_load_verify_locations(ctx, "cert/ca.pem", NULL);

	//加载服务器证书
	SSL_CTX_use_certificate_file(ctx, "cert/server.pem", SSL_FILETYPE_PEM);


	

	//加载服务器私钥
	SSL_CTX_use_PrivateKey_file(ctx, "cert/server.key", SSL_FILETYPE_PEM);
	
	//验证私钥与证书是否相符
	if (!SSL_CTX_check_private_key(ctx))
	{
		printf("私钥与证书不相符\n");
		exit(1);
	}

	//设置加密算法
	//SSL_CTX_set_cipher_list(ctx, "TLS_RSA_WITH_NULL_SHA");

	printf("*******************\n");
	printf("初始化完成...\n");
	printf("*******************\n\n");
	//开始正常的TCP socket过程
	printf("*******************\n");
	printf("开始TCP连接...\n");

	//选用ipv4协议，tcp连接，建立套接字
	listen_sd = socket(AF_INET, SOCK_STREAM, 0);
	
	//为socket地址分配空间
	memset(&sock_server, '\0', sizeof(sock_server));
	//选用ipv4
	sock_server.sin_family = AF_INET;
	//分配ip地址，接受本机所有地址
	sock_server.sin_addr.s_addr = INADDR_ANY;
	//分配端口号
	sock_server.sin_port = htons(4433);
	//绑定套接字和协议地址
	err = bind(listen_sd, (struct sockaddr*) &sock_server, sizeof(sock_server));
	
	//指定队列大小
	err = listen(listen_sd, 5);

	client_len = sizeof(sock_temp);
	printf("等待客户端TCP连接...\n");
	sd = accept(listen_sd, (struct sockaddr*) &sock_temp, &client_len);
	//打印通信地址
	struct in_addr addr1;
	unsigned long l1;
	l1 = sock_temp.sin_addr.s_addr;
	memcpy(&addr1, &l1, 4);
	printf("连接IP： %s, 端口号： %d\n", inet_ntoa(addr1), ntohs(sock_server.sin_port));
	//连接达成
	printf("*******************\n\n");
	printf("*******************\n");
	printf("开始 SSL 连接...\n");
	//创建SSL套接字
	ssl = SSL_new(ctx);
	//绑定套接字
	SSL_set_fd(ssl, sd);
	//接受SSL连接请求
	err = SSL_accept(ssl);
	printf("SSL连接完成...\n");

	printf("*******************\n\n");
	//数据交换
	printf("*******************\n");
	printf("开始SSL数据交换...\n");
	do {
		err = SSL_read(ssl, buf, sizeof(buf) - 1);
		buf[err] = '\0';
		printf("客户端:%s\n", buf);
		printf("服务器:");
		gets_s(buf);
		err = SSL_write(ssl, buf, strlen(buf));
	} while (strcmp(buf, "bye"));
	printf("*******************\n");


	//通信结束，释放资源

	closesocket(listen_sd);
	SSL_shutdown(ssl);
	SSL_free(ssl);
	SSL_CTX_free(ctx);
	system("pause");
	return 0;
}
