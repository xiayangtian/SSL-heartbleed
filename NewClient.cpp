// Client.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include "pch.h"
#include <iostream>
#include <fstream>
#include <stdio.h>  
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <openssl/bio.h>
#include <openssl/des.h>
#include <openssl/buffer.h>
#include <random>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <winsock.h>
#include <openssl/rand.h>
#pragma comment(lib,"ws2_32.lib") 
#pragma comment(lib,"libeay32.lib")
#pragma comment(lib,"ssleay32.lib")


int main()
{
	int err;
	int sd;
	struct sockaddr_in sa;
	SSL_CTX* ctx;
	SSL* ssl;
	X509* server_cert;

	char* str;
	char buf[4096];
	const SSL_METHOD *meth;
	int seed_int[100];
	WSADATA wsaData;

	WSAStartup(MAKEWORD(2, 2), &wsaData);

	SSL_library_init();
	SSL_load_error_strings();
	//meth = TLSv1_client_method();
	meth = SSLv23_client_method();
	ctx = SSL_CTX_new(meth);
	

	SSL_CTX_load_verify_locations(ctx, "cert/ca.pem", NULL);

	SSL_CTX_use_certificate_file(ctx, "cert/client.pem", SSL_FILETYPE_PEM);

	SSL_CTX_use_PrivateKey_file(ctx, "cert/client.key", SSL_FILETYPE_PEM);

	if (!SSL_CTX_check_private_key(ctx))
	{
		printf("私钥与证书不相符\n");
		exit(1);
	}
	printf("*******************\n");
	printf("初始化完成...\n");
	printf("*******************\n\n");

	printf("*******************\n");
	printf("开始TCP连接...\n");
	
	sd = socket(AF_INET, SOCK_STREAM, 0);
	memset(&sa, '\0', sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = inet_addr("127.0.0.1");
	sa.sin_port = htons(4433);
	err = connect(sd, (struct sockaddr*)&sa, sizeof(sa));

	printf("完成TCP连接...\n");
	printf("*******************\n\n");

	printf("*******************\n");
	printf("开始SSL连接...\n");

	ssl = SSL_new(ctx);


	SSL_set_fd(ssl, sd);
	err = SSL_connect(ssl);


	printf("SSL连接完成...\n");
	printf("*******************\n\n");


	printf("*******************\n");
	printf("开始SSL数据交换...\n");
	do {
		printf("客户端:");
		gets_s(buf);
		err = SSL_write(ssl, buf, strlen(buf));
		
		err = SSL_read(ssl, buf, 4095);
		buf[err] = '\0';
		printf("服务器:%s\n", buf);
	} while (strcmp(buf, "bye"));
	printf("*******************\n");
	


	//通信结束，释放资源
	closesocket(sd);
	SSL_shutdown(ssl);
	SSL_free(ssl);
	SSL_CTX_free(ctx);
	system("pause");
	return 0;
}

