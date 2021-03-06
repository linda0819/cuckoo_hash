#include <stdint.h>  
#include <assert.h>  
#include<stdio.h>
#include<iostream>
#include<functional>
#include "llhcuckoo.h"
#include "sha1.h"
using namespace std;

#define urlnumber 8

/***************���Ժ���***************************/
int main()
{
	int ret = 0;
	size_t  test_buflen[urlnumber];
	static unsigned char test_buf[urlnumber][30] = {
		{ "www.baidu.com" },
		{ "www.sina.com" },
		{ "www.csdn.com" },
		{ "google.com" },
		{ "www.qunaer.com" },
		{ "muduo.com.cn" },
		{ "www.ouc.edu.cn" },
		{ "www.sina.com" }
	};

	cuckoo_hash hash_table;

	for (int i = 0; i < urlnumber; i++)
	{
		test_buflen[i] = countlength(test_buf[i]);
	}
	unsigned char result[32] = { 0 };
	for (size_t i = 0; i < urlnumber; ++i)
	{
		ZEN_LIB::sha1(test_buf[i],(const size_t)test_buflen[i], result);
		hash_table.cuckoo_hash_put(result);
	}
	hash_table.print();
	system("pause");
	return 0;
}

/***************����sha1�����㷨***************************/
//int main()
//{
//	int ret = 0;
//	static unsigned char test_buf[7][81] =
//	{
//		{ "" },
//		{ "a" },
//		{ "abc" },
//		{ "message digest" },
//		{ "abcdefghijklmnopqrstuvwxyz" },
//		{ "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" },
//		{ "12345678901234567890123456789012345678901234567890123456789012345678901234567890" }
//	};
//
//	static const size_t test_buflen[7] =
//	{
//		0, 1, 3, 14, 26, 62, 80  //(�ַ�����С)
//	};
//	unsigned char result[32] = { 0 };
//	static const unsigned char sha1_test_sum[7][20] =
//	{
//		{ 0xda,0x39,0xa3,0xee,0x5e,0x6b,0x4b,0x0d,0x32,0x55,0xbf,0xef,0x95,0x60,0x18,0x90,0xaf,0xd8,0x07,0x09 },
//		{ 0x86,0xf7,0xe4,0x37,0xfa,0xa5,0xa7,0xfc,0xe1,0x5d,0x1d,0xdc,0xb9,0xea,0xea,0xea,0x37,0x76,0x67,0xb8 },
//		{ 0xa9,0x99,0x3e,0x36,0x47,0x06,0x81,0x6a,0xba,0x3e,0x25,0x71,0x78,0x50,0xc2,0x6c,0x9c,0xd0,0xd8,0x9d },
//		{ 0xc1,0x22,0x52,0xce,0xda,0x8b,0xe8,0x99,0x4d,0x5f,0xa0,0x29,0x0a,0x47,0x23,0x1c,0x1d,0x16,0xaa,0xe3 },
//		{ 0x32,0xd1,0x0c,0x7b,0x8c,0xf9,0x65,0x70,0xca,0x04,0xce,0x37,0xf2,0xa1,0x9d,0x84,0x24,0x0d,0x3a,0x89 },
//		{ 0x76,0x1c,0x45,0x7b,0xf7,0x3b,0x14,0xd2,0x7e,0x9e,0x92,0x65,0xc4,0x6f,0x4b,0x4d,0xda,0x11,0xf9,0x40 },
//		{ 0x50,0xab,0xf5,0x70,0x6a,0x15,0x09,0x90,0xa0,0x8b,0x2c,0x5e,0xa4,0x0f,0xa0,0xe5,0x85,0x55,0x47,0x32 },
//	};
//	for (size_t i = 0; i < 7; ++i)
//	{
//		ZEN_LIB::sha1(test_buf[i], test_buflen[i], result);
//		for (int j = 0; j< 20; j++)
//		{
//			printf("%x", result[j]);
//		}
//		ret = memcmp(result, sha1_test_sum[i], 20);
//		if (ret != 0)
//		{
//			cout << "false" << endl;
//		}		
//	}
//	system("pause");
//	return 0;
//}
