#ifndef LLHCUCKOO_H
#include<stdio.h>
#include<iostream>
const static int slotnumber = 4;
static int slotsize = 100;
static int collidenumber = 0;
#define cuckoo_hash_lsb(key, count)  (((size_t *)(key))[0] & (count - 1))
#define cuckoo_hash_msb(key, count)  (((size_t *)(key))[1] & (count - 1))
#define DEBUG
class slotnode;
enum EnumTest{
	AVAILIBLE, OCCUPIED, DELETED,
};
class log_entry {
public:
	log_entry(unsigned char value[30], unsigned char key[20]);
	~log_entry() {};
private:
	unsigned char sha1[20];
	unsigned char data[30];
};
class cuckoo_hash {
public:
	cuckoo_hash();
	~cuckoo_hash() { delete[]slot; }
	void cuckoo_hash_put(unsigned char *result);
	void cuckoo_hash_collide(unsigned int key1, unsigned int key2);
	void cuckoo_hash_puttag(unsigned int key1, unsigned int key2);
	void re_hash();
#ifdef DEBUG
	void print();
#endif
private:
	slotnode **bucket = NULL;
	slotnode *slot = NULL;
};

class slotnode {
public:
	slotnode()
	{
		status = AVAILIBLE;
		tag[0] = 0;
		tag[1] = 0;
	}
	~slotnode() {}
	void setstatus(enum EnumTest sta) { status = sta; }
	void settag(unsigned int tag0, unsigned int tag1) { 
		tag[0] = tag0;
		tag[1] = tag1;
	}
	unsigned int gettag() { return tag[1]; }
	enum EnumTest getstatus()
	{
		return status;
	}
	bool sametag(unsigned int key1, unsigned int key2)
	{
		return (tag[0] == key1) && (tag[1] == key2);
	}

private:
	enum EnumTest status;
	unsigned int tag[2];
};



static inline int is_pow_of_2(uint32_t x)
{
	return !(x & (x - 1));  //判断一个数(x)是否是2的n次方
}
/*********************
函数名：next_pow_of_2();
作用：将unsigned int类型的数据向上补齐至2的n次方
********************/
static inline uint32_t next_pow_of_2(uint32_t x)
{
	if (is_pow_of_2(x))   //如果文件大小是2的n次方，直接返回
		return x;
	x |= x >> 1;
	x |= x >> 2;
	x |= x >> 4;
	x |= x >> 8;
	x |= x >> 16;
	return x + 1;        //将低5位置0
}
#endif // !LLHCUCKOO_H
