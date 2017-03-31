#include "llhcuckoo.h"

log_entry::log_entry(unsigned char value[30], unsigned char key[20])
{
	int index = 0;
	while (value[index] != '\0')
	{
		data[index] = value[index];
		index++;
	}
	for (int i = 0; i < 20; i++)
	{
		sha1[i] = key[i];
	}
}

cuckoo_hash::cuckoo_hash()
{
	slot = new slotnode[slotsize];
	bucket = new slotnode*[slotsize / slotnumber];
	for (int i = 0; i < slotsize/ slotnumber; i++)
	{
		bucket[i] = &slot[slotnumber * i];
	}
}
void cuckoo_hash::cuckoo_hash_puttag(unsigned int key1, unsigned int key2)
{
	int index1 = 0, index2 = 0;
	while (bucket[key1][index1].getstatus() != AVAILIBLE && (index1 < slotnumber)) {
		if (bucket[key1][index1].sametag(key1, key2))  return;
		index1++;
	}
	if (bucket[key1][index1].getstatus() == AVAILIBLE)
	{
		bucket[key1][index1].setstatus(OCCUPIED);
		bucket[key1][index1].settag(key1, key2);
	}
	else if (index1 == slotnumber)
	{
		while (bucket[key2][index2].getstatus() != AVAILIBLE && (index2 < slotnumber)) {
			if (bucket[key2][index2].sametag(key2, key1))  return;
			index2++;
		}
		if (bucket[key2][index2].getstatus() == AVAILIBLE)
		{
			bucket[key2][index2].setstatus(OCCUPIED);
			bucket[key2][index2].settag(key2, key1);
		}
		else
			cuckoo_hash_collide(key1, key2);
	}

}
void cuckoo_hash::cuckoo_hash_put(unsigned char *result)
{

	    int index1 = 0,index2=0;
		int key_num1 = slotsize / slotnumber;
		int key_num=next_pow_of_2(key_num1);
		unsigned int key1= cuckoo_hash_lsb(result, key_num)% key_num1;
		unsigned int key2= cuckoo_hash_msb(result, key_num)% key_num1;
		while(bucket[key1][index1].getstatus() != AVAILIBLE&&(index1<slotnumber)){
			if (bucket[key1][index1].sametag(key1, key2))  return;
			index1++;
	   }
		if (bucket[key1][index1].getstatus() == AVAILIBLE)
		{
			bucket[key1][index1].setstatus(OCCUPIED);
			bucket[key1][index1].settag(key1, key2);
		}
		else if (index1 == slotnumber)
		{
			while (bucket[key2][index2].getstatus() != AVAILIBLE && (index2 < slotnumber)) {
				if (bucket[key2][index2].sametag(key2, key1))  return;
				index2++;
			}
			if (bucket[key2][index2].getstatus() == AVAILIBLE)
			{
				bucket[key2][index2].setstatus(OCCUPIED);
				bucket[key2][index2].settag(key2, key1);
			}
			else
				cuckoo_hash_collide(key1,key2);
		}
}

void cuckoo_hash::cuckoo_hash_collide(unsigned int key1, unsigned int key2)
{
	collidenumber++;
	unsigned int old_tag[2];
	old_tag[0] = key1;
	int index2 = 0;
	old_tag[1] = bucket[key1][0].gettag();
	bucket[key1][0].settag(key1, key2);
	while (bucket[old_tag[1]][index2].getstatus() != AVAILIBLE && (index2 < slotnumber))
	{
		index2++;
	}
	if (bucket[old_tag[1]][index2].getstatus() == AVAILIBLE)
	{
		bucket[old_tag[1]][index2].setstatus(OCCUPIED);
		bucket[old_tag[1]][index2].settag(old_tag[1], old_tag[0]);
	}
	else if (index2 == slotnumber)
		cuckoo_hash_collide(old_tag[1], old_tag[0]);
	int temp = slotsize / slotnumber;
	if (collidenumber == temp)
	{
		re_hash();
	}
}

#ifdef DEBUG
void cuckoo_hash::print()
{
	for (int i = 0; i < 25; i++)
		for (int j = 0; j < 4; j++)
		{
			if (bucket[i][j].getstatus() == OCCUPIED)
				printf("%d %d\r\n", i,bucket[i][j].gettag());
		}
}
#endif
void cuckoo_hash::re_hash()
{
	slotnode *old_slot = slot;
	slotnode **old_bucket = bucket;
	int old_slotsize = slotsize;
	slotsize *= 2;
	slot = new slotnode[slotsize];
	bucket = &slot;
	for (int i = 0; i < slotsize / slotnumber; i++)
	{
		bucket[i] = &slot[slotnumber * i];
	}
	for (int i = 0; i < old_slotsize; i++)
	{
		if (old_slot[i].getstatus() == OCCUPIED)
			cuckoo_hash_puttag(i, old_slot[i].gettag());
	}
	delete []old_slot;
}