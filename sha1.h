#ifndef SHA1
/****************************
SHA1�㷨����ȫ��ϣ�㷨
���ڳ���С��2^64λ����Ϣ��SHA1�����һ��20λ����ϢժҪ��
�����յ���Ϣ��ʱ�������ϢժҪ����������֤���ݵ������ԡ�
�ڴ���Ĺ����У����ݺܿ��ܻᷢ���仯����ô��ʱ��ͻ������ͬ����ϢժҪ��
SHA1���������ԣ�
1.�����Դ���ϢժҪ�и�ԭ��Ϣ��
2.������ͬ����Ϣ�������ͬ������ϢժҪ��
******************************/
//�ֽ����Сͷ�ʹ�ͷ������  
#define ZEN_LITTLE_ENDIAN  0x0123  
#define ZEN_BIG_ENDIAN     0x3210  
#ifndef ZEN_BYTES_ORDER  
#define ZEN_BYTES_ORDER    ZEN_LITTLE_ENDIAN  
#endif  

#ifndef ZEN_SWAP_UINT16  
#define ZEN_SWAP_UINT16(x)  ((((x) & 0xff00) >>  8) | (((x) & 0x00ff) <<  8))  
#endif  
#ifndef ZEN_SWAP_UINT32  
#define ZEN_SWAP_UINT32(x)  ((((x) & 0xff000000) >> 24) | (((x) & 0x00ff0000) >>  8) |(((x)& 0x0000ff00) << 8) | (((x)& 0x000000ff) << 24))
#endif  
#ifndef ZEN_SWAP_UINT64  
#define ZEN_SWAP_UINT64(x)  ((((x) & 0xff00000000000000) >> 56) | (((x) & 0x00ff000000000000) >>  40) | (((x)& 0x0000ff0000000000) >> 24) | (((x)& 0x000000ff00000000) >> 8) | (((x)& 0x00000000ff000000) << 8) | (((x)& 0x0000000000ff0000) << 24) |(((x)& 0x000000000000ff00) << 40) | (((x)& 0x00000000000000ff) << 56))
#endif 
//ÿ�δ����BLOCK�Ĵ�С  
#define ROTL32(dword, n) ((dword) << (n) ^ ((dword) >> (32 - (n))))  
#define ROTR32(dword, n) ((dword) >> (n) ^ ((dword) << (32 - (n))))  
#define ROTL64(qword, n) ((qword) << (n) ^ ((qword) >> (64 - (n))))  
#define ROTR64(qword, n) ((qword) >> (n) ^ ((qword) << (64 - (n)))) 
void *swap_uint32_memcpy(void *to, const void *from, size_t length)
{
	memcpy(to, from, length);
	size_t remain_len = (4 - (length & 3)) & 3;
	//���ݲ���4�ֽڵı���,����0  
	if (remain_len)
	{
		for (size_t i = 0; i < remain_len; ++i)
		{
			*((char *)(to)+length + i) = 0;
		}
		//������4�ı���  
		length += remain_len;
	}
	//���е����ݷ�ת  
	for (size_t i = 0; i < length / 4; ++i)
	{
		((uint32_t *)to)[i] = ZEN_SWAP_UINT32(((uint32_t *)to)[i]);
	}
	return to;
}
///SHA1�Ľ�����ݳ���  
static const size_t ZEN_SHA1_HASH_SIZE = 20;

namespace ZEN_LIB
{
	/*!
	@brief      ���ڴ��BUFFER��SHA1ֵ
	@return     unsigned char* ���صĵĽ��
	@param[in]  buf    ��SHA1���ڴ�BUFFERָ��
	@param[in]  size   BUFFER����
	@param[out] result ���
	*/
	unsigned char *sha1(const unsigned char *buf,
		size_t size,
		unsigned char result[ZEN_SHA1_HASH_SIZE]);
};

static const size_t ZEN_SHA1_BLOCK_SIZE = 64;
//SHA1�㷨�������ģ�����һЩ״̬���м����ݣ����  
typedef struct sha1_ctx
{

	//��������ݵĳ���  
	uint64_t length_;
	//��û�д�������ݳ���  
	uint64_t unprocessed_;
	/* 160-bit algorithm internal hashing state */
	uint32_t hash_[5];
} sha1_ctx;

//�ڲ�������SHA1�㷨�������ĵĳ�ʼ��  
static void zen_sha1_init(sha1_ctx *ctx)
{
	ctx->length_ = 0;
	ctx->unprocessed_ = 0;
	// ��ʼ���㷨�ļ���������ħ����  
	ctx->hash_[0] = 0x67452301;
	ctx->hash_[1] = 0xefcdab89;
	ctx->hash_[2] = 0x98badcfe;
	ctx->hash_[3] = 0x10325476;
	ctx->hash_[4] = 0xc3d2e1f0;
}
/*!
@brief      �ڲ���������һ��64bit�ڴ�����ժҪ(�Ӵ�)����
@param      hash  ��ż���hash����ĵ�����
@param      block Ҫ����Ĵ�����ڴ��
*/
static void zen_sha1_process_block(uint32_t hash[5],
	const uint32_t block[ZEN_SHA1_BLOCK_SIZE / 4])
{
	size_t        t;
	uint32_t      wblock[80];
	register uint32_t      a, b, c, d, e, temp;
	//SHA1�㷨������ڲ�����Ҫ���Ǵ�ͷ���ģ���Сͷ�Ļ���ת��  
#if ZEN_BYTES_ORDER == ZEN_LITTLE_ENDIAN  
	swap_uint32_memcpy(wblock, block, ZEN_SHA1_BLOCK_SIZE);
#else  
	::memcpy(wblock, block, ZEN_SHA1_BLOCK_SIZE);
#endif  
	//����  
	for (t = 16; t < 80; t++)
	{
		wblock[t] = ROTL32(wblock[t - 3] ^ wblock[t - 8] ^ wblock[t - 14] ^ wblock[t - 16], 1);
	}
	a = hash[0];
	b = hash[1];
	c = hash[2];
	d = hash[3];
	e = hash[4];

	for (t = 0; t < 20; t++)
	{
		/* the following is faster than ((B & C) | ((~B) & D)) */
		temp = ROTL32(a, 5) + (((c ^ d) & b) ^ d)
			+ e + wblock[t] + 0x5A827999;
		e = d;
		d = c;
		c = ROTL32(b, 30);
		b = a;
		a = temp;
	}

	for (t = 20; t < 40; t++)
	{
		temp = ROTL32(a, 5) + (b ^ c ^ d) + e + wblock[t] + 0x6ED9EBA1;
		e = d;
		d = c;
		c = ROTL32(b, 30);
		b = a;
		a = temp;
	}

	for (t = 40; t < 60; t++)
	{
		temp = ROTL32(a, 5) + ((b & c) | (b & d) | (c & d))
			+ e + wblock[t] + 0x8F1BBCDC;
		e = d;
		d = c;
		c = ROTL32(b, 30);
		b = a;
		a = temp;
	}

	for (t = 60; t < 80; t++)
	{
		temp = ROTL32(a, 5) + (b ^ c ^ d) + e + wblock[t] + 0xCA62C1D6;
		e = d;
		d = c;
		c = ROTL32(b, 30);
		b = a;
		a = temp;
	}

	hash[0] += a;
	hash[1] += b;
	hash[2] += c;
	hash[3] += d;
	hash[4] += e;
}

/*!
@brief      �ڲ��������������ݵ�ǰ�沿��(>64�ֽڵĲ���)��ÿ�����һ��64�ֽڵ�block�ͽ����Ӵմ���
@param      ctx  �㷨�������ģ���¼�м����ݣ������
@param      msg  Ҫ���м��������buffer
@param      size ����
*/
static void zen_sha1_update(sha1_ctx *ctx,
	const unsigned char *buf,
	size_t size)
{
	//Ϊ����zen_sha1_update���Զ�ν��룬���ȿ����ۼ�  
	ctx->length_ += size;

	//ÿ������Ŀ鶼��64�ֽ�  
	while (size >= ZEN_SHA1_BLOCK_SIZE)
	{
		zen_sha1_process_block(ctx->hash_, reinterpret_cast<const uint32_t *>(buf));
		buf += ZEN_SHA1_BLOCK_SIZE;
		size -= ZEN_SHA1_BLOCK_SIZE;
	}

	ctx->unprocessed_ = size;
}
/*!
@brief      �ڲ��������������ݵ���󲿷֣����0x80,��0�����ӳ�����Ϣ
@param      ctx    �㷨�������ģ���¼�м����ݣ������
@param      msg    Ҫ���м��������buffer
@param      result ���صĽ��
*/
static void zen_sha1_final(sha1_ctx *ctx,
	const unsigned char *msg,
	size_t size,
	unsigned char *result)
{

	uint32_t message[ZEN_SHA1_BLOCK_SIZE / 4];
	//����ʣ������ݣ�����Ҫƴ�����1��������������Ҫ����Ŀ飬ǰ����㷨��֤�ˣ����һ����϶�С��64���ֽ�  
	if (ctx->unprocessed_)
	{
		memcpy(message, msg + size - ctx->unprocessed_, static_cast<size_t>(ctx->unprocessed_));
	}

	//�õ�0x80Ҫ����ڵ�λ�ã���uint32_t �����У���  
	uint32_t index = ((uint32_t)ctx->length_ & 63) >> 2;
	uint32_t shift = ((uint32_t)ctx->length_ & 3) * 8;

	//���0x80��ȥ�����Ұ����µĿռ䲹��0  
	message[index] &= ~(0xFFFFFFFF << shift);
	message[index++] ^= 0x80 << shift;

	//������block���޷����������ĳ����޷����ɳ���64bit����ô�ȴ������block  
	if (index > 14)
	{
		while (index < 16)
		{
			message[index++] = 0;
		}

		zen_sha1_process_block(ctx->hash_, message);
		index = 0;
	}
	//��0  
	while (index < 14)
	{
		message[index++] = 0;
	}

	//���泤�ȣ�ע����bitλ�ĳ���,����������ҿ��������˰��죬  
	uint64_t data_len = (ctx->length_) << 3;

	//ע��SHA1�㷨Ҫ���64bit�ĳ����Ǵ�ͷBIG-ENDIAN����Сͷ������Ҫ����ת��  
#if ZEN_BYTES_ORDER == ZEN_LITTLE_ENDIAN  
	data_len = ZEN_SWAP_UINT64(data_len);
#endif  

	message[14] = (uint32_t)(data_len & 0x00000000FFFFFFFF);
	message[15] = (uint32_t)((data_len & 0xFFFFFFFF00000000ULL) >> 32);

	zen_sha1_process_block(ctx->hash_, message);

	//ע�����Ǵ�ͷ���ģ���Сͷ������Ҫ����ת��  
#if ZEN_BYTES_ORDER == ZEN_LITTLE_ENDIAN  
	swap_uint32_memcpy(result, &ctx->hash_, ZEN_SHA1_HASH_SIZE);
#else  
	memcpy(result, &ctx->hash_, ZEN_SHA1_HASH_SIZE);
#endif  
}

//����һ���ڴ����ݵ�SHA1ֵ  
unsigned char *ZEN_LIB::sha1(const unsigned char *msg,
	size_t size,
	unsigned char result[ZEN_SHA1_HASH_SIZE])
{
	assert(result != NULL);
	sha1_ctx ctx;
	zen_sha1_init(&ctx);
	zen_sha1_update(&ctx, msg, size);
	zen_sha1_final(&ctx, msg, size, result);
	return result;
}
int countlength(unsigned char *p)
{
	int count = 0;
	while (*(p++) != '\0')
		count++;
	return count;
}

#endif // !SHA1

