
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

//r specifies the per-round shift amounts
const uint32_t r[64] = { 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
};

//const uint32_t k[64] = {
//	0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
//	0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
//	0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
//	0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
//	0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
//	0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
//	0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
//	0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
//	0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
//	0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
//	0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
//	0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
//	0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
//	0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
//	0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
//	0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391 };

void to_bytes(uint32_t val, uint8_t *bytes)
{
	bytes[0] = (uint8_t)val;
	bytes[1] = (uint8_t)(val >> 8);
	bytes[2] = (uint8_t)(val >> 16);
	bytes[3] = (uint8_t)(val >> 24);
}

uint32_t to_int32(const uint8_t *bytes)
{
	return (uint32_t)bytes[0]
		| ((uint32_t)bytes[1] << 8)
		| ((uint32_t)bytes[2] << 16)
		| ((uint32_t)bytes[3] << 24);
}

// leftrotate function definition
#define LEFTROTATE(x, c) (((x) << (c)) | ((x) >> (32 - (c))))

void md5(const uint8_t *message, size_t msg_len, uint8_t *digest) {

	//Use binary integer part of the sines of integers as constants:
	uint32_t k[64];
	for (int i = 0; i < 64; i++){
		k[i] = floor(abs(sin((double)i + 1)) * pow((double)2, 32));
        printf("%d",pow(2.0,4.0));
	}
    printf("%s","\n");

	uint32_t h0, h1, h2, h3;
	//Initialize variables:
	h0 = 0x67452301;
	h1 = 0xEFCDAB89;
	h2 = 0x98BADCFE;
	h3 = 0x10325476;

	//Pre-processing:
	// append "1" bit to message
	// append "0" bits until message length in bits ≡ 448 (mod 512)
	const uint32_t d_512 = 512 / 8;
	const uint32_t d_448 = 448 / 8;
	size_t new_len = msg_len + (d_512 - (msg_len - d_448 + d_512) % d_512);
	// for (new_len = msg_len + 1; new_len % (512/8) != 448/8; new_len++);

	uint8_t* msg = (uint8_t*)malloc(new_len + 8);
	memcpy(msg, message, msg_len);
	msg[msg_len] = 0x80; // append the "1" bit; most significant bit is "first"
	for (uint32_t offset = msg_len + 1; offset < new_len; offset++)
		msg[offset] = 0; // append "0" bits

	// to_bytes(msg_len*8, msg + new_len);
	// to_bytes(msg_len>>29, msg + new_len + 4);
	uint32_t* msg_leninfo = (uint32_t*)(msg + new_len);
	msg_leninfo[0] = msg_len * 8;
	msg_leninfo[1] = msg_len >> 29;
	// append bit length of message as 64-bit little-endian integer to message

	//Process the message in successive 512-bit chunks:
	for (uint32_t offset = 0; offset < new_len; offset += (512 / 8)) {

		uint32_t w[16];
		uint32_t a, b, c, d, f, g;

		// break chunk into sixteen 32-bit words w[j], 0 ≤ j ≤ 15
		for (uint32_t i = 0; i < 16; i++)
			w[i] = to_int32(msg + offset + i * 4);

		// Initialize hash value for this chunk:
		a = h0;
		b = h1;
		c = h2;
		d = h3;

		// Main loop:
		for (uint32_t i = 0; i < 64; i++) {

			if (i < 16) {
				f = (b & c) | ((~b) & d);
				g = i;
			}
			else if (i < 32) {
				f = (d & b) | ((~d) & c);
				g = (5 * i + 1) % 16;
			}
			else if (i < 48) {
				f = b ^ c ^ d;
				g = (3 * i + 5) % 16;
			}
			else {
				f = c ^ (b | (~d));
				g = (7 * i) % 16;
			}

			uint32_t temp = d;
			d = c;
			c = b;
			b = b + LEFTROTATE((a + f + k[i] + w[g]), r[i]);
			a = temp;

		}

		// Add this chunk's hash to result so far:
		h0 += a;
		h1 += b;
		h2 += c;
		h3 += d;

	}

	// cleanup
	free(msg);

	//var char digest[16] := h0 append h1 append h2 append h3 //(Output is in little-endian)
	to_bytes(h0, digest);
	to_bytes(h1, digest + 4);
	to_bytes(h2, digest + 8);
	to_bytes(h3, digest + 12);
}

int main(int argc, char **argv) {
	char *msg = argv[1];
	size_t len;
	int i;
	uint8_t result[16];

	if (argc < 2) {
		printf("usage: %s 'string'\n", argv[0]);
		return 1;
	}

	len = strlen(msg);

	// benchmark
	for (i = 0; i < 1; i++) {
		md5((uint8_t*)msg, len, result);
	}

	// display result
	for (i = 0; i < 16; i++)
		printf("%2.2x", result[i]);
	puts("");

	return 0;
}
