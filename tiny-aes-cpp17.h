#pragma once

/*
This is a small implementation of AES in modern(ish) C++. Currently only AES 128 CBC is supported.
Works in Visual Studio 2017 and 2019.

	Usage:
	aes encrypter;
	expandedKeys expKeys = {};
	
	encrypter.expandKeys(expKeys, key);
	encrypter.encrypt(expKeys, iv, buffer, filesize);
*/

#include <cstring>
#include <functional>
#include <array>

// AES block length is always 16
constexpr uint8_t blocklen = 16;

// AES blocks are divided into 4 rows of 4 bytes each. Bytes is also the number of 'columns'
constexpr uint8_t bytes = 4;
constexpr uint8_t rows = 4;

// AES128 = 10 rounds
constexpr uint8_t rounds = 10;

// Convert each 16 byte block into a vector of vectors.
using wordtype = std::array<uint8_t, bytes>;
using blocktype = std::array<wordtype, rows>;

constexpr int boxsize = blocklen * blocklen;
constexpr std::array<uint8_t, 5> short_range = { 0, 1, 2, 3, 4 };
std::vector<uint8_t> range(uint8_t end)
{
	return std::vector<uint8_t>(short_range.begin(), short_range.begin() + end + 1);
}

// Helper to loop over a block, apply f() to each element
void loopAll(blocktype& block1, std::function<void(const uint8_t&)> f)
{
	for (auto i = 0; i < rows; ++i)
		for (auto j = 0; j < bytes; ++j)
			f(block1.at(i).at(j));
}

void loopAll(wordtype& dest, const wordtype& word1, const wordtype& word2, std::function<void(uint8_t&, const uint8_t&, const uint8_t&)> f)
{
	for (auto j = 0; j < bytes; ++j)
		f(dest.at(j), word1.at(j), word2.at(j));
}

// Helper to loop over tow block, apply f() to corresponding elements in each block
void loopAll(blocktype& block1, const blocktype& block2, std::function<void(uint8_t&, const uint8_t&)> f)
{
	for (auto i = 0; i < rows; ++i)
		for (auto j = 0; j < bytes; ++j)
			f(block1.at(i).at(j), block2.at(i).at(j));
}

//#define PRINTING

#ifdef PRINTING
#include <fstream>
#include <intrin.h>
#include <iostream>
#include <iomanip>

// Print block as hex
void printbuffer(blocktype& buf)
{
	loopAll(buf, [](const uint8_t& x) -> void { std::cout << std::setw(2) << std::setfill('0') << std::hex << (int)x; });
	std::cout << std::endl;
	
}

// Print buffer as hex
int printbuf(const unsigned char* buf, const int size)
{
	for (int i = 0; i < size; i++)
	{
		printf("%02x", (unsigned char)buf[i]);
	}
	printf("\n");

	return 0;
}

#else
void printbuffer(blocktype& buf) {};
int printbuf(const unsigned char* buf, const int size) { return 0;  };
#endif

// copy block to block
void copy(blocktype& dest, const blocktype& source)
{
	loopAll(dest, source, [](uint8_t& x, const uint8_t& y) -> void { x = y; });
}

// Copy raw buffer to block
void copyBuffer(blocktype& dest, const uint8_t * source)
{
	for (auto i = 0; i < rows; i++)
		for (auto j = 0; j < bytes; j++)
			dest.at(i).at(j) = source[i * bytes + j];
}

// Copy block back to raw buffer
void copyToBuffer(uint8_t* dest, const blocktype& source)
{
	for (auto i = 0; i < rows; i++)
		for (auto j = 0; j < bytes; j++)
			dest[i * bytes + j] = source.at(i).at(j);
}


// Handles the keys for each round
struct expandedKeys
{
public:
	expandedKeys()
	{
		std::array<blocktype, rounds + 1> temp = {};
		roundKey.assign(temp.begin(), temp.end());
	}
	blocktype &round(const uint8_t r)
	{
		return roundKey.at(r);
	}

	void copyRound0(const uint8_t* key)
	{
		copyBuffer(roundKey[0], key);
	}

private:
	std::vector<blocktype> roundKey;

};

// Main class
class aes
{
public:
	aes() {}
	virtual ~aes() {}

	// Expand all keys for the rounds from the primary key
	// See https://en.wikipedia.org/wiki/Rijndael_key_schedule
	void expandKeys(expandedKeys& expKeys, const uint8_t *key)
	{
		// The first round key is the key itself
		expKeys.copyRound0(key);

		for (uint8_t round = 1; round < rounds + 1; ++round)
		{
			wordtype temp = {};
			auto tempkey = expKeys.round(round - 1).at(rows - 1);
			temp = tempkey;

			rot(temp, 1);
			applybox(temp, sbox);
			applyxor(temp, rcon.at(round));
			applyxorrow(expKeys.round(round).at(0), expKeys.round(round - 1).at(0), temp);

			for (uint8_t i = 1; i < rows; ++i)
			{
				applyxorrow(expKeys.round(round).at(i), expKeys.round(round - 1).at(i), expKeys.round(round).at(i - 1));
			}
		}
	}

	// Encrypt a block with IV and key
	void encrypt(expandedKeys keys, const uint8_t *iv_in, uint8_t* buffer_in, const size_t size)
	{
		blocktype iv; 
		copyBuffer(iv, iv_in);

		for (auto block = 0; block < size / blocklen; ++block)
		{
			blocktype buffer;
			copyBuffer(buffer, &buffer_in[block * blocklen]);

			applyxorblock(buffer, iv);
			applyxorblock(buffer, keys.round(0));

			for (auto round = 1; round < rounds; ++round)
			{
				applybox(buffer, sbox);
				rotrows(buffer);
				mixcolumns(buffer);
				applyxorblock(buffer, keys.round(round));
			}

			applybox(buffer, sbox);
			rotrows(buffer);
			applyxorblock(buffer, keys.round(rounds));

			copyToBuffer(&buffer_in[block * blocklen], buffer);
			copy(iv, buffer);
		}
	}

	// Decrypt a block with IV and key
	void decrypt(expandedKeys keys, const uint8_t *iv_in, uint8_t* buffer_in, const size_t size)
	{
		blocktype iv; 
		copyBuffer(iv, iv_in);
		blocktype next_iv;

		for (auto block = 0; block < size / blocklen; block++)
		{
			blocktype buffer;
			copyBuffer(buffer, &buffer_in[block * blocklen]);
			copy(next_iv, buffer);
			applyxorblock(buffer, keys.round(rounds));

			for (auto round = rounds - 1; round > 0; --round)
			{
				rotrows_inv(buffer);
				applybox(buffer, rsbox);
				applyxorblock(buffer, keys.round(round));
				mixcolumns_inv(buffer);
			}

			rotrows_inv(buffer);
			applybox(buffer, rsbox);			
			applyxorblock(buffer, keys.round(0));
			applyxorblock(buffer, iv);

			copyToBuffer(&buffer_in[block * blocklen], buffer);
			copy(iv, next_iv);
		}
	}

private:
	using boxtype = const std::array<uint8_t, boxsize>; 

	boxtype sbox {
		0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
		0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
		0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
		0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
		0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
		0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
		0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
		0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
		0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
		0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
		0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
		0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
		0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
		0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
		0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
		0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };

	boxtype rsbox = {
	  0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
	  0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
	  0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
	  0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
	  0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
	  0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
	  0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
	  0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
	  0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
	  0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
	  0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
	  0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
	  0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
	  0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
	  0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
	  0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d };

	const std::array<uint8_t, 11> rcon = { 0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };

	// Rotate a row (4 bytes) n steps
	void rot(wordtype& row, const uint8_t step)
	{
		const wordtype temp(row); 
		for (auto m : range(3))
			row.at(m) = temp.at((m+1)%4);
	}

public:
	// Rotate the whole block based on AES ShiftRows
	void rotrows(blocktype& buf)
	{
		const blocktype temp(buf);
		for (auto a : range(3))
			for (auto b: range(2))
				buf.at(a).at(b+1) = temp.at((a + b + 1) % 4).at(b+1);
	}

	// Rotate the whole block based on AES ShiftRows
	void rotrows_inv(blocktype& buf)
	{
		const blocktype temp(buf);
		for (auto a : range(3))
			for (auto b : range(2))
				buf.at((a + b + 1) % 4).at(b + 1) = temp.at(a).at(b + 1);
	}


	// Apply the s-box to a word
	void applybox(wordtype& row, const boxtype box)
	{
		for (auto& byte : row)
			byte = box.at(byte);
	}

	// Apply s-box to a whole block
	void applybox(blocktype& buffer, const boxtype box)
	{
		for (auto& row : buffer)
			applybox(row, box);
	}

	// Apply a xor for the firts byte, part of the key expansion
	void applyxor(wordtype& row, const uint8_t val)
	{
		row.at(0) ^= val;
	}

	// XOR two rows
	void applyxorrow(wordtype& dest, const wordtype row, const wordtype row2)
	{
		loopAll(dest, row, row2, [](uint8_t& x, const uint8_t& y, const uint8_t& z) -> void { x = y ^ z; });
	}

	// XOR two blocks
	void applyxorblock(blocktype& buffer, const blocktype &val)
	{
		loopAll(buffer, val, [](uint8_t& x, const uint8_t& y) -> void { x ^= y; });
	}

	// h-function used in MixColumns
	constexpr uint8_t h(const uint8_t v)
	{
		return ((v << 1) ^ (((v >> 7) & 1) * 27));
	}

	// AES MixColumns for one row
	void mix(wordtype& buffer)
	{
		const wordtype a(buffer);
		uint8_t temp = 0;
		for (auto m : range(3))
			temp ^= a.at(m);

		for (auto m : range(3))
			buffer.at(m) ^= h(a.at(m) ^ a.at((m+1) % 4)) ^ temp;
	}

	constexpr uint8_t h_pow(const uint8_t v, const uint8_t p)
	{
		uint8_t r = v;
		for (auto i = 1; i <= p; i++)
			r = h(r);	
		return r;
	}
	
	uint8_t mult(const uint8_t v, const uint8_t y)
	{
		uint8_t r=0;
		for (auto m : range(4))
			r ^= (y >> m & 1) * h_pow(v, m);
		return r;
	}

	void mix_inv(wordtype& buffer)
	{
		const wordtype a(buffer);
		std::vector<uint8_t> val = { 14,9,13,11 };

		for (auto c : range(3))
			for (auto b : range(3))
				buffer.at(c) ^= mult(a.at(b), val.at((c + ((4 - b) % 4)) % 4));
	}

	// MixColumns a block
	void mixcolumns(blocktype& buffer)
	{
		for (auto r : buffer)
			mix(r);
	}


	// Inverted MixColumns a block
	void mixcolumns_inv(blocktype& buffer)
	{
		for (auto r : buffer)
			mix_inv(r);
	}
};
