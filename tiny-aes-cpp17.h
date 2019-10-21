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

using boxtype = std::array<uint8_t, boxsize>;


constexpr uint8_t ROTL8(uint8_t x, uint8_t shift)
{
	return ((uint8_t)((x) << (shift)) | ((x) >> (8 - (shift))));
}

boxtype create_sbox()
{
	boxtype sbox = {};
	uint8_t p = 1, q = 1;

	/* loop invariant: p * q == 1 in the Galois field */
	do {
		/* multiply p by 3 */
		p = p ^ (p << 1) ^ (p & 0x80 ? 0x1B : 0);

		/* divide q by 3 (equals multiplication by 0xf6) */
		q ^= q << 1;
		q ^= q << 2;
		q ^= q << 4;
		q ^= q & 0x80 ? 0x09 : 0;

		/* compute the affine transformation */
		uint8_t xformed = q ^ ROTL8(q, 1) ^ ROTL8(q, 2) ^ ROTL8(q, 3) ^ ROTL8(q, 4);

		sbox.at(p) = xformed ^ 0x63;
	} while (p != 1);

	/* 0 is a special case since it has no inverse */
	sbox.at(0) = 0x63;

	return sbox;
}

boxtype create_rsbox(boxtype sbox)
{
	boxtype rsbox{};
	for (auto i = 0; i < 256; ++i)
		rsbox[sbox[i]] = i;
	
	return rsbox;
}

const boxtype sbox = create_sbox();
const boxtype rsbox = create_rsbox(sbox);

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
