### Header only AES in modern C++

This is a small implementation of AES in modern(ish) C++. Currently only AES 128 CBC is supported.
Works in Visual Studio 2017 and 2019. 


#### Usage
```
aes encrypter;
expandedKeys expKeys = {};
	
encrypter.expandKeys(expKeys, key);
encrypter.encrypt(expKeys, iv, buffer, filesize);
```