#include <iostream>
#include "okcrypt.h"

void PrintEncrypt(const char* algo, const std::string& hexCipherData) {
	std::cout << algo << "加密结果：\n" << hexCipherData << std::endl;
	std::cout << "----------------------------------\n";
}

void PrintDecrypt(const char* algo, const std::string& hexCipherData) {
	std::cout << algo << "解密结果：\n" << hexCipherData << std::endl;
	std::cout << "----------------------------------\n";
}

int main()
{
	std::string plain{ "plain data" };
	
	std::cout << "原始数据：" << plain << "\n-----\n";
	
	PrintEncrypt("MD5", okcrypt::EncryptMD5(plain));
	PrintEncrypt("Base64", okcrypt::EncryptBase64(plain));
	PrintEncrypt("SHA256", okcrypt::EncryptSHA256(plain));
	PrintEncrypt("SHA512", okcrypt::EncryptSHA512(plain));
	PrintEncrypt("SHA3-256", okcrypt::EncryptSHA3_256(plain));
	PrintEncrypt("SHA3-512", okcrypt::EncryptSHA3_512(plain));

	try {
		// DES
		std::string cipher;
		std::string recovered;
		okcrypt::InitalizeDESKey();
		std::cout << "des key: " << okcrypt::ToHex(okcrypt::GetDESKey()) << std::endl;
		okcrypt::EncryptDES("text will be encryped with des", cipher);
		PrintEncrypt("DES", okcrypt::ToHex(cipher));
		okcrypt::DecryptDES(cipher, recovered);
		PrintDecrypt("DES", recovered);

		cipher.clear();
		recovered.clear();

		// 3DES
		okcrypt::Initalize3DESKey();
		std::cout << "3des key: " << okcrypt::ToHex(okcrypt::Get3DESKey()) << std::endl;
		okcrypt::Encrypt3DES("text will be encryped with 3des", cipher);
		PrintEncrypt("3DES", okcrypt::ToHex(cipher));
		okcrypt::Decrypt3DES(cipher, recovered);
		PrintDecrypt("3DES", recovered);

		cipher.clear();
		recovered.clear();

		// AES
		okcrypt::InitalizeAESKey();
		std::cout << "aes key: " << okcrypt::ToHex(okcrypt::GetAESKey()) << std::endl;
		okcrypt::EncryptAES("text will be encrypted with aes", cipher);
		PrintEncrypt("AES", okcrypt::ToHex(cipher));
		okcrypt::DecryptAES(cipher, recovered);
		PrintDecrypt("AES", recovered);

		cipher.clear();
		recovered.clear();

		// RSA
		okcrypt::InitalizeRSAKeys();
		std::cout << "rsa public key: " << okcrypt::ToHex(okcrypt::GetRSAPublicKey()) << std::endl;
		okcrypt::EncryptRSA("text will be encrypted with rsa", cipher);
		PrintEncrypt("RSA", okcrypt::ToHex(cipher));
		okcrypt::DecryptRSA(cipher, recovered);
		PrintDecrypt("RSA", recovered);
	}
	catch (const CryptoPP::Exception& e)
	{
		std::cerr << "Error: " << e.what() << std::endl;
	}
	

	std::cin.get();
	return 0;
}