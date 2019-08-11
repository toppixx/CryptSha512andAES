/*
 * main.cpp
 *
 *  Created on: 11.08.2019
 *      Author: Schlepptop
 */

#include <iostream>
#include "AES.h"
#include <iostream>
#include <cassert>
#include <cstring>
#include "SHA512.h"

using namespace std;
using std::string;
using std::cout;
using std::endl;
void testMain();


string asciitolower(string in) {
	char tab2[1024];
	strncpy(tab2, in.c_str(), sizeof(tab2));
	tab2[sizeof(tab2) - 1] = 0;
	for(unsigned int i = 0; i < sizeof(tab2); i++)
	{
		if (tab2[i] <= 'Z' && tab2[i] >= 'A')
			tab2[i] = tab2[i] - ('Z' - 'z');
	}
    return string(tab2);
}

int main()
{

	string inputTest = "test";
	string inputGrape = "grape";
	string inputFreaky = "oiuoiuq23985985tuy89dv98g43698rhkfklndsbfglkdg9384593459853glfsgkbfdgkj";

	string outputTest = sha512(inputTest);
	string outputGrape = sha512(inputGrape);
	string outputFreaky = sha512(inputFreaky);
	bool check512 = false;
	AES aes(256);
	unsigned char plain[] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
	unsigned char iv[] = { 0x21, 0x3a, 0x2e, 0x12, 0xf1, 0xe3, 0xa2, 0x20, 0x44, 0x51, 0x21, 0xee, 0xff, 0xaa, 0xae, 0xab };
	unsigned char key[] = { 'a', 't', 'l', 'a', 's', ' ','c', 'o', 'p', 'c', 'o',  ' ', 'i', 'a', 's',  ' ', '1', '9',
	0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };

	unsigned int len;
	unsigned char *out = aes.EncryptCBC(plain, 16 * sizeof(unsigned char), key, iv, len);
	unsigned char *innew = aes.DecryptCBC(out, 16 * sizeof(unsigned char), key, iv, len);
	assert(!memcmp(innew, plain, 16 * sizeof(unsigned char)));
	cout << "Test CBC [OK]" << endl;
	delete[] out;
	delete[] innew;


	string resultTest =   "EE26B0DD4AF7E749AA1A8EE3C10AE9923F618980772E473F8819A5D4940E0DB27AC185F8A0E1D5F84F88BC887FD67B143732C304CC5FA9AD8E6F57F50028A8FF";   //result for "test"
	string resultGrape =  "9375D1ABDB644A01955BCCAD12E2F5C2BD8A3E226187E548D99C559A99461453B980123746753D07C169C22A5D9CC75CB158F0E8D8C0E713559775B5E1391FC4";  //result for "grape"
	string resultFreaky = "68A3DF375D9BF91005DA4C97EEB73F352D4B0898A42773B383482B69ADC59A9ED6C0D760D3CC8F56861D4B74E35F973C53C7D3F7F951158FAAE5E43E1FAE65AF";  //"poipiuiljjkjuziuoiuoiuzgfukhkjlknlkkoilkjölk0987090ß90uzuiohölknhlit8767654ezfghjkh"


	cout << "sha512('"<< inputTest << "'):" << "\nresult was: " << outputTest << endl;
	string buffer = asciitolower(resultTest);
	check512 = buffer.compare(outputTest);
	bool retBool = 0 == check512;
	cout << "should be:  " << resultTest << endl;
	cout << "retval was: " << retBool << endl;

	cout << "\nsha512('"<< inputGrape << "'):" << "\nresult was: " << outputGrape << endl;
	buffer = asciitolower(resultGrape);
	check512 = buffer.compare(outputGrape);
	retBool = 0 == check512;
	cout << "should be:  " << resultGrape << endl;
	cout << "retval was: " << retBool << endl;

	cout << "\nsha512('"<< inputFreaky << "'):" << "\nresult was: " << outputFreaky << endl;
	buffer = asciitolower(resultFreaky);
	check512 = buffer.compare(outputFreaky);
	retBool = 0 == check512;
	cout << "should be:  " << resultFreaky << endl;
	cout << "retval was: " << retBool << endl;

	return 0;
}

void testMain()
{

	string inputTest = "test";
	string inputGrape = "grape";
	string inputFreaky = "oiuoiuq23985985tuy89dv98g43698rhkfklndsbfglkdg9384593459853glfsgkbfdgkj";

	string outputTest = sha512(inputTest);
	string outputGrape = sha512(inputGrape);
	string outputFreaky = sha512(inputFreaky);
	bool check512 = false;
	AES aes(256);
	unsigned char plain[] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
	unsigned char iv[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
	unsigned char key[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x011,
	0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };

	unsigned int len;
	unsigned char *out = aes.EncryptCBC(plain, 16 * sizeof(unsigned char), key, iv, len);
	unsigned char *innew = aes.DecryptCBC(out, 16 * sizeof(unsigned char), key, iv, len);
	assert(!memcmp(innew, plain, 16 * sizeof(unsigned char)));
	cout << "Test CBC [OK]" << endl;
	delete[] out;
	delete[] innew;


	string resultTest =   "EE26B0DD4AF7E749AA1A8EE3C10AE9923F618980772E473F8819A5D4940E0DB27AC185F8A0E1D5F84F88BC887FD67B143732C304CC5FA9AD8E6F57F50028A8FF";   //result for "test"
	string resultGrape =  "9375D1ABDB644A01955BCCAD12E2F5C2BD8A3E226187E548D99C559A99461453B980123746753D07C169C22A5D9CC75CB158F0E8D8C0E713559775B5E1391FC4";  //result for "grape"
	string resultFreaky = "68A3DF375D9BF91005DA4C97EEB73F352D4B0898A42773B383482B69ADC59A9ED6C0D760D3CC8F56861D4B74E35F973C53C7D3F7F951158FAAE5E43E1FAE65AF";  //"poipiuiljjkjuziuoiuoiuzgfukhkjlknlkkoilkjölk0987090ß90uzuiohölknhlit8767654ezfghjkh"


	cout << "sha512('"<< inputTest << "'):" << "\nresult was: " << outputTest << endl;
	string buffer = asciitolower(resultTest);
	check512 = buffer.compare(outputTest);
	bool retBool = 0 == check512;
	cout << "should be:  " << resultTest << endl;
	cout << "retval was: " << retBool << endl;

	cout << "\nsha512('"<< inputGrape << "'):" << "\nresult was: " << outputGrape << endl;
	buffer = asciitolower(resultGrape);
	check512 = buffer.compare(outputGrape);
	retBool = 0 == check512;
	cout << "should be:  " << resultGrape << endl;
	cout << "retval was: " << retBool << endl;

	cout << "\nsha512('"<< inputFreaky << "'):" << "\nresult was: " << outputFreaky << endl;
	buffer = asciitolower(resultFreaky);
	check512 = buffer.compare(outputFreaky);
	retBool = 0 == check512;
	cout << "should be:  " << resultFreaky << endl;
	cout << "retval was: " << retBool << endl;

}
