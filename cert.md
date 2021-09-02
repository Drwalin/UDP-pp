
Drwalin's Certificate format versions and it's specification
==============================================================

# Table of Contents
1. Useful references
2. Magic Number
3. Drwalin's Certificate Version 1


# 1. Usefull references
-----------------

https://en.wikipedia.org/wiki/List_of_file_signatures
https://www.garykessler.net/library/file_sigs.html


# 2. Magic Number
-----------------

The Magic Number of Drwalin's Certificate signature is placed at the very
begining of every Drwalin's Certificate. The presented value in hexadicimal
code is:

> 44 63

which presents two ascii characters:

> D c


|offset|0|1|
|-|-|-|
|hex|44|63|
|ascii|D|c|



# 3. Drwalin's Certificate Version 1
-------------

All certificate numeric structure elements are encoded with little endian.

```C++
struct Date {
	/*
	 * Representes as in POSIX systems.
	 * Number of seconds since 1970.01.01 00:00
	 * assuming each day has 86400 seconds.
	 */
	int64_t date;	
};

struct ShortInt {
	/*
	 * Variable length integer.
	 * Pushes 7 lower bits of byte
	 * at it's arrival when highest bit is set
	 * ends when highest bit is not set.
	 */
	uint8_t bytes[1..10];
	/*
	 * Example values:
	 *  0x12:      { 0x12 }
	 *  0x123:     { 0xA3, 0x02 }
	 *  0x9876543: { 0xC3, 0xCA, 0x9D, 0x4C }
	 */
};

template<typename T>
struct Arr {
	ShortInt size;
	T objects[size];
};

struct SHA256 {
	uint8_t bytes[32];
};

usinG DER = mbedtls public key DER formatted.

struct CERT {
	uin8_t MagicNumber[2] = {0x44, 0x63};
	uint8_t Version = 0x01;
	Date IssueDate;
	Date ExpiryDate;
	DER PublicKey;
	Arr<SHA256> ParentingCertChain;
	Arr<uint8_t> ParentSignature;
};
```

`uint8_t Version` - Version identifier. For Verision 1 it's value is 0x01. A
certificate can be signed only by the same version of a certificate.

`Date IssueDate` - Date of signing a certificate with it's parent public key.

`Date ExpiryDate` - Date of expiry of a certificate. Maximum difference between
IssueDate and ExpiryDate is half a year. Only exception is for Root Certificate
Authority, where it's validity period may be as high as 16 years.

`DER PublicKey` - Public key for encryption and signature verification compliant
to certificate and private key owner. It uses DER format defined in mbedtls
library.

`Arr<SHA256> ParentingCertChain` - Chain of this certificate ancestors SHA2-256
signatures. Empty ParentingCertChain determines a self-signed certificate for
Root Certificate Authority. The last element must contain RootCA certificate
signature. Every element in this array must be a direct parent to a
previos-element. Maximal length of parenting chain is 7.

`Arr<uint8_t> ParentSignature` - Contains a hash SHA2-256 of this
certificate signed by it's parent.

To calculate a hash SHA2-256 of a certificate it is needed to take everything in
CERT structer in presented order except ParentSignature.










|offset|0|1|
|-|-|-|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
|hex|44|63|
