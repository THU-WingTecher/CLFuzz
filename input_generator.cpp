#include <cstdint>
#include <array>
#include <fuzzing/datasource/datasource.hpp>
#include <fuzzing/datasource/id.hpp>
#include <cryptofuzz/operations.h>
#include <cryptofuzz/repository.h>
#include <cryptofuzz/options.h>
#include <cryptofuzz/util.h>
#include <boost/multiprecision/cpp_int.hpp>
#include <boost/lexical_cast.hpp>
#include "config.h"
#include "repository_tbl.h"
#include "numbers.h"
#include "mutatorpool.h"
#include "third_party/json/json.hpp"
#include <fstream>  
#include <string>  
#include <iostream> 
#include <cstdio>
#include <cstdlib>
#include <math.h>


using namespace std;

static const std::array<std::string, 256> hexMap = {
        "00", "01", "02", "03", "04", "05", "06", "07", "08", "09", "0a", "0b", "0c", "0d", "0e", "0f",
        "10", "11", "12", "13", "14", "15", "16", "17", "18", "19", "1a", "1b", "1c", "1d", "1e", "1f",
        "20", "21", "22", "23", "24", "25", "26", "27", "28", "29", "2a", "2b", "2c", "2d", "2e", "2f",
        "30", "31", "32", "33", "34", "35", "36", "37", "38", "39", "3a", "3b", "3c", "3d", "3e", "3f",
        "40", "41", "42", "43", "44", "45", "46", "47", "48", "49", "4a", "4b", "4c", "4d", "4e", "4f",
        "50", "51", "52", "53", "54", "55", "56", "57", "58", "59", "5a", "5b", "5c", "5d", "5e", "5f",
        "60", "61", "62", "63", "64", "65", "66", "67", "68", "69", "6a", "6b", "6c", "6d", "6e", "6f",
        "70", "71", "72", "73", "74", "75", "76", "77", "78", "79", "7a", "7b", "7c", "7d", "7e", "7f",
        "80", "81", "82", "83", "84", "85", "86", "87", "88", "89", "8a", "8b", "8c", "8d", "8e", "8f",
        "90", "91", "92", "93", "94", "95", "96", "97", "98", "99", "9a", "9b", "9c", "9d", "9e", "9f",
        "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7", "a8", "a9", "aa", "ab", "ac", "ad", "ae", "af",
        "b0", "b1", "b2", "b3", "b4", "b5", "b6", "b7", "b8", "b9", "ba", "bb", "bc", "bd", "be", "bf",
        "c0", "c1", "c2", "c3", "c4", "c5", "c6", "c7", "c8", "c9", "ca", "cb", "cc", "cd", "ce", "cf",
        "d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7", "d8", "d9", "da", "db", "dc", "dd", "de", "df",
        "e0", "e1", "e2", "e3", "e4", "e5", "e6", "e7", "e8", "e9", "ea", "eb", "ec", "ed", "ee", "ef",
        "f0", "f1", "f2", "f3", "f4", "f5", "f6", "f7", "f8", "f9", "fa", "fb", "fc", "fd", "fe", "ff"};

struct keypair{
    int keyLength;
    int ivLength;
    int blockSize;
};

static map<uint64_t, int> DigestLengthMap = {
    { CF_DIGEST("BLAKE2B512"), 64},
    { CF_DIGEST("BLAKE2S256"), 32},
    { CF_DIGEST("MD5"), 16},
    { CF_DIGEST("MD5_SHA1"), 36},
    { CF_DIGEST("SHA1"), 20},
    { CF_DIGEST("SHA224"), 28},
    { CF_DIGEST("SHA256"), 32},
    { CF_DIGEST("SHA3-224"), 28},
    { CF_DIGEST("SHA3-256"), 32},
    { CF_DIGEST("SHA3-384"), 48},
    { CF_DIGEST("SHA3-512"), 64},
    { CF_DIGEST("SHA384"), 48},
    { CF_DIGEST("SHA512"), 64},
    { CF_DIGEST("SHA512-224"), 28},
    { CF_DIGEST("SHA512-256"), 32},
    { CF_DIGEST("SHAKE128"), 16},
    { CF_DIGEST("SHAKE256"), 32},
    { CF_DIGEST("SM3"), 32},
};

static map<uint64_t, keypair> CipherKeyMap = {
    { CF_CIPHER("AES"), {16, 0, 16}},
    { CF_CIPHER("AES_128_CBC"), {16, 16, 16}},
    { CF_CIPHER("AES_128_CBC_HMAC_SHA1"), {16, 16, 16}},
    { CF_CIPHER("AES_128_CBC_HMAC_SHA256"), {16, 16, 16}},
    { CF_CIPHER("AES_128_CCM"), {16, 12, 1}},
    { CF_CIPHER("AES_128_CFB"), {16, 16, 1}},
    { CF_CIPHER("AES_128_CFB1"), {16, 16, 1}},
    { CF_CIPHER("AES_128_CFB8"), {16, 16, 1}},
    { CF_CIPHER("AES_128_CTR"), {16, 16, 1}},
    { CF_CIPHER("AES_128_ECB"), {16, 0, 16}},
    { CF_CIPHER("AES_128_GCM"), {16, 12, 1}},
    { CF_CIPHER("AES_128_OCB"), {16, 12, 16}},
    { CF_CIPHER("AES_128_OFB"), {16, 16, 1}},
    { CF_CIPHER("AES_128_WRAP"), {16, 8, 8}},
    { CF_CIPHER("AES_128_WRAP_PAD"), {16, 4, 8}},
    { CF_CIPHER("AES_128_XTS"), {32, 16, 1}},
    { CF_CIPHER("AES_192_CBC"), {24, 16, 16}},
    { CF_CIPHER("AES_192_CCM"), {24, 12, 1}},
    { CF_CIPHER("AES_192_CFB"), {24, 16, 1}},
    { CF_CIPHER("AES_192_CFB1"), {24, 16, 1}},
    { CF_CIPHER("AES_192_CFB8"), {24, 16, 1}},
    { CF_CIPHER("AES_192_CTR"), {24, 16, 1}},
    { CF_CIPHER("AES_192_ECB"), {24, 0, 16}},
    { CF_CIPHER("AES_192_GCM"), {24, 12, 1}},
    { CF_CIPHER("AES_192_OFB"), {24, 16, 1}},
    { CF_CIPHER("AES_192_WRAP"), {24, 8, 8}},
    { CF_CIPHER("AES_192_WRAP_PAD"), {24, 4, 8}},
    { CF_CIPHER("AES_256_CBC"), {32, 16, 16}},
    { CF_CIPHER("AES_256_CBC_HMAC_SHA1"), {32, 16, 16}},
    { CF_CIPHER("AES_256_CBC_HMAC_SHA256"), {32, 16, 16}},
    { CF_CIPHER("AES_256_CCM"), {32, 12, 1}},
    { CF_CIPHER("AES_256_CFB"), {32, 16, 1}},
    { CF_CIPHER("AES_256_CFB1"), {32, 16, 1}},
    { CF_CIPHER("AES_256_CFB8"), {32, 16, 1}},
    { CF_CIPHER("AES_256_CTR"), {32, 16, 1}},
    { CF_CIPHER("AES_256_ECB"), {32, 0, 16}},
    { CF_CIPHER("AES_256_GCM"), {32, 12, 1}},
    { CF_CIPHER("AES_256_OCB"), {32, 12, 16}},
    { CF_CIPHER("AES_256_OFB"), {32, 16, 1}},
    { CF_CIPHER("AES_256_WRAP"), {32, 8, 8}},
    { CF_CIPHER("AES_256_WRAP_PAD"), {32, 4, 8}},
    { CF_CIPHER("AES_256_XTS"), {64, 16, 1}},
    { CF_CIPHER("ARIA_128_CBC"), {16, 16, 16}},
    { CF_CIPHER("ARIA_128_CCM"), {16, 12, 1}},
    { CF_CIPHER("ARIA_128_CFB"), {16, 16, 1}},
    { CF_CIPHER("ARIA_128_CFB1"), {16, 16, 1}},
    { CF_CIPHER("ARIA_128_CFB8"), {16, 16, 1}},
    { CF_CIPHER("ARIA_128_CTR"), {16, 16, 1}},
    { CF_CIPHER("ARIA_128_ECB"), {16, 0, 16}},
    { CF_CIPHER("ARIA_128_GCM"), {16, 12, 1}},
    { CF_CIPHER("ARIA_128_OFB"), {16, 16, 1}},
    { CF_CIPHER("ARIA_192_CBC"), {24, 16, 16}},
    { CF_CIPHER("ARIA_192_CCM"), {24, 12, 1}},
    { CF_CIPHER("ARIA_192_CFB"), {24, 16, 1}},
    { CF_CIPHER("ARIA_192_CFB1"), {24, 16, 1}},
    { CF_CIPHER("ARIA_192_CFB8"), {24, 16, 1}},
    { CF_CIPHER("ARIA_192_CTR"), {24, 16, 1}},
    { CF_CIPHER("ARIA_192_ECB"), {24, 0, 16}},
    { CF_CIPHER("ARIA_192_GCM"), {24, 12, 1}},
    { CF_CIPHER("ARIA_192_OFB"), {24, 16, 1}},
    { CF_CIPHER("ARIA_256_CBC"), {32, 16, 16}},
    { CF_CIPHER("ARIA_256_CCM"), {32, 12, 1}},
    { CF_CIPHER("ARIA_256_CFB"), {32, 16, 1}},
    { CF_CIPHER("ARIA_256_CFB1"), {32, 16, 1}},
    { CF_CIPHER("ARIA_256_CFB8"), {32, 16, 1}},
    { CF_CIPHER("ARIA_256_CTR"), {32, 16, 1}},
    { CF_CIPHER("ARIA_256_ECB"), {32, 0, 16}},
    { CF_CIPHER("ARIA_256_GCM"), {32, 12, 1}},
    { CF_CIPHER("ARIA_256_OFB"), {32, 16, 1}},
    { CF_CIPHER("BF_CBC"), {16, 8, 8}},
    { CF_CIPHER("BF_CFB"), {16, 8, 1}},
    { CF_CIPHER("BF_ECB"), {16, 0, 8}},
    { CF_CIPHER("BF_OFB"), {16, 8, 1}},
    { CF_CIPHER("CAMELLIA_128_CBC"), {16, 16, 16}},
    { CF_CIPHER("CAMELLIA_128_CFB"), {16, 16, 1}},
    { CF_CIPHER("CAMELLIA_128_CFB1"), {16, 16, 1}},
    { CF_CIPHER("CAMELLIA_128_CFB8"), {16, 16, 1}},
    { CF_CIPHER("CAMELLIA_128_CTR"), {16, 16, 1}},
    { CF_CIPHER("CAMELLIA_128_ECB"), {16, 0, 16}},
    { CF_CIPHER("CAMELLIA_128_OFB"), {16, 16, 1}},
    { CF_CIPHER("CAMELLIA_192_CBC"), {24, 16, 16}},
    { CF_CIPHER("CAMELLIA_192_CFB"), {24, 16, 1}},
    { CF_CIPHER("CAMELLIA_192_CFB1"), {24, 16, 1}},
    { CF_CIPHER("CAMELLIA_192_CFB8"), {24, 16, 1}},
    { CF_CIPHER("CAMELLIA_192_CTR"), {24, 16, 1}},
    { CF_CIPHER("CAMELLIA_192_ECB"), {24, 0, 16}},
    { CF_CIPHER("CAMELLIA_192_OFB"), {24, 16, 1}},
    { CF_CIPHER("CAMELLIA_256_CBC"), {32, 16, 16}},
    { CF_CIPHER("CAMELLIA_256_CFB"), {32, 16, 1}},
    { CF_CIPHER("CAMELLIA_256_CFB1"), {32, 16, 1}},
    { CF_CIPHER("CAMELLIA_256_CFB8"), {32, 16, 1}},
    { CF_CIPHER("CAMELLIA_256_CTR"), {32, 16, 1}},
    { CF_CIPHER("CAMELLIA_256_ECB"), {32, 0, 16}},
    { CF_CIPHER("CAMELLIA_256_OFB"), {32, 16, 1}},
    { CF_CIPHER("CAST5_CBC"), {16, 8, 8}},
    { CF_CIPHER("CAST5_CFB"), {16, 8, 1}},
    { CF_CIPHER("CAST5_ECB"), {16, 0, 8}},
    { CF_CIPHER("CAST5_OFB"), {16, 8, 1}},
    { CF_CIPHER("CHACHA20"), {32, 16, 1}},
    { CF_CIPHER("CHACHA20_POLY1305"), {32, 12, 1}},
    { CF_CIPHER("DESX_A_CBC"), {24, 8, 8}},
    { CF_CIPHER("DES_CBC"), {8, 8, 8}},
    { CF_CIPHER("DES_CFB"), {8, 8, 1}},
    { CF_CIPHER("DES_CFB1"), {8, 8, 1}},
    { CF_CIPHER("DES_CFB8"), {8, 8, 1}},
    { CF_CIPHER("DES_ECB"), {8, 0, 8}},
    { CF_CIPHER("DES_EDE"), {16, 0, 8}},
    { CF_CIPHER("DES_EDE3"), {24, 0, 8}},
    { CF_CIPHER("DES_EDE3_CBC"), {24, 8, 8}},
    { CF_CIPHER("DES_EDE3_CFB"), {24, 8, 1}},
    { CF_CIPHER("DES_EDE3_CFB1"), {24, 8, 1}},
    { CF_CIPHER("DES_EDE3_CFB8"), {24, 8, 1}},
    { CF_CIPHER("DES_EDE3_OFB"), {24, 8, 1}},
    { CF_CIPHER("DES_EDE3_WRAP"), {24, 0, 8}},
    { CF_CIPHER("DES_EDE_CBC"), {16, 8, 8}},
    { CF_CIPHER("DES_EDE_CFB"), {16, 8, 1}},
    { CF_CIPHER("DES_EDE_OFB"), {16, 8, 1}},
    { CF_CIPHER("DES_OFB"), {8, 8, 1}},
    { CF_CIPHER("IDEA_CBC"), {16, 8, 8}},
    { CF_CIPHER("IDEA_CFB"), {16, 8, 1}},
    { CF_CIPHER("IDEA_ECB"), {16, 0, 8}},
    { CF_CIPHER("IDEA_OFB"), {16, 8, 1}},
    { CF_CIPHER("RC2_40_CBC"), {5, 8, 8}},
    { CF_CIPHER("RC2_64_CBC"), {8, 8, 8}},
    { CF_CIPHER("RC2_CBC"), {16, 8, 8}},
    { CF_CIPHER("RC2_CFB"), {16, 8, 1}},
    { CF_CIPHER("RC2_ECB"), {16, 0, 8}},
    { CF_CIPHER("RC2_OFB"), {16, 8, 1}},
    { CF_CIPHER("RC4"), {16, 0, 1}},
    { CF_CIPHER("RC4_40"), {5, 0, 1}},
    { CF_CIPHER("RC4_HMAC_MD5"), {16, 0, 1}},
    { CF_CIPHER("RC5_32_12_16_CBC"), {16, 8, 8}},
    { CF_CIPHER("RC5_32_12_16_CFB"), {16, 8, 1}},
    { CF_CIPHER("RC5_32_12_16_ECB"), {16, 0, 8}},
    { CF_CIPHER("RC5_32_12_16_OFB"), {16, 8, 1}},
    { CF_CIPHER("SEED_CBC"), {16, 16, 16}},
    { CF_CIPHER("SEED_CFB"), {16, 16, 1}},
    { CF_CIPHER("SEED_ECB"), {16, 0, 16}},
    { CF_CIPHER("SEED_OFB"), {16, 16, 1}},
    { CF_CIPHER("SM4_CBC"), {16, 16, 16}},
    { CF_CIPHER("SM4_CFB"), {16, 16, 1}},
    { CF_CIPHER("SM4_CTR"), {16, 16, 1}},
    { CF_CIPHER("SM4_ECB"), {16, 0, 16}},
    { CF_CIPHER("SM4_OFB"), {16, 16, 1}},

};

uint32_t PRNG(void)
{
    static uint32_t nSeed = 5323;
    nSeed = (8253729 * nSeed + 2396403);
    return nSeed  % 32767;
}


static std::vector<size_t> SplitLength(size_t left, const size_t numParts) {
    std::vector<size_t> lengths;
    for (size_t i = 0; i < numParts; i++) {
        const auto cur = PRNG() % (left+1);
        lengths.push_back(cur);
        left -= cur;
    }

    std::vector<size_t> lengths_randomized;
    for (size_t i = 0; i < numParts; i++) {
        const auto cur = lengths.begin() + PRNG() % (lengths.size());
        lengths_randomized.push_back(*cur);
        lengths.erase(cur);
    }

    return lengths_randomized;
}

static bool getBool(void) {
    return PRNG() % 2 == 0;
}

static size_t getDefaultSize(void) {
    static const std::array defaultSizes = {0, 1, 2, 4, 8, 12, 16, 24, 32, 64};

    return defaultSizes[PRNG() % defaultSizes.size()];
}

static std::string getBuffer(size_t size, const bool alternativeSize = false) {

    if ( alternativeSize == true ) {
        if ( getBool() ) {
            const auto newSize = getDefaultSize();
            if ( newSize < size ) {
                size = newSize;
            }
        }
    }

    std::string ret;

    for (size_t i = 0; i < size; i++) {
        ret += hexMap[PRNG() % 256];
    }

    return ret;
}

static std::vector<uint8_t> getBufferBin(const size_t size) {
    std::vector<uint8_t> ret(size);

    for (size_t i = 0; i < size; i++) {
        ret[i] = PRNG();
    }

    return ret;
}

static std::string getBignum(bool mustBePositive = false) {
    std::string ret;

    if ( PRNG() % 10 <= 3 ) {
        constexpr long sizeMax = cryptofuzz::config::kMaxBignumSize;
        constexpr long sizeTop = sizeMax * 0.5;
        constexpr long sizeBottom = sizeMax - sizeTop;

        static_assert(sizeBottom > 0);
        static_assert(sizeBottom + sizeTop <= sizeMax);

        const size_t size = (PRNG() % sizeTop) + sizeBottom;

        for (size_t i = 0; i < size; i++) {
            char c = '0' + (PRNG() % 10);
            if ( i == 0 && c == '0' ) {
                /* Cannot have leading zeroes */
                c = '1';
            }
            ret += c;
        }
    } else {
        if ( getBool() && Pool_Bignum.Have()) {
            ret = Pool_Bignum.Get().str;
        } else {
            ret = cryptofuzz::numbers.at(PRNG() % cryptofuzz::numbers.size());
        }
    }

    const bool isNegative = !ret.empty() && ret[0] == '-';
    if ( cryptofuzz::config::kNegativeIntegers == false ) {
        mustBePositive = true;
    }

    if ( isNegative && mustBePositive ) {
        ret = std::string(ret.data() + 1, ret.size() - 1);
    }

    if ( !mustBePositive && !isNegative && getBool() ) {
        ret = "-" + ret;
    }

    return ret;
}

static std::string tinyMutate(std::string s){
    std::string str = s;
    switch (PRNG() % 4){
        case 0:{
            str = "00" + str;
            break;
        }
        case 1:{
            str = str + "00";
            break;
        }
        case 2:{
            str = hexMap[PRNG()%256] + str;
            break;
        }
        case 3:{
            str = str + hexMap[PRNG()%256];
            break;
        }
        case 4:{
            str = "";
            break;
        }
    }
    return str;
}

extern "C" size_t LLVMFuzzerMutate(uint8_t* data, size_t size, size_t maxSize);

extern cryptofuzz::Options* cryptofuzz_options;

static uint64_t getRandomCipher(void) {
    if ( !cryptofuzz_options->ciphers.Empty() ) {
        return cryptofuzz_options->ciphers.At(PRNG());
    } else {
        return CipherLUT[ PRNG() % (sizeof(CipherLUT) / sizeof(CipherLUT[0])) ].id;
    }
}

static uint64_t getRandomDigest(void) {
    if ( !cryptofuzz_options->digests.Empty() ) {
        return cryptofuzz_options->digests.At(PRNG());
    } else {
        return DigestLUT[ PRNG() % (sizeof(DigestLUT) / sizeof(DigestLUT[0])) ].id;
    }
}

static uint64_t getRandomCurve(void) {
    if ( !cryptofuzz_options->curves.Empty() ) {
        return cryptofuzz_options->curves.At(PRNG());
    } else {
        return ECC_CurveLUT[ PRNG() % (sizeof(ECC_CurveLUT) / sizeof(ECC_CurveLUT[0])) ].id;
    }
}

static uint64_t getRandomCalcOp(void) {
    if ( !cryptofuzz_options->calcOps.Empty() ) {
        return cryptofuzz_options->calcOps.At(PRNG());
    } else {
        return CalcOpLUT[ PRNG() % (sizeof(CalcOpLUT) / sizeof(CalcOpLUT[0])) ].id;
    }
}

static std::string get_BLS_PyECC_DST(void) {
    return "424c535f5349475f424c53313233383147325f584d443a5348412d3235365f535357555f524f5f504f505f";
}

static std::string get_BLS_BasicScheme_DST(void) {
    return "424c535f5349475f424c53313233383147325f584d443a5348412d3235365f535357555f524f5f4e554c5f";
}

static std::string get_BLS_predefined_DST(void) {
    return getBool() ? get_BLS_PyECC_DST() : get_BLS_BasicScheme_DST();
}

static void generateECCPoint(void) {
    if ( (PRNG() % 100) != 0 ) {
        return;
    }

    const auto curveID = getRandomCurve();

    const auto a = cryptofuzz::repository::ECC_CurveToA(curveID);
    if ( a == std::nullopt ) {
        return;
    }

    const auto b = cryptofuzz::repository::ECC_CurveToB(curveID);
    if ( b == std::nullopt ) {
        return;
    }

    const auto p = cryptofuzz::repository::ECC_CurveToPrime(curveID);
    if ( p == std::nullopt ) {
        return;
    }

    const auto o = cryptofuzz::repository::ECC_CurveToPrime(curveID);
    if ( o == std::nullopt ) {
        return;
    }

    const auto x = getBignum(true);

    const auto y = cryptofuzz::util::Find_ECC_Y(x, *a, *b, *p, *o, getBool());

    Pool_CurveECC_Point.Set({ curveID, x, y });
}



static std::string getSeedClearText(size_t size) {
    std::string ret;
    int temp;

    switch( PRNG() % 4){
        /* extremely short*/
        case 0:{
            temp = PRNG() % 3;
            for(int i=0;i<temp;i++){
                ret+=hexMap[PRNG() % 256];
            }
            break;
        }
        /* extremely long*/
        case 1:{
            temp = PRNG() % 2 + 1;
            temp = temp * 1024 + (PRNG()%5-5);
            ret = getBuffer(temp);
            break;
        }
        /* ramdom */
        case 2:{
            temp = PRNG() % 100;
            ret = getBuffer(temp * 64);
            break;
        }
        /* empty */
        case 3:{
            ret = "";
            break;
        }
    }
    return ret;
}

static std::string getSeedKey(size_t size, uint64_t cipherType) {
    string ret;
    int temp;
    switch( PRNG() % 8){
        /* extremely short*/
        case 0:{
            temp = PRNG() % 3;
            for(int i=0;i<temp;i++){
                ret += hexMap[PRNG() % 256];
            }
            break;
        }
        /* extremely long*/
        case 1:{
            temp = PRNG() % 2 + 1;
            temp = temp * 1024 + (PRNG()%5-5);
            ret = getBuffer(temp);
            break;
        }
        /* empty */
        case 2:{
            ret = "";
            break;
        }
        /* random */
        case 3:{
            temp = PRNG() % 100;
            ret = getBuffer(temp * 64);
            break;
        }
        /* suggested or requested */
        default:{
            if(CipherKeyMap.count(cipherType) != 0){
                size = CipherKeyMap[cipherType].keyLength;
            }
            ret = getBuffer(size);
        }
    }
    return ret;
}

static std::string getSeedIV(size_t size, uint64_t cipherType) {
    string ret;
    int temp;
    switch( PRNG() % 8){
        /* extremely short*/
        case 0:{
            temp = PRNG() % 3;
            for(int i=0;i<temp;i++){
                ret += hexMap[PRNG() % 256];
            }
            break;
        }
        /* extremely long*/
        case 1:{
            temp = PRNG() % 2 + 1;
            temp = temp * 1024 + (PRNG()%5-5);
            ret = getBuffer(temp);
            break;
        }
        /* empty */
        case 2:{
            ret = "";
            break;
        }
        /* random */
        case 3:{
            temp = PRNG() % 100;
            ret = getBuffer(temp * 64);
            break;
        }
        /* suggested or requested */
        default:{
            if(CipherKeyMap.count(cipherType) != 0){
                size = CipherKeyMap[cipherType].ivLength;
            }
            ret = getBuffer(size);
        }
    }
    return ret;
}

static std::string getSeedCipherText(size_t size, uint64_t cipherType) {
    string ret = "";
    int temp;
    switch( PRNG() % 3){
        /* extremely short*/
        case 0:{
            temp = PRNG() % 3;
            for(int i=0;i<temp;i++){
                ret += hexMap[PRNG() % 256];
            }
            break;
        }
        /* extremely long*/
        case 1:{
            temp = PRNG() % 2 + 1;
            temp = temp * 1024 + (PRNG()%5-5);
            ret = getBuffer(temp);
            break;
        }
        /* empty */
        case 2:{
            ret = "";
            break;
        }
        /* random */
        case 3:{
            temp = PRNG() % 100;
            ret = getBuffer(temp * 64);
            break;
        }
        /* normal block size */
        default:{
            if(CipherKeyMap.count(cipherType) != 0){
                size = CipherKeyMap[cipherType].blockSize;
            }
            ret = getBuffer(size);
        }
    }
    /* leading empty char*/
    if(PRNG()){
        int zeronum = PRNG()%10;
        for(int i=0;i<zeronum;i++){
            ret = hexMap[0] + ret;
        }
    }
    return ret;
}


static std::string getSmallSeedBignum(bool Positive = false){
    string ret = "";

}

static std::string getSeedBignum(bool Positive = false){
    string ret = "";
    int temp = PRNG() % 2 + 1;
    for (int i = 0; i < temp; i++) {
        char c = '0' + (PRNG() % 10);
        if ( i == 0 && c == '0' ) {
            /* Cannot have leading zeroes */
            c = '1';
        }
        ret += c;
    }
    return ret;
}

static std::string getEccY(std::string x, uint64_t curveID){
    const auto a = cryptofuzz::repository::ECC_CurveToA(curveID);
    if ( a == std::nullopt ) {
        return getSeedBignum();
    }

    const auto b = cryptofuzz::repository::ECC_CurveToB(curveID);
    if ( b == std::nullopt ) {
        return getSeedBignum();
    }

    const auto p = cryptofuzz::repository::ECC_CurveToPrime(curveID);
    if ( p == std::nullopt ) {
        return getSeedBignum();
    }

    const auto o = cryptofuzz::repository::ECC_CurveToPrime(curveID);
    if ( o == std::nullopt ) {
        return getSeedBignum();
    }

    const std::string y = cryptofuzz::util::Find_ECC_Y(x, *a, *b, *p, *o, getBool());

    Pool_CurveECC_Point.Set({ curveID, x, y });

    return y;
}

std::string getBLSPrivateKey(){
    size_t len = PRNG() % 21;
    return getBuffer(len);
}

extern "C" size_t LLVMFuzzerCustomMutator(uint8_t* data, size_t size, size_t maxSize, unsigned int seed) {
    (void)seed;
    size_t out_size = 0;
    std::vector<uint8_t> modifier;
    bool reuseModifier;

    if ( maxSize < 64 || getBool() ) {
        goto end;
    }

    reuseModifier = getBool();

    if ( reuseModifier == true ) {
        cryptofuzz::util::MemorySanitizerUnpoison(data, size);

        /* Try to extract modifier from input */
        try {
            fuzzing::datasource::Datasource ds(data, size);
            /* ignore result */ ds.Get<uint64_t>();
            /* ignore result */ ds.GetData(0, 1);
            modifier = ds.GetData(0);
        } catch ( fuzzing::datasource::Datasource::OutOfData ) { }
    }

    {
        uint64_t operation;
        
        if ( !cryptofuzz_options->operations.Empty() ) {
            operation = cryptofuzz_options->operations.At(PRNG());
        } else {
            operation = OperationLUT[ PRNG() % (sizeof(OperationLUT) / sizeof(OperationLUT[0])) ].id;
        }
        fuzzing::datasource::Datasource dsOut2(nullptr, 0);

        nlohmann::json parameters;

#define GET_OR_BIGNUM(x) getBool() ? (x) : getSeedBignum();
        switch ( operation ) {
            case    CF_OPERATION("Digest"):
                {
                    size_t numParts = 0;

                    numParts++; /* modifier */
                    numParts++; /* cleartext */

                    const auto lengths = SplitLength(maxSize - 64, numParts);

                    parameters["modifier"] = getBuffer(lengths[0]);
                    string ret = getSeedClearText(lengths[1]);
                    parameters["cleartext"] = ret;
                    parameters["digestType"] = getRandomDigest();

                    cryptofuzz::operation::Digest op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("HMAC"):
                {
                    size_t numParts = 0;

                    numParts++; /* modifier */
                    numParts++; /* cleartext */
                    numParts++; /* iv */
                    numParts++; /* key */

                    const auto lengths = SplitLength(maxSize - 64, numParts);

                    parameters["modifier"] = getBuffer(lengths[0]);
                    parameters["cleartext"] = getSeedClearText(lengths[1]);
                    uint64_t ciphertype = getRandomCipher();
                    parameters["cipher"]["cipherType"] = ciphertype;
                    parameters["cipher"]["iv"] = getSeedIV(lengths[2], ciphertype);
                    parameters["cipher"]["key"] = getSeedKey(lengths[3], ciphertype);
                    parameters["digestType"] = getRandomDigest();

                    cryptofuzz::operation::HMAC op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("CMAC"):
                {
                    size_t numParts = 0;

                    numParts++; /* modifier */
                    numParts++; /* cleartext */
                    numParts++; /* iv */
                    numParts++; /* key */
                    const auto lengths = SplitLength(maxSize - 64, numParts);

                    parameters["modifier"] = getBuffer(lengths[0]);
                    parameters["cleartext"] = getSeedClearText(lengths[1]);
                    uint64_t ciphertype = getRandomCipher();
                    parameters["cipher"]["cipherType"] = ciphertype;
                    parameters["cipher"]["iv"] = getSeedIV(lengths[2], ciphertype);
                    parameters["cipher"]["key"] = getSeedKey(lengths[3], ciphertype);

                    cryptofuzz::operation::CMAC op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("SymmetricEncrypt"):
                {
                    const bool aad_enabled = PRNG() % 2;
                    const bool tagSize_enabled = PRNG() % 2;
                    size_t numParts = 0;

                    numParts++; /* modifier */
                    numParts++; /* cleartext */
                    numParts++; /* iv */
                    numParts++; /* key */

                    if ( aad_enabled ) {
                        numParts++; /* aad */
                    }

                    auto lengths = SplitLength(maxSize - 64, numParts);

                    parameters["modifier"] = getBuffer(lengths[0]);
                    if ( getBool() ) {
                        if ( 16 < lengths[1] ) {
                            lengths[1] = 16;
                        }
                    }
                    uint64_t ciphertype = getRandomCipher();
                    parameters["cipher"]["cipherType"] = ciphertype;
                    parameters["cipher"]["iv"] = getSeedIV(0, ciphertype);
                    parameters["cipher"]["key"] = getSeedKey(lengths[3], ciphertype);
                    std::string cleartext = "";
                    if(ciphertype == CF_CIPHER("AES")){
                        cleartext = getBuffer(16*(PRNG()%10));
                    }else{
                        cleartext = getSeedClearText(lengths[1]);
                    }
                    parameters["cleartext"] = cleartext;
                    if ( aad_enabled ) {
                        parameters["aad_enabled"] = true;
                        if ( getBool() ) {
                            lengths[4] = 0;
                        }
                        parameters["aad"] = getBuffer(lengths[4]);
                    } else {
                        parameters["aad_enabled"] = false;
                    }

                    if ( tagSize_enabled ) {
                        parameters["tagSize_enabled"] = true;
                        if ( getBool() ) {
                            parameters["tagSize"] = getDefaultSize();
                        } else {
                            parameters["tagSize"] = PRNG() % 102400;
                        }
                    } else {
                        parameters["tagSize_enabled"] = false;
                    }

                    parameters["ciphertextSize"] = cleartext.length();

                    cryptofuzz::operation::SymmetricEncrypt op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("SymmetricDecrypt"):
                {
                    const bool aad_enabled = PRNG() % 2;
                    const bool tag_enabled = PRNG() % 2;
                    size_t numParts = 0;
                    uint32_t expected = 0;

                    numParts++; /* modifier */
                    numParts++; /* cleartext */
                    numParts++; /* iv */
                    numParts++; /* key */

                    if ( aad_enabled ) {
                        numParts++; /* aad */
                    }
                    if ( tag_enabled ) {
                        numParts++; /* tag */
                    }

                    auto lengths = SplitLength(maxSize - 64, numParts);

                    parameters["modifier"] = getBuffer(lengths[0]);
                    if ( getBool() ) {
                        if ( 16 < lengths[1] ) {
                            lengths[1] = 16;
                        }
                    }
                    switch (PRNG() % 2){
                        case 0:
                            if ( Pool_BlockCipherEncrypt.Have() ) {
                                const auto P = Pool_BlockCipherEncrypt.Get();
                                parameters["ciphertext"] = P.ciphertext;
                                parameters["cipher"]["iv"] = P.iv;
                                parameters["cipher"]["key"] = P.key;
                                parameters["cleartextSize"] = P.cleartextSize;
                                expected = 1;
                                break;
                            } 
                        default: {
                            uint64_t ciphertype = getRandomCipher();
                            parameters["cipher"]["cipherType"] = ciphertype;
                            std::string ciphertext = "";
                            if(ciphertype == CF_CIPHER("AES")){
                                ciphertext = getBuffer(16*(PRNG()%10));
                            }else{
                                ciphertext = getSeedCipherText(lengths[1], ciphertype);
                            }
                            parameters["ciphertext"] = ciphertext;
                            parameters["cipher"]["iv"] = getSeedIV(lengths[2], ciphertype);
                            parameters["cipher"]["key"] = getSeedKey(lengths[3], ciphertype);
                            parameters["cleartextSize"] = ciphertext.length() + PRNG() % 10;
                        }
                        break;
                    }

                    if ( aad_enabled ) {
                        parameters["aad_enabled"] = true;
                        if ( getBool() ) {
                            lengths[4] = 0;
                        }
                        parameters["aad"] = getBuffer(lengths[4]);
                    } else {
                        parameters["aad_enabled"] = false;
                    }

                    if ( tag_enabled ) {
                        parameters["tag_enabled"] = true;
                        parameters["tag"] = getBuffer(lengths[aad_enabled ? 5 : 4], true);
                    } else {
                        parameters["tag_enabled"] = false;
                    }
                    parameters["expected"] = expected;
                    cryptofuzz::operation::SymmetricDecrypt op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("BignumCalc"):
            case    CF_OPERATION("BignumCalc_Mod_BLS12_381_R"):
            case    CF_OPERATION("BignumCalc_Mod_BLS12_381_P"):
            case    CF_OPERATION("BignumCalc_Mod_2Exp256"):
            case    CF_OPERATION("BignumCalc_Mod_SECP256K1"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1000);
                    parameters["calcOp"] = getRandomCalcOp();
                    parameters["bn1"] = getSeedBignum();
                    parameters["bn2"] = getSeedBignum();
                    parameters["bn3"] = getSeedBignum();
                    parameters["bn4"] = "";
                    cryptofuzz::operation::BignumCalc op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("ECC_PrivateToPublic"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1000);
                    const auto curveID = getRandomCurve();
                    parameters["curveType"] = curveID;

                    if ( getBool() ) {
                        const auto order = cryptofuzz::repository::ECC_CurveToOrder(curveID);
                        if ( order != std::nullopt ) {
                            const auto o = boost::multiprecision::cpp_int(*order);
                            parameters["priv"] = boost::lexical_cast<std::string>(o-1);
                        } else {
                            parameters["priv"] = getSeedBignum();
                        }
                    } else {
                        parameters["priv"] = getSeedBignum();
                    }
                    cryptofuzz::operation::ECC_PrivateToPublic op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("ECC_ValidatePubkey"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1000);
                    uint32_t expected = 0;
                    if ( Pool_CurveKeypair.Have() ) {
                        const auto P = Pool_CurveKeypair.Get();
                        parameters["curveType"] = P.curveID;
                        parameters["pub_x"] = P.pub_x;
                        parameters["pub_y"] = P.pub_y;
                        switch(PRNG() % 5){
                            case 0:
                            case 1:{
                                /* origin curve value*/
                                parameters["pub_x"] = P.pub_x;
                                parameters["pub_y"] = P.pub_y;
                                if(P.pub_x != "" && P.pub_y != "" &&
                                   P.pub_x != "0" && P.pub_y != "0" ) expected = 1;
                                break;
                            }
                            case 2:{
                                /* near value*/
                                if(getBool()){
                                    parameters["pub_x"] = P.pub_x;
                                    parameters["pub_y"] = getBool()?
                                    boost::lexical_cast<std::string>(boost::multiprecision::cpp_int(P.pub_y) + 1):
                                    boost::lexical_cast<std::string>(boost::multiprecision::cpp_int(P.pub_y) - 1);
                                }else{
                                    parameters["pub_x"] = getBool()?
                                    boost::lexical_cast<std::string>(boost::multiprecision::cpp_int(P.pub_x) + 1):
                                    boost::lexical_cast<std::string>(boost::multiprecision::cpp_int(P.pub_x) - 1);
                                    parameters["pub_y"] = P.pub_y;
                                }
                                if(P.curveID != CF_ECC_CURVE("x25519") && P.curveID != CF_ECC_CURVE("x448") &&
                                   P.curveID != CF_ECC_CURVE("ed25519") && P.curveID != CF_ECC_CURVE("ed448")){
                                    expected = 2;
                                }
                                break;
                            }
                            case 3:{
                                /* switch */
                                parameters["pub_x"] = P.pub_y;
                                parameters["pub_y"] = P.pub_x;
                                expected = 3;
                                break;
                            }
                            case 4:{
                                /* change curveType */
                                parameters["pub_x"] = P.pub_x;
                                parameters["pub_y"] = P.pub_y;
                                uint64_t curve = getRandomCurve();;
                                expected = 0;
                                parameters["curveType"] = curve;
                                break;
                            }
                        }
                    } else {
                        parameters["curveType"] = getRandomCurve();
                        parameters["pub_x"] = getSeedBignum();
                        parameters["pub_y"] = getSeedBignum();
                    }
                    parameters["id"] = expected;
                    cryptofuzz::operation::ECC_ValidatePubkey op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("ECDH_Derive"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1000);
                    // if ( Pool_CurvePrivkey.Have() && getBool() == true ) {
                    if ( Pool_CurvePrivkey.Have()) {

                        const auto P1 = Pool_CurveKeypair.Get();
                        // const auto P2 = Pool_CurveKeypair.Get();

                        // CF_CHECK_EQ(P1.curveID, P2.curveID);

                        parameters["curveType"] = P1.curveID;

                        parameters["priv"] = P1.privkey;

                        parameters["pub_x"] = P1.pub_x;
                        parameters["pub_y"] = P1.pub_y;
                    } else {
                        parameters["curveType"] = getRandomCurve();

                        parameters["priv"] = getSeedBignum();

                        parameters["pub_x"] = getSeedBignum();
                        parameters["pub_y"] = getSeedBignum();
                    }

                    cryptofuzz::operation::ECDH_Derive op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("ECDSA_Sign"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1000);
                    // if ( Pool_CurvePrivkey.Have() && getBool() == true ) {
                     if ( Pool_CurvePrivkey.Have()) {
                        const auto P1 = Pool_CurvePrivkey.Get();
                        parameters["curveType"] = P1.curveID;
                        parameters["priv"] = P1.priv;
                    }else{
                        parameters["curveType"] = getRandomCurve();
                        parameters["priv"] = getSeedBignum();
                    }
                    parameters["nonce"] = getSeedBignum();

                    if ( getBool() ) {
                        parameters["cleartext"] = cryptofuzz::util::DecToHex(getSeedBignum(true), (PRNG() % 64) * 2);
                    } else {
                        parameters["cleartext"] = getSeedClearText(PRNG() % 32);
                    }
                    parameters["nonceSource"] = PRNG() % 3;
                    parameters["digestType"] = CF_DIGEST("NULL");

                    cryptofuzz::operation::ECDSA_Sign op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("ECGDSA_Sign"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1000);

                    const auto P1 = Pool_CurvePrivkey.Get();

                    parameters["curveType"] = P1.curveID;
                    parameters["priv"] = P1.priv;
                    parameters["nonce"] = getSeedBignum();

                    if ( getBool() ) {
                        parameters["cleartext"] = cryptofuzz::util::DecToHex(getSeedBignum(true), (PRNG() % 64) * 2);
                    } else {
                        parameters["cleartext"] = getSeedClearText(PRNG() % 32);
                    }
                    parameters["nonceSource"] = PRNG() % 3;
                    // parameters["digestType"] = getRandomDigest();
                    parameters["digestType"] = getBool() == true ? CF_DIGEST("NULL") : CF_DIGEST("SHA256");
                    cryptofuzz::operation::ECGDSA_Sign op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("ECRDSA_Sign"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1000);

                    const auto P1 = Pool_CurvePrivkey.Get();

                    parameters["curveType"] = P1.curveID;
                    parameters["priv"] = P1.priv;
                    parameters["nonce"] = getSeedBignum();

                    if ( getBool() ) {
                        parameters["cleartext"] = cryptofuzz::util::DecToHex(getSeedBignum(true), (PRNG() % 64) * 2);
                    } else {
                        parameters["cleartext"] = getSeedClearText(PRNG() % 32);
                    }
                    parameters["nonceSource"] = PRNG() % 3;
                    parameters["digestType"] = getBool() == true ? CF_DIGEST("NULL") : getRandomDigest();
                    cryptofuzz::operation::ECRDSA_Sign op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("Schnorr_Sign"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1000);

                    const auto P1 = Pool_CurvePrivkey.Get();

                    parameters["curveType"] = P1.curveID;
                    parameters["priv"] = P1.priv;
                    parameters["nonce"] = getSeedBignum();

                    if ( getBool() ) {
                        parameters["cleartext"] = cryptofuzz::util::DecToHex(getSeedBignum(true), (PRNG() % 64) * 2);
                    } else {
                        parameters["cleartext"] = getSeedClearText(PRNG() % 32);
                    }
                    parameters["nonceSource"] = PRNG() % 3;
                    parameters["digestType"] = getBool() == true ? CF_DIGEST("NULL") : getRandomDigest();
                    cryptofuzz::operation::Schnorr_Sign op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("ECDSA_Verify"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1024);
                    uint32_t expected = 0;
                    if ( Pool_CurveECDSASignature.Have() == true ) {
                        const auto P = Pool_CurveECDSASignature.Get();
                        parameters["curveType"] = P.curveID;
                        parameters["signature"]["pub"][0] = P.pub_x;
                        parameters["signature"]["pub"][1] = P.pub_y;
                        switch(PRNG() % 5){
                            case 0:
                            case 1:{
                                /* origin curve value*/
                                parameters["signature"]["pub"][0] = P.pub_x;
                                parameters["signature"]["pub"][1] = P.pub_y;
                                if(P.pub_x != "" && P.pub_y != "" &&
                                   P.pub_x != "0" && P.pub_y != "0" ) expected = 1;
                                break;
                            }
                            case 2:{
                                /* near value*/
                                if(getBool()){
                                    parameters["signature"]["pub"][0] = P.pub_x;
                                    parameters["signature"]["pub"][1] = getBool()?
                                    boost::lexical_cast<std::string>(boost::multiprecision::cpp_int(P.pub_y) + 1):
                                    boost::lexical_cast<std::string>(boost::multiprecision::cpp_int(P.pub_y) - 1);
                                }else{
                                    parameters["signature"]["pub"][0] = getBool()?
                                    boost::lexical_cast<std::string>(boost::multiprecision::cpp_int(P.pub_x) + 1):
                                    boost::lexical_cast<std::string>(boost::multiprecision::cpp_int(P.pub_x) - 1);
                                    parameters["signature"]["pub"][1] = P.pub_y;
                                }
                                if(P.curveID != CF_ECC_CURVE("x25519") && P.curveID != CF_ECC_CURVE("x448") &&
                                   P.curveID != CF_ECC_CURVE("ed25519") && P.curveID != CF_ECC_CURVE("ed448")){
                                    expected = 2;
                                }
                                break;
                            }
                            case 3:{
                                /* switch */
                                parameters["signature"]["pub"][0] = P.pub_y;
                                parameters["signature"]["pub"][1] = P.pub_x;
                                expected = 3;
                                break;
                            }
                            case 4:{
                                /* change curveType */
                                parameters["signature"]["pub"][0] = P.pub_x;
                                parameters["signature"]["pub"][1] = P.pub_y;
                                uint64_t newcurve = getRandomCurve();
                                expected = 0;
                                parameters["curveType"] = newcurve;
                                break;
                            }
                        }
                        /* mutator R and S*/
                        if(getBool()){
                            parameters["signature"]["signature"][0] = getBool() ? getSeedBignum() : P.sig_r;
                            auto sigS = getBool() ? getSeedBignum() : P.sig_y;
                            if ( getBool() ) {
                                /* Test ECDSA signature malleability */

                                const auto order = cryptofuzz::repository::ECC_CurveToOrder(P.curveID);
                                if ( order != std::nullopt ) {
                                    const auto o = boost::multiprecision::cpp_int(*order);
                                    const auto s = boost::multiprecision::cpp_int(sigS);
                                    if ( o > s ) {
                                        sigS = boost::lexical_cast<std::string>(o - s);
                                    }
                                }
                            }
                            parameters["signature"]["signature"][1] = sigS;
                            if(expected == 1)expected = 0;
                        }else{
                            parameters["signature"]["signature"][0] = P.sig_r;
                            parameters["signature"]["signature"][1] = P.sig_y;
                        }
                        parameters["signature"]["signature"][0] = P.sig_r;
                        parameters["signature"]["signature"][1] = P.sig_y;
                         /* mutator clearText*/
                        parameters["cleartext"] = P.cleartext;
                        /* fix digest type*/
                        parameters["digestType"] = P.digestID;

                    } else {
                        parameters["curveType"] = getRandomCurve();

                        parameters["signature"]["pub"][0] = getSeedBignum();
                        parameters["signature"]["pub"][1] = getSeedBignum();

                        parameters["signature"]["signature"][0] = getSeedBignum();
                        parameters["signature"]["signature"][1] = getSeedBignum();

                        parameters["cleartext"] = cryptofuzz::util::DecToHex(getSeedBignum(true), (PRNG() % 64) * 2);
                        parameters["digestType"] = CF_DIGEST("NULL");
                    }
                    parameters["id"] = expected;
                    cryptofuzz::operation::ECDSA_Verify op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("ECGDSA_Verify"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1024);

                    if ( Pool_CurveECDSASignature.Have() == true ) {
                        const auto P = Pool_CurveECDSASignature.Get();
                        parameters["curveType"] = P.curveID;

                        parameters["signature"]["pub"][0] = getBool() ? getSeedBignum() : P.pub_x;
                        parameters["signature"]["pub"][1] = getBool() ? getSeedBignum() : P.pub_y;

                        parameters["signature"]["signature"][0] =  P.sig_r;
                        auto sigS = P.sig_y;

        
                        parameters["signature"]["signature"][1] = sigS;
                        parameters["cleartext"] = P.cleartext;
                    } else {
                        parameters["curveType"] = getRandomCurve();

                        parameters["signature"]["pub"][0] = getSeedBignum();
                        parameters["signature"]["pub"][1] = getSeedBignum();

                        parameters["signature"]["signature"][0] = getSeedBignum();
                        parameters["signature"]["signature"][1] = getSeedBignum();

                        parameters["cleartext"] = cryptofuzz::util::DecToHex(getSeedBignum(true), (PRNG() % 64) * 2);
                    }

                    parameters["digestType"] = getRandomDigest();

                    cryptofuzz::operation::ECGDSA_Verify op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("ECRDSA_Verify"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1024);

                    if ( Pool_CurveECDSASignature.Have() == true ) {
                        const auto P = Pool_CurveECDSASignature.Get();
                        parameters["curveType"] = P.curveID;

                        parameters["signature"]["pub"][0] = getBool() ? getSeedBignum() : P.pub_x;
                        parameters["signature"]["pub"][1] = getBool() ? getSeedBignum() : P.pub_y;

                        parameters["signature"]["signature"][0] = getBool() ? getSeedBignum() : P.sig_r;
                        auto sigS = getBool() ? getSeedBignum() : P.sig_y;

                        if ( getBool() ) {
                            /* Test ECRDSA signature malleability */

                            const auto order = cryptofuzz::repository::ECC_CurveToOrder(P.curveID);
                            if ( order != std::nullopt ) {
                                const auto o = boost::multiprecision::cpp_int(*order);
                                const auto s = boost::multiprecision::cpp_int(sigS);
                                if ( o > s ) {
                                    sigS = boost::lexical_cast<std::string>(o - s);
                                }
                            }
                        }

                        parameters["signature"]["signature"][1] = sigS;
                        parameters["cleartext"] = P.cleartext;
                    } else {
                        parameters["curveType"] = getRandomCurve();

                        parameters["signature"]["pub"][0] = getSeedBignum();
                        parameters["signature"]["pub"][1] = getSeedBignum();

                        parameters["signature"]["signature"][0] = getSeedBignum();
                        parameters["signature"]["signature"][1] = getSeedBignum();

                        parameters["cleartext"] = cryptofuzz::util::DecToHex(getSeedBignum(true), (PRNG() % 64) * 2);
                    }

                    parameters["digestType"] = getRandomDigest();

                    cryptofuzz::operation::ECRDSA_Verify op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("Schnorr_Verify"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1024);

                    if ( Pool_CurveECDSASignature.Have() == true ) {
                        const auto P = Pool_CurveECDSASignature.Get();
                        parameters["curveType"] = P.curveID;

                        parameters["signature"]["pub"][0] = getBool() ? getSeedBignum() : P.pub_x;
                        parameters["signature"]["pub"][1] = getBool() ? getSeedBignum() : P.pub_y;

                        parameters["signature"]["signature"][0] = getBool() ? getSeedBignum() : P.sig_r;
                        auto sigS = getBool() ? getSeedBignum() : P.sig_y;

                        if ( getBool() ) {
                            /* Test Schnorr signature malleability */

                            const auto order = cryptofuzz::repository::ECC_CurveToOrder(P.curveID);
                            if ( order != std::nullopt ) {
                                const auto o = boost::multiprecision::cpp_int(*order);
                                const auto s = boost::multiprecision::cpp_int(sigS);
                                if ( o > s ) {
                                    sigS = boost::lexical_cast<std::string>(o - s);
                                }
                            }
                        }

                        parameters["signature"]["signature"][1] = sigS;
                        parameters["cleartext"] = P.cleartext;
                    } else {
                        parameters["curveType"] = getRandomCurve();

                        parameters["signature"]["pub"][0] = getSeedBignum();
                        parameters["signature"]["pub"][1] = getSeedBignum();

                        parameters["signature"]["signature"][0] = getSeedBignum();
                        parameters["signature"]["signature"][1] = getSeedBignum();

                        parameters["cleartext"] = cryptofuzz::util::DecToHex(getSeedBignum(true), (PRNG() % 64) * 2);
                    }

                    parameters["digestType"] = getRandomDigest();

                    cryptofuzz::operation::Schnorr_Verify op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("ECDSA_Recover"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1024);

                    if ( getBool() && Pool_CurveECDSASignature.Have() == true ) {
                        const auto P = Pool_CurveECDSASignature.Get();
                        parameters["curveType"] = P.curveID;

                        parameters["signature"][0] = getBool() ? getSeedBignum() : P.sig_r;
                        parameters["signature"][1] = getBool() ? getSeedBignum() : P.sig_y;

                        if ( getBool() ) {
                            parameters["cleartext"] = P.cleartext;
                        } else {
                            parameters["cleartext"] = cryptofuzz::util::DecToHex(getSeedBignum(true), (PRNG() % 64) * 2);
                        }
                    } else {
                        parameters["curveType"] = getRandomCurve();

                        parameters["signature"][0] = getSeedBignum();
                        parameters["signature"][1] = getSeedBignum();

                        parameters["cleartext"] = cryptofuzz::util::DecToHex(getSeedBignum(true), (PRNG() % 64) * 2);
                    }

                    parameters["id"] = PRNG() % 4;
                    parameters["digestType"] = getRandomDigest();

                    cryptofuzz::operation::ECDSA_Recover op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("ECC_GenerateKeyPair"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 128);
                    parameters["curveType"] = getRandomCurve();

                    cryptofuzz::operation::ECC_GenerateKeyPair op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("ECIES_Encrypt"):
            case    CF_OPERATION("ECIES_Decrypt"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 128);
                    if ( operation == CF_OPERATION("ECIES_Encrypt") ) {
                        parameters["cleartext"] = getSeedClearText(PRNG() % 1024);
                    } else {
                        parameters["ciphertext"] = getSeedClearText(PRNG() % 1024);
                    }
                    parameters["cipherType"] = getRandomCipher();
                    // parameters["cipherType"] = CF_CIPHER("AES_128_CBC");
                    parameters["iv_enabled"] = false;

                    parameters["priv"] = getSeedBignum();

                    if ( Pool_CurveKeypair.Have() && getBool() == true ) {
                        const auto P = Pool_CurveKeypair.Get();

                        parameters["curveType"] = P.curveID;
                        parameters["pub_x"] = P.pub_x;
                        parameters["pub_y"] = P.pub_y;

                        if ( Pool_CurvePrivkey.Have() && getBool() == true ) {
                            const auto P2 = Pool_CurvePrivkey.Get();
                            if ( P2.curveID == P.curveID ) {
                                parameters["priv"] = P2.priv;
                            }
                        }
                    } else {
                        parameters["curveType"] = getRandomCurve();
                        parameters["pub_x"] = getSeedBignum();
                        parameters["pub_y"] = getSeedBignum();
                    }

                    if ( operation == CF_OPERATION("ECIES_Encrypt") ) {
                        cryptofuzz::operation::ECIES_Encrypt op(parameters);
                        op.Serialize(dsOut2);
                    } else {
                        cryptofuzz::operation::ECIES_Decrypt op(parameters);
                        op.Serialize(dsOut2);
                    }
                }
                break;
            case    CF_OPERATION("ECC_Point_Add"):
            case    CF_OPERATION("ECC_Point_Mul"):
                {
                    parameters["modifier"] = "";
                    if (Pool_CurveECC_Point.Have() == true ) {
                        // if ( getBool() && Pool_CurveECC_Point.Have() == true ) {
                        const auto P = Pool_CurveECC_Point.Get();
                        uint64_t curveID = P.curveID;
                        if(CurveToPool.count(curveID) != 0 && CurveToPool[curveID].Have()){
                            const auto P1 = CurveToPool[curveID].Get();
                            parameters["a_x"] = P1.x;
                            parameters["a_y"] = P1.y;
                            const auto P2 = CurveToPool[curveID].Get();
                            parameters["b_x"] = P2.x;
                            parameters["b_y"] = P2.y;
                            parameters["curveType"] = curveID;
                        }else{
                            parameters["curveType"] = curveID;
                            parameters["a_x"] = P.x;
                            parameters["a_y"] = P.y;
                            const auto P2 = Pool_CurveECC_Point.Get();
                            parameters["b_x"] = P2.x;
                            parameters["b_y"] = P2.y;
                        }
                    }else{
                        uint64_t curveID = getRandomCurve();
                        parameters["curveType"] = getRandomCurve();
                        std::string s;
                        s = getSeedBignum();
                        parameters["a_x"] = s;
                        parameters["a_y"] = getBool()? getEccY(s,curveID) : getSeedBignum();
                        s = getSeedBignum();
                        parameters["b_x"] = s;
                        parameters["b_y"] = getBool()? getEccY(s,curveID) : getSeedBignum();
                        
                    }

                    cryptofuzz::operation::ECC_Point_Add op(parameters);
                    op.Serialize(dsOut2);

                    generateECCPoint();
                }
                break;
            // case    CF_OPERATION("ECC_Point_Mul"):
            //     {
            //         parameters["modifier"] = "";

            //         if ( Pool_CurveECC_Point.Have() == true && getBool()) {
            //             const auto P = Pool_CurveECC_Point.Get();
            //             parameters["curveType"] = P.curveID;

            //             parameters["a_x"] = getBool() ? getSeedBignum() : P.x;
            //             parameters["a_y"] = getBool() ? getSeedBignum() : P.y;
            //         } else {
            //             uint64_t curveID = getRandomCurve();
            //             parameters["curveType"] = curveID;
            //             string s = getSeedBignum();
            //             parameters["a_x"] = s;
            //             parameters["a_y"] = getBool() ? getEccY(s, curveID) : getSeedBignum();
            //         }

            //         parameters["b"] = getSeedBignum();

            //         cryptofuzz::operation::ECC_Point_Mul op(parameters);
            //         op.Serialize(dsOut2);

            //         generateECCPoint();
            //     }
            //     break;
            case    CF_OPERATION("KDF_SCRYPT"):
                {
                    size_t numParts = 0;

                    numParts++; /* modifier */
                    numParts++; /* password */
                    numParts++; /* salt */

                    const auto lengths = SplitLength(maxSize - 64, numParts);

                    parameters["modifier"] = getBuffer(lengths[0]);
                    parameters["password"] = getSeedClearText(lengths[1]);
                    parameters["salt"] = getSeedClearText(lengths[2]);
                    parameters["N"] = pow(2,PRNG() % 5);
                    parameters["r"] = 8;
                    parameters["p"] = PRNG() % 1024 + 1;
                    parameters["keySize"] = PRNG() % 100;

                    cryptofuzz::operation::KDF_SCRYPT op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("KDF_HKDF"):
                {
                    size_t numParts = 0;

                    numParts++; /* modifier */
                    numParts++; /* password */
                    numParts++; /* salt */
                    numParts++; /* info */

                    const auto lengths = SplitLength(maxSize - 64, numParts);

                    parameters["modifier"] = getBuffer(lengths[0]);
                    parameters["password"] = getSeedClearText(lengths[1]);
                    parameters["salt"] = getSeedClearText(lengths[2]);
                    parameters["info"] = getBuffer(lengths[3]);
                    uint64_t digestType = getRandomDigest();
                    if(DigestLengthMap.count(digestType) != 0){
                         parameters["keySize"] = PRNG() % (DigestLengthMap[digestType]*255);
                    }else{
                         parameters["keySize"] = PRNG() % (2*255);
                    }
                    parameters["digestType"] = digestType;
                    cryptofuzz::operation::KDF_HKDF op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("KDF_TLS1_PRF"):
                {
                    size_t numParts = 0;

                    numParts++; /* modifier */
                    numParts++; /* secret */
                    numParts++; /* seed */

                    const auto lengths = SplitLength(maxSize - 64, numParts);

                    parameters["modifier"] = getBuffer(lengths[0]);
                    parameters["secret"] = getSeedClearText(lengths[1]);
                    parameters["seed"] = getSeedClearText(lengths[2]);
                    parameters["keySize"] = PRNG() % 1024;
                    // parameters["digestType"] = getRandomDigest();

                    parameters["digestType"] = CF_DIGEST("MD5_SHA1");

                    cryptofuzz::operation::KDF_TLS1_PRF op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("KDF_PBKDF"):
                {
                    size_t numParts = 0;

                    numParts++; /* modifier */
                    numParts++; /* password */
                    numParts++; /* salt */

                    const auto lengths = SplitLength(maxSize - 64, numParts);

                    parameters["modifier"] = getBuffer(lengths[0]);
                    parameters["password"] = getSeedClearText(lengths[1]);
                    parameters["salt"] = getSeedClearText(lengths[2]);
                    parameters["iterations"] = PRNG() % 5;
                    parameters["keySize"] = PRNG() % 256;
                    parameters["digestType"] = getRandomDigest();

                    cryptofuzz::operation::KDF_PBKDF op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("KDF_PBKDF1"):
                {
                    size_t numParts = 0;

                    numParts++; /* modifier */
                    numParts++; /* password */
                    numParts++; /* salt */

                    const auto lengths = SplitLength(maxSize - 64, numParts);

                    parameters["modifier"] = getSeedClearText(lengths[0]);
                    parameters["password"] = getBuffer(lengths[1]);
                    parameters["salt"] = getSeedClearText(lengths[2]);
                    parameters["iterations"] = PRNG() % 5;
                    parameters["keySize"] = PRNG() % 256;
                    parameters["digestType"] = getRandomDigest();

                    cryptofuzz::operation::KDF_PBKDF op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("KDF_PBKDF2"):
                {
                    size_t numParts = 0;

                    numParts++; /* modifier */
                    numParts++; /* password */
                    numParts++; /* salt */

                    const auto lengths = SplitLength(maxSize - 64, numParts);

                    parameters["modifier"] = getBuffer(lengths[0]);
                    parameters["password"] = getSeedClearText(lengths[1]);
                    parameters["salt"] = getSeedClearText(lengths[2]);
                    parameters["iterations"] = PRNG() % 5;
                    parameters["keySize"] = PRNG() % 256;
                    parameters["digestType"] = getRandomDigest();

                    cryptofuzz::operation::KDF_PBKDF2 op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("KDF_ARGON2"):
                {
                    size_t numParts = 0;

                    numParts++; /* modifier */
                    numParts++; /* password */
                    numParts++; /* salt */

                    const auto lengths = SplitLength(maxSize - 64, numParts);

                    parameters["modifier"] = getBuffer(lengths[0]);
                    parameters["password"] = getSeedClearText(lengths[1]);
                    // parameters["salt"] = getSeedClearText(lengths[2]);
                    parameters["salt"] = getBuffer(16);
                    parameters["type"] = PRNG() % 3 + 1;
                    // parameters["threads"] = PRNG() % 256;
                    parameters["threads"] = 1;
                    parameters["memory"] = PRNG() % (64*1024);
                    // parameters["iterations"] = PRNG() % 3;
                    parameters["iterations"] = PRNG()%3+3;
                    // parameters["keySize"] = PRNG() % 1024;
                    parameters["keySize"] = PRNG() % 1008 + 16;

                    cryptofuzz::operation::KDF_ARGON2 op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("KDF_SSH"):
                {
                    size_t numParts = 0;

                    numParts++; /* modifier */
                    numParts++; /* key */
                    numParts++; /* xcghash */
                    numParts++; /* session_id */

                    const auto lengths = SplitLength(maxSize - 64, numParts);

                    parameters["modifier"] = getBuffer(lengths[0]);
                    parameters["key"] = getSeedClearText(lengths[1]);
                    parameters["xcghash"] = getSeedClearText(lengths[2]);
                    parameters["session_id"] = getSeedClearText(lengths[3]);
                    parameters["type"] = getBuffer(1);
                    parameters["keySize"] = PRNG() % 1024;
                    parameters["digestType"] = getRandomDigest();

                    cryptofuzz::operation::KDF_SSH op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("KDF_X963"):
                {
                    size_t numParts = 0;

                    numParts++; /* modifier */
                    numParts++; /* secret */
                    numParts++; /* info */

                    const auto lengths = SplitLength(maxSize - 64, numParts);

                    parameters["modifier"] = getBuffer(lengths[0]);
                    parameters["secret"] = getSeedClearText(lengths[1]);
                    parameters["info"] = getSeedClearText(lengths[2]);
                    parameters["keySize"] = PRNG() % 1024;
                    parameters["digestType"] = getRandomDigest();

                    cryptofuzz::operation::KDF_X963 op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("KDF_SP_800_108"):
                {
                    size_t numParts = 0;

                    numParts++; /* modifier */
                    numParts++; /* secret */
                    numParts++; /* salt */
                    numParts++; /* label */

                    const auto lengths = SplitLength(maxSize - 64, numParts);

                    parameters["mech"]["mode"] = true;
                    parameters["mech"]["type"] = getRandomDigest();


                    // if ( getBool() == true ) {
                    //     /* MAC = HMAC */
                    //     parameters["mech"]["mode"] = true;
                    //     parameters["mech"]["type"] = getRandomDigest();
                    // } else {
                    //     /* MAC = CMAC */
                    //     parameters["mech"]["mode"] = false;
                    //     parameters["mech"]["type"] = getRandomCipher();
                    // }

                    parameters["modifier"] = getBuffer(lengths[0]);
                    parameters["secret"] = getSeedClearText(lengths[1]);
                    unsigned int mode = 0;
                    parameters["mode"] = mode;
                    if(mode == 1){
                        parameters["salt"] = getBuffer(0);
                    }else{
                        parameters["salt"] = getSeedClearText(lengths[2]);
                    }
                    parameters["label"] = getBuffer(lengths[3]);
                    parameters["keySize"] = PRNG() % 17000;

                    cryptofuzz::operation::KDF_SP_800_108 op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("DH_GenerateKeyPair"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1000);
                    parameters["prime"] = getSeedBignum();
                    parameters["base"] = getSeedBignum();

                    cryptofuzz::operation::DH_GenerateKeyPair op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("DH_Derive"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1000);
                    parameters["prime"] = getSmallSeedBignum();
                    parameters["base"] = getSmallSeedBignum();
                    if ( Pool_DH_PublicKey.Have() && getBool() == true ) {
                        parameters["pub"] = Pool_DH_PublicKey.Get().str;
                    } else {
                        parameters["pub"] = getSeedBignum();
                    }

                    if ( Pool_DH_PrivateKey.Have() && getBool() == true ) {
                        parameters["priv"] = Pool_DH_PrivateKey.Get().str;
                    } else {
                        parameters["priv"] = getSeedBignum();
                    }

                    cryptofuzz::operation::DH_Derive op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("BLS_PrivateToPublic"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1000);
                    parameters["curveType"] = CF_ECC_CURVE("BLS12_381");

                    parameters["priv"] = getBLSPrivateKey();

                    cryptofuzz::operation::BLS_PrivateToPublic op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("BLS_PrivateToPublic_G2"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1000);
                    parameters["curveType"] = CF_ECC_CURVE("BLS12_381");

                    parameters["priv"] = getBLSPrivateKey();

                    cryptofuzz::operation::BLS_PrivateToPublic_G2 op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("BLS_Sign"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1000);
                    parameters["curveType"] = CF_ECC_CURVE("BLS12_381");
                    auto hashOrPoint = getBool();
                    //const auto hashOrPoint = false;
                    if(hashOrPoint == true || Pool_CurveBLSG2.Have() == false){
                        hashOrPoint = true;
                        parameters["cleartext"] = cryptofuzz::util::DecToHex(getSeedBignum(true), (PRNG() % 64) * 2);
                        parameters["point_v"] = "";
                        parameters["point_w"] = "";
                        parameters["point_x"] = "";
                        parameters["point_y"] = "";
                    }else{
                        const auto P = Pool_CurveBLSG2.Get();
                        parameters["point_v"] = P.g2_v;
                        parameters["point_w"] = P.g2_w;
                        parameters["point_x"] = P.g2_x;
                        parameters["point_y"] = P.g2_y;
                        parameters["cleartext"] = "";
                    }
                    parameters["hashOrPoint"] = hashOrPoint;
                    // parameters["dest"] = getBool() ? getBuffer(PRNG() % 512) : get_BLS_predefined_DST();
                    parameters["dest"] = get_BLS_predefined_DST();
                    parameters["aug"] = "";
                    parameters["priv"] = getBLSPrivateKey();

                    cryptofuzz::operation::BLS_Sign op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("BLS_Verify"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1000);
                    uint32_t expected = 0;
                    if ( Pool_CurveBLSSignature.Have() == true ) {
                        const auto P = Pool_CurveBLSSignature.Get();
                        parameters["curveType"] = P.curveID;
                        parameters["hashOrPoint"] = true;
                        parameters["point_v"] = P.point_v;
                        parameters["point_w"] = P.point_w;
                        parameters["point_x"] = P.point_x;
                        parameters["point_y"] = P.point_y;
                        parameters["cleartext"] = P.cleartext;
                        parameters["dest"] = P.dest;
                        parameters["aug"] = P.aug;
                        parameters["pub_x"] = P.pub_x;
                        parameters["pub_y"] = P.pub_y;
                        parameters["sig_v"] = P.sig_v;
                        parameters["sig_w"] = P.sig_w;
                        parameters["sig_x"] = P.sig_x;
                        parameters["sig_y"] = P.sig_y;
                        switch ( PRNG() % 3){
                            case 0:{
                                parameters["curveType"] = P.curveID;
                                parameters["hashOrPoint"] = P.hashOrPoint;
                                parameters["point_v"] = P.point_v;
                                parameters["point_w"] = P.point_w;
                                parameters["point_x"] = P.point_x;
                                parameters["point_y"] = P.point_y;
                                parameters["cleartext"] = P.cleartext;
                                parameters["dest"] = P.dest;
                                parameters["aug"] = P.aug;
                                parameters["pub_x"] = P.pub_x;
                                parameters["pub_y"] = P.pub_y;
                                parameters["sig_v"] = P.sig_v;
                                parameters["sig_w"] = P.sig_w;
                                parameters["sig_x"] = P.sig_x;
                                parameters["sig_y"] = P.sig_y;
                                if(P.pub_x != "0" && P.pub_y != "0") expected = 1;
                                break;
                            }
                            case 1:{
                                parameters["curveType"] = P.curveID;
                                parameters["hashOrPoint"] = P.hashOrPoint;
                                parameters["point_v"] = P.point_v;
                                parameters["point_w"] = P.point_w;
                                parameters["point_x"] = P.point_x;
                                parameters["point_y"] = P.point_y;
                                parameters["cleartext"] = P.cleartext;
                                parameters["dest"] = P.dest;
                                parameters["aug"] = P.aug;
                                parameters["pub_x"] = P.pub_x;
                                parameters["pub_y"] = P.pub_y;
                                parameters["sig_v"] = P.sig_v;
                                parameters["sig_w"] = P.sig_w;
                                if(getBool()){
                                    parameters["sig_x"] = P.sig_x;
                                    parameters["sig_y"] = getBool()?
                                    boost::lexical_cast<std::string>(boost::multiprecision::cpp_int(P.sig_y) + 1):
                                    boost::lexical_cast<std::string>(boost::multiprecision::cpp_int(P.sig_y) - 1);
                                }else{
                                    parameters["sig_x"] = getBool()?
                                    boost::lexical_cast<std::string>(boost::multiprecision::cpp_int(P.sig_x) + 1):
                                    boost::lexical_cast<std::string>(boost::multiprecision::cpp_int(P.sig_x) - 1);
                                    parameters["sig_y"] = P.sig_y;
                                }
                                if(P.pub_x != "0" && P.pub_y != "0") expected = 2;
                                break;
                            }
                            case 2:{
                                parameters["curveType"] = P.curveID;
                                parameters["hashOrPoint"] = P.hashOrPoint;
                                parameters["point_v"] = P.point_v;
                                parameters["point_w"] = P.point_w;
                                parameters["point_x"] = P.point_x;
                                parameters["point_y"] = P.point_y;
                                parameters["cleartext"] = P.cleartext;
                                parameters["dest"] = P.dest;
                                parameters["aug"] = P.aug;
                                parameters["pub_x"] = P.pub_x;
                                parameters["pub_y"] = P.pub_y;
                                parameters["sig_v"] = P.sig_v;
                                parameters["sig_w"] = P.sig_w;
                                parameters["sig_x"] = P.sig_y;
                                parameters["sig_y"] = P.sig_x;
                                if(P.pub_x != "0" && P.pub_y != "0" && P.sig_y!=P.sig_x) expected = 3;
                                break;
                            }
                        }
                    } else {
                        parameters["curveType"] = CF_ECC_CURVE("BLS12_381");
                        const auto hashOrPoint = true;
                        parameters["hashOrPoint"] = hashOrPoint;
                        if ( hashOrPoint == true ) {
                            parameters["cleartext"] = getSeedClearText(PRNG() % 32);
                            parameters["point_v"] = "";
                            parameters["point_w"] = "";
                            parameters["point_x"] = "";
                            parameters["point_y"] = "";
                        } else {
                            parameters["point_v"] = getSeedBignum();
                            parameters["point_w"] = getSeedBignum();
                            parameters["point_x"] = getSeedBignum();
                            parameters["point_y"] = getSeedBignum();
                            parameters["cleartext"] = "";
                        }
                        // parameters["dest"] = getBool() ? getSeedClearText(PRNG() % 512) : get_BLS_predefined_DST();
                        parameters["dest"] = get_BLS_predefined_DST();
                        parameters["pub_x"] = getSeedBignum();
                        parameters["pub_y"] = getSeedBignum();
                        parameters["sig_v"] = getSeedBignum();
                        parameters["sig_w"] = getSeedBignum();
                        parameters["sig_x"] = getSeedBignum();
                        parameters["sig_y"] = getSeedBignum();
                    }
                    parameters["expected"] = expected;
                    cryptofuzz::operation::BLS_Verify op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("BLS_IsG1OnCurve"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1000);
                    parameters["curveType"] = CF_ECC_CURVE("BLS12_381");
                    uint32_t expected = 0;
                    if(Pool_CurveBLSG1.Have() == false){
                        parameters["g1_x"] = getSeedBignum();
                        parameters["g1_y"] = getSeedBignum();
                        expected = 0;
                    }else{
                        const auto P = Pool_CurveBLSG1.Get();
                        switch(PRNG() % 4){
                            case 0:{
                                parameters["g1_x"] = P.g1_x;
                                parameters["g1_y"] = P.g1_y;
                                if(P.g1_x!="0" || P.g1_y!="0"){
                                    expected = 1;
                                }
                                break;
                            }
                            case 1:{
                                parameters["g1_x"] = P.g1_y;
                                parameters["g1_y"] = P.g1_x;
                                if(P.g1_x!="0" || P.g1_y!="0"){
                                    expected = 2;
                                }
                                break;
                            }
                            case 2:{
                                if(getBool()){
                                    parameters["g1_x"] = P.g1_x;
                                    parameters["g1_y"] = getBool()?
                                    boost::lexical_cast<std::string>(boost::multiprecision::cpp_int(P.g1_y) + 1):
                                    boost::lexical_cast<std::string>(boost::multiprecision::cpp_int(P.g1_y) - 1);
                                }else{
                                    parameters["g1_x"] = getBool()?
                                    boost::lexical_cast<std::string>(boost::multiprecision::cpp_int(P.g1_x) + 1):
                                    boost::lexical_cast<std::string>(boost::multiprecision::cpp_int(P.g1_x) - 1);
                                    parameters["g1_y"] = P.g1_y;
                                }
                                expected = 3;
                                break;
                            }
                            case 3:{
                                parameters["g1_x"] = getSeedBignum();
                                parameters["g1_y"] = getSeedBignum();
                                expected = 0;
                                break;
                            }
                        }
                    }
                    parameters["expected"] = expected;
                    cryptofuzz::operation::BLS_IsG1OnCurve op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("BLS_IsG2OnCurve"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1000);
                    parameters["curveType"] = CF_ECC_CURVE("BLS12_381");
                    uint32_t expected = 0;
                    if(Pool_CurveBLSG2.Have() == false){
                        parameters["g2_v"] = getSeedBignum();
                        parameters["g2_w"] = getSeedBignum();
                        parameters["g2_x"] = getSeedBignum();
                        parameters["g2_y"] = getSeedBignum();
                        expected = 0;
                    }else{
                        const auto P = Pool_CurveBLSG2.Get();
                        switch(PRNG() % 3){
                            case 0:{
                                parameters["g2_v"] = P.g2_v;
                                parameters["g2_w"] = P.g2_w;
                                parameters["g2_x"] = P.g2_x;
                                parameters["g2_y"] = P.g2_y;
                                if(P.g2_v=="0"||P.g2_w=="0"||P.g2_x=="0"||P.g2_y=="0")expected = 0;
                                else if(P.g2_v==""||P.g2_w==""||P.g2_x==""||P.g2_y=="")expected = 0;
                                else expected = 1;
                                break;
                            }
                            case 1:{
                                parameters["g2_v"] = P.g2_v;
                                parameters["g2_w"] = P.g2_w;
                                parameters["g2_x"] = P.g2_y;
                                parameters["g2_y"] = P.g2_x;
                                if(P.g2_v=="0"||P.g2_w=="0"||P.g2_x=="0"||P.g2_y=="0")expected = 0;
                                else if(P.g2_v==""||P.g2_w==""||P.g2_x==""||P.g2_y=="")expected = 0;
                                else expected = 2;
                                break;
                            }
                            case 2:{
                                parameters["g2_v"] = GET_OR_BIGNUM(P.g2_v);
                                parameters["g2_w"] = GET_OR_BIGNUM(P.g2_w);
                                parameters["g2_x"] = GET_OR_BIGNUM(P.g2_x);
                                parameters["g2_y"] = GET_OR_BIGNUM(P.g2_y);
                                expected = 0;
                                break;
                            }
                        }
                    }
                    parameters["expected"] = expected;
                    cryptofuzz::operation::BLS_IsG2OnCurve op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("BLS_GenerateKeyPair"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1000);
                    parameters["curveType"] = CF_ECC_CURVE("BLS12_381");
                    parameters["ikm"] = getSeedClearText(PRNG() % 480 + 32);
                    parameters["info"] = "";
                    cryptofuzz::operation::BLS_GenerateKeyPair op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("BLS_Decompress_G1"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1000);
                    parameters["curveType"] = CF_ECC_CURVE("BLS12_381");
                    parameters["compressed"] = getBLSPrivateKey();

                    cryptofuzz::operation::BLS_Decompress_G1 op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("BLS_Compress_G1"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1000);
                    parameters["curveType"] = CF_ECC_CURVE("BLS12_381");
                    uint32_t expected = 0;
                    std::string compressed = "";
                    if(Pool_CurveBLSG1.Have() == false){
                        parameters["g1_x"] = getSeedBignum();
                        parameters["g1_y"] = getSeedBignum();
                        expected = 0;
                    }else{
                        if(Pool_CurveBLSG1_Compress.Have() == true){
                            const auto P = Pool_CurveBLSG1_Compress.Get();
                            compressed = P.compress;
                            parameters["g1_x"] = P.g1_x;
                            parameters["g1_y"] = P.g1_y;
                            switch(PRNG() % 4){
                                case 0:{
                                    parameters["g1_x"] = P.g1_x;
                                    parameters["g1_y"] = P.g1_y;
                                    expected = 1;
                                    break;
                                }
                                case 1:{
                                    parameters["g1_x"] = P.g1_y;
                                    parameters["g1_y"] = P.g1_x;
                                    if(P.g1_y == P.g1_x){
                                        expected = 1;
                                    }else{
                                        expected = 2;
                                    }
                                    break;
                                }
                                case 2:{
                                    if(getBool()){
                                        parameters["g1_x"] = P.g1_x;
                                        parameters["g1_y"] = getBool()?
                                        boost::lexical_cast<std::string>(boost::multiprecision::cpp_int(P.g1_y) + 1):
                                        boost::lexical_cast<std::string>(boost::multiprecision::cpp_int(P.g1_y) - 1);
                                    }else{
                                        parameters["g1_x"] = getBool()?
                                        boost::lexical_cast<std::string>(boost::multiprecision::cpp_int(P.g1_x) + 1):
                                        boost::lexical_cast<std::string>(boost::multiprecision::cpp_int(P.g1_x) - 1);
                                        parameters["g1_y"] = P.g1_y;
                                    }
                                    expected = 3;
                                    break;
                                }
                                case 3:{
                                    parameters["g1_x"] = GET_OR_BIGNUM(P.g1_x);
                                    parameters["g1_y"] = GET_OR_BIGNUM(P.g1_y);
                                    expected = 0;
                                }
                            }
                        }else{
                            const auto P = Pool_CurveBLSG1.Get();
                            parameters["g1_x"] = P.g1_x;
                            parameters["g1_y"] = P.g1_y;
                        }
                    }
                    parameters["expected"] = expected;
                    parameters["compressed"] = compressed;
                    cryptofuzz::operation::BLS_Compress_G1 op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("BLS_Decompress_G2"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1000);
                    parameters["curveType"] = CF_ECC_CURVE("BLS12_381");
                    if(getBool() && Pool_CurveBLSG1.Have() == true){
                        const auto P = Pool_CurveBLSG1.Get();
                        parameters["g1_x"] = P.g1_x;
                        parameters["g1_y"] = P.g1_y;
                    }else{
                        parameters["g1_x"] = getSeedBignum();
                        parameters["g1_y"] = getSeedBignum();
                    }
                    cryptofuzz::operation::BLS_Decompress_G2 op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("BLS_Compress_G2"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1000);
                    parameters["curveType"] = CF_ECC_CURVE("BLS12_381");
                    uint32_t expected = 0;
                    std::string compressed_x = "";
                    std::string compressed_y = "";
                    if(Pool_CurveBLSG2.Have() == false){
                        parameters["g2_v"] = getSeedBignum();
                        parameters["g2_w"] = getSeedBignum();
                        parameters["g2_x"] = getSeedBignum();
                        parameters["g2_y"] = getSeedBignum();
                        expected = 0;
                    }else{
                        if(Pool_CurveBLSG2_Compress.Have() == true){
                            const auto P = Pool_CurveBLSG2_Compress.Get();
                            compressed_x = P.compress_x;
                            compressed_y = P.compress_y;
                            parameters["g2_v"] = P.g2_v;
                            parameters["g2_w"] = P.g2_w;
                            parameters["g2_x"] = P.g2_x;
                            parameters["g2_y"] = P.g2_y;
                            switch(PRNG() % 3){
                                case 0:{
                                    parameters["g2_v"] = P.g2_v;
                                    parameters["g2_w"] = P.g2_w;
                                    parameters["g2_x"] = P.g2_x;
                                    parameters["g2_y"] = P.g2_y;
                                    expected = 1;
                                    break;
                                }
                                case 1:{
                                    parameters["g2_v"] = P.g2_v;
                                    parameters["g2_w"] = P.g2_w;
                                    parameters["g2_x"] = P.g2_y;
                                    parameters["g2_y"] = P.g2_x;
                                    if(P.g2_y == P.g2_x){
                                        expected = 1;
                                    }else{
                                        expected = 2;
                                    }
                                    break;
                                }
                                case 2:{
                                    parameters["g2_v"] = GET_OR_BIGNUM(P.g2_v);
                                    parameters["g2_w"] = GET_OR_BIGNUM(P.g2_w);
                                    parameters["g2_x"] = GET_OR_BIGNUM(P.g2_x);
                                    parameters["g2_y"] = GET_OR_BIGNUM(P.g2_y);
                                    expected = 0;
                                    break;
                                }
                            }
                        }else{
                            const auto P = Pool_CurveBLSG2.Get();
                            parameters["g2_v"] = GET_OR_BIGNUM(P.g2_v);
                            parameters["g2_w"] = GET_OR_BIGNUM(P.g2_w);
                            parameters["g2_x"] = GET_OR_BIGNUM(P.g2_x);
                            parameters["g2_y"] = GET_OR_BIGNUM(P.g2_y);
                        }
                    
                    }
                    parameters["expected"] = expected;
                    parameters["compressed_x"] = compressed_x;
                    parameters["compressed_y"] = compressed_y;
                    cryptofuzz::operation::BLS_Compress_G2 op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("BLS_HashToG1"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1000);
                    parameters["curveType"] = CF_ECC_CURVE("BLS12_381");
                    parameters["cleartext"] = getSeedClearText(PRNG() % 1024);
                    // parameters["dest"] = getBool() ? getSeedClearText(PRNG() % 255) : get_BLS_predefined_DST();
                    parameters["dest"] = get_BLS_predefined_DST();
                    parameters["aug"] = getSeedClearText(PRNG() % 1024);

                    cryptofuzz::operation::BLS_HashToG1 op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("BLS_HashToG2"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1000);
                    parameters["curveType"] = CF_ECC_CURVE("BLS12_381");
                    parameters["cleartext"] = getSeedClearText(PRNG() % 1024);
                    // parameters["dest"] = getBool() ? getSeedClearText(PRNG() % 512) : get_BLS_predefined_DST();
                    parameters["dest"] = get_BLS_predefined_DST();
                    parameters["aug"] = getSeedClearText(PRNG() % 1024);

                    cryptofuzz::operation::BLS_HashToG2 op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("BLS_Pairing"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1000);
                    parameters["curveType"] = CF_ECC_CURVE("BLS12_381");

                    // parameters["dest"] = getBool() ? getSeedClearText(PRNG() % 512) : get_BLS_predefined_DST();
                    parameters["dest"] = get_BLS_predefined_DST();

                    nlohmann::json components = nlohmann::json::array();

                    const auto numComponents = PRNG() % 16;

                    for (size_t i = 0; i < numComponents; i++) {
                        nlohmann::json component;

                        if ( Pool_CurveBLSSignature.Have() == true ) {
                            const auto P = Pool_CurveBLSSignature.Get();

                            component["msg"] = P.cleartext;
                            parameters["dest"] = P.dest;
                            component["aug"] = P.aug;
                            component["pub_x"] = P.pub_x;
                            component["pub_y"] = P.pub_y;
                            component["sig_v"] = P.sig_v;
                            component["sig_w"] = P.sig_w;
                            component["sig_x"] = P.sig_x;
                            component["sig_y"] = P.sig_y;
                        } else {
                            if (Pool_CurveBLSG2.Have() == true ) {
                                const auto P = Pool_CurveBLSG2.Get();
                                component["sig_v"] = P.g2_v;
                                component["sig_w"] = P.g2_w;
                                component["sig_x"] = P.g2_x;
                                component["sig_y"] = P.g2_y;
                            } else {
                                component["sig_v"] = getSeedBignum();
                                component["sig_w"] = getSeedBignum();
                                component["sig_x"] = getSeedBignum();
                                component["sig_y"] = getSeedBignum();
                            }

                            if ( Pool_CurveKeypair.Have() ) {
                                const auto P = Pool_CurveKeypair.Get();
                                component["pub_x"] = P.pub_x;
                                component["pub_y"] = P.pub_y;
                            } else {
                                component["pub_x"] = getSeedBignum();
                                component["pub_y"] = getSeedBignum();
                            }

                            component["msg"] = getSeedClearText(PRNG() % 1024);
                            component["aug"] = getSeedClearText(PRNG() % 1024);
                        }

                        components.push_back(component);
                    }

                    parameters["components"] = components;

                    cryptofuzz::operation::BLS_Pairing op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("BLS_G1_Add"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1000);
                    parameters["curveType"] = CF_ECC_CURVE("BLS12_381");
                    if(Pool_CurveBLSG1.Have() == false){
                        parameters["a_x"] = getSeedBignum();
                        parameters["a_y"] = getSeedBignum();
                        parameters["b_x"] = getSeedBignum();
                        parameters["b_y"] = getSeedBignum();
                    }else{
                        const auto P1 = Pool_CurveBLSG1.Get();
                        const auto P2 = Pool_CurveBLSG1.Get();
                        parameters["a_x"] = P1.g1_x;
                        parameters["a_y"] = P1.g1_y;
                        parameters["b_x"] = P2.g1_x;
                        parameters["b_y"] = P2.g1_y;

                    }
                    cryptofuzz::operation::BLS_G1_Add op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("BLS_G1_Mul"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1000);
                    parameters["curveType"] = CF_ECC_CURVE("BLS12_381");
                    if(Pool_CurveBLSG1.Have() == false){
                        parameters["a_x"] = getSeedBignum();
                        parameters["a_y"] = getSeedBignum();
                    }else{
                        const auto P = Pool_CurveBLSG1.Get();
                        parameters["a_x"] = P.g1_x;
                        parameters["a_y"] = P.g1_y;
                    }
                    parameters["b"] = getSeedBignum();

                    cryptofuzz::operation::BLS_G1_Mul op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("BLS_G1_IsEq"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1000);
                    parameters["curveType"] = CF_ECC_CURVE("BLS12_381");

                    if (Pool_CurveBLSG1.Have() == true ) {
                        const auto P = Pool_CurveBLSG1.Get();
                        parameters["a_x"] = P.g1_x;
                        parameters["a_y"] = P.g1_y;
                    } else {
                        parameters["a_x"] = getSeedBignum();
                        parameters["a_y"] = getSeedBignum();
                    }

                    if ( Pool_CurveBLSG1.Have() == true ) {
                        const auto P = Pool_CurveBLSG1.Get();
                        parameters["b_x"] = P.g1_x;
                        parameters["b_y"] = P.g1_y;
                    } else {
                        parameters["b_x"] = getSeedBignum();
                        parameters["b_y"] = getSeedBignum();
                    }

                    cryptofuzz::operation::BLS_G1_IsEq op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("BLS_G1_Neg"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1000);
                    parameters["curveType"] = CF_ECC_CURVE("BLS12_381");

                    if ( Pool_CurveBLSG1.Have() == true ) {
                        const auto P = Pool_CurveBLSG1.Get();
                        parameters["a_x"] = P.g1_x;
                        parameters["a_y"] = P.g1_y;
                    } else {
                        parameters["a_x"] = getSeedBignum();
                        parameters["a_y"] = getSeedBignum();
                    }

                    cryptofuzz::operation::BLS_G1_Neg op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("BLS_G2_Add"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1000);
                    parameters["curveType"] = CF_ECC_CURVE("BLS12_381");
                    if(Pool_CurveBLSG2.Have() == false){
                        parameters["a_v"] = getSeedBignum();
                        parameters["a_w"] = getSeedBignum();
                        parameters["a_x"] = getSeedBignum();
                        parameters["a_y"] = getSeedBignum();
                        parameters["b_v"] = getSeedBignum();
                        parameters["b_w"] = getSeedBignum();
                        parameters["b_x"] = getSeedBignum();
                        parameters["b_y"] = getSeedBignum();

                    }else{
                        const auto P1 = Pool_CurveBLSG2.Get();
                        const auto P2 = Pool_CurveBLSG2.Get();
                        parameters["a_v"] = P1.g2_v;
                        parameters["a_w"] = P1.g2_w;
                        parameters["a_x"] = P1.g2_x;
                        parameters["a_y"] = P1.g2_y;
                        parameters["b_v"] = P2.g2_v;
                        parameters["b_w"] = P2.g2_w;
                        parameters["b_x"] = P2.g2_x;
                        parameters["b_y"] = P2.g2_y;
                    }
                    cryptofuzz::operation::BLS_G2_Add op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("BLS_G2_Mul"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1000);
                    parameters["curveType"] = CF_ECC_CURVE("BLS12_381");
                    if(Pool_CurveBLSG2.Have() == false){
                        parameters["a_v"] = getSeedBignum();
                        parameters["a_w"] = getSeedBignum();
                        parameters["a_x"] = getSeedBignum();
                        parameters["a_y"] = getSeedBignum();
                    }else{
                        const auto P = Pool_CurveBLSG2.Get();
                        parameters["a_v"] = P.g2_v;
                        parameters["a_w"] = P.g2_w;
                        parameters["a_x"] = P.g2_x;
                        parameters["a_y"] = P.g2_y;
                    }

                    parameters["b"] = getSeedBignum();

                    cryptofuzz::operation::BLS_G2_Mul op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("BLS_G2_IsEq"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1000);
                    parameters["curveType"] = CF_ECC_CURVE("BLS12_381");

                    if (Pool_CurveBLSG2.Have() == true ) {
                        const auto P = Pool_CurveBLSG2.Get();
                        parameters["a_v"] = P.g2_v;
                        parameters["a_w"] = P.g2_w;
                        parameters["a_x"] = P.g2_x;
                        parameters["a_y"] = P.g2_y;
                    } else {
                        parameters["a_v"] = getSeedBignum();
                        parameters["a_w"] = getSeedBignum();
                        parameters["a_x"] = getSeedBignum();
                        parameters["a_y"] = getSeedBignum();
                    }

                    if ( Pool_CurveBLSG2.Have() == true ) {
                        const auto P = Pool_CurveBLSG2.Get();
                        parameters["b_v"] = P.g2_v;
                        parameters["b_w"] = P.g2_w;
                        parameters["b_x"] = P.g2_x;
                        parameters["b_y"] = P.g2_y;
                    } else {
                        parameters["b_v"] = getSeedBignum();
                        parameters["b_w"] = getSeedBignum();
                        parameters["b_x"] = getSeedBignum();
                        parameters["b_y"] = getSeedBignum();
                    }

                    cryptofuzz::operation::BLS_G2_IsEq op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("BLS_G2_Neg"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1000);
                    parameters["curveType"] = CF_ECC_CURVE("BLS12_381");

                    if ( Pool_CurveBLSG2.Have() == true ) {
                        const auto P = Pool_CurveBLSG2.Get();
                        parameters["a_v"] = P.g2_v;
                        parameters["a_w"] = P.g2_w;
                        parameters["a_x"] = P.g2_x;
                        parameters["a_y"] = P.g2_y;
                    } else {
                        parameters["a_v"] = getSeedBignum();
                        parameters["a_w"] = getSeedBignum();
                        parameters["a_x"] = getSeedBignum();
                        parameters["a_y"] = getSeedBignum();
                    }

                    cryptofuzz::operation::BLS_G2_Neg op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("SR25519_Verify"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1024);

                    parameters["signature"]["pub"] = getSeedBignum();

                    parameters["signature"]["signature"][0] = getSeedBignum();
                    parameters["signature"]["signature"][1] = getSeedBignum();

                    parameters["cleartext"] = cryptofuzz::util::DecToHex(getSeedBignum(true), (PRNG() % 64) * 2);

                    cryptofuzz::operation::SR25519_Verify op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            default:
                goto end;
        }
#undef GET_OR_BIGNUM

        fuzzing::datasource::Datasource dsOut(nullptr, 0);

        /* Operation ID */
        dsOut.Put<uint64_t>(operation);

        dsOut.PutData(dsOut2.GetOut());

        /* Modifier */
        if ( reuseModifier == true && !modifier.empty() ) {
            dsOut.PutData(modifier);
        } else {
            size_t modifierMaxSize = maxSize / 10;
            if ( modifierMaxSize == 0 ) {
                modifierMaxSize = 1;
            }

            dsOut.PutData(getBufferBin(PRNG() % modifierMaxSize));
        }

        /* Module ID */
        dsOut.Put<uint64_t>( ModuleLUT[ PRNG() % (sizeof(ModuleLUT) / sizeof(ModuleLUT[0])) ].id );

        /* Terminator */
        dsOut.Put<bool>(false);

        const auto insertSize = dsOut.GetOut().size();
        out_size = insertSize;
        if ( insertSize <= maxSize ) {
            memcpy(data, dsOut.GetOut().data(), insertSize);

            /* Fall through to LLVMFuzzerMutate */
        }
    }

end:
    return out_size;
}
