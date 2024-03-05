#pragma once

#include <array>
#include <string>
#include <cstdint>
#include <map>
#include <mutex>

#include "config.h"

template <class T, size_t Size>
class MutatorPool {
	private:
		std::array<T, Size> pool = {};
        std::array<bool, Size> init = {};
		bool set = false;
        unsigned long setpos = 0;
        unsigned long getpos = 0;
	public:
		void Set(const T& v);
		bool Have(void) const;
		T Get(void);
};

struct SingleString{
    std::string str;
};

struct CurvePrivkey_Pair{
    uint64_t curveID;
    std::string priv;
};
extern MutatorPool<CurvePrivkey_Pair, cryptofuzz::config::kMutatorPoolSize> Pool_CurvePrivkey;

struct CurveKeypair_Pair{
    uint64_t curveID;
    std::string privkey;
    std::string pub_x;
    std::string pub_y;
};
extern MutatorPool<CurveKeypair_Pair, cryptofuzz::config::kMutatorPoolSize> Pool_CurveKeypair;

struct CurveECDSASignature_Pair{
    uint64_t curveID;
    uint64_t digestID;
    std::string cleartext;
    std::string pub_x;
    std::string pub_y;
    std::string sig_r;
    std::string sig_y;
};
extern MutatorPool<CurveECDSASignature_Pair, cryptofuzz::config::kMutatorPoolSize> Pool_CurveECDSASignature;

struct CurveECC_Point_Pair{
    uint64_t curveID;
    std::string x;
    std::string y;
};
extern MutatorPool<CurveECC_Point_Pair, cryptofuzz::config::kMutatorPoolSize> Pool_CurveECC_Point;
extern MutatorPool<SingleString, cryptofuzz::config::kMutatorPoolSize> Pool_Bignum;

struct CurveBLSSignature_Pair{
    uint64_t curveID;
    bool hashOrPoint;
    std::string point_v;
    std::string point_w;
    std::string point_x;
    std::string point_y;
    std::string cleartext;
    std::string dest;
    std::string aug;
    std::string pub_x;
    std::string pub_y;
    std::string sig_v;
    std::string sig_w;
    std::string sig_x;
    std::string sig_y;
};
extern MutatorPool<CurveBLSSignature_Pair, cryptofuzz::config::kMutatorPoolSize> Pool_CurveBLSSignature;

struct CurveBLSG1_Pair{
    uint64_t curveID;
    std::string g1_x;
    std::string g1_y;
};
extern MutatorPool<CurveBLSG1_Pair, cryptofuzz::config::kMutatorPoolSize> Pool_CurveBLSG1;


struct CurveBLSG2_Pair{
    uint64_t curveID;
    std::string g2_v;
    std::string g2_w;
    std::string g2_x;
    std::string g2_y;
};
extern MutatorPool<CurveBLSG2_Pair, cryptofuzz::config::kMutatorPoolSize> Pool_CurveBLSG2;
extern MutatorPool<SingleString, cryptofuzz::config::kMutatorPoolSize> Pool_DH_PrivateKey;
extern MutatorPool<SingleString, cryptofuzz::config::kMutatorPoolSize> Pool_DH_PublicKey;

struct CurveBLSG1_Compress{
    uint64_t curveID;
    std::string g1_x;
    std::string g1_y;
    std::string compress;
};

struct CurveBLSG2_Compress{
    uint64_t curveID;
    std::string g2_v;
    std::string g2_w;
    std::string g2_x;
    std::string g2_y;
    std::string compress_x;
    std::string compress_y;
};

struct EncryptionKey{
    std::string key;
    std::string iv;
    std::string plaintext;
    uint64_t cipherID;
    uint64_t cleartextSize;
    std::string ciphertext;
};

extern MutatorPool<CurveBLSG1_Compress, cryptofuzz::config::kMutatorPoolSize> Pool_CurveBLSG1_Compress;
extern MutatorPool<CurveBLSG2_Compress, cryptofuzz::config::kMutatorPoolSize> Pool_CurveBLSG2_Compress;

extern MutatorPool<EncryptionKey, cryptofuzz::config::kMutatorPoolSize> Pool_BlockCipherEncrypt;

extern std::map<uint64_t, MutatorPool<CurveECC_Point_Pair, cryptofuzz::config::kMutatorPoolSize>> CurveToPool;

extern std::mutex mt1, mt2, mt3, mt4, mt5;
extern std::FILE *fp;