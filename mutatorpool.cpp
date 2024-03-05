#include "mutatorpool.h"

uint32_t PRNG(void);

template <class T, size_t Size>
void MutatorPool<T, Size>::Set(const T& v) {
    pool[setpos] = v;
    init[setpos] = true;
    setpos++;
    if(setpos >= Size){
        setpos = 0;
    }
    set = true;
}

template <class T, size_t Size>
bool MutatorPool<T, Size>::Have(void) const {
	return set;
}

template <class T, size_t Size>
T MutatorPool<T, Size>::Get(void) {
    int nextpos = (getpos >= Size-1)?0:getpos + 1;
    if(init[nextpos]){
        getpos = nextpos;
    }
    return pool[getpos];
}

MutatorPool<CurvePrivkey_Pair, cryptofuzz::config::kMutatorPoolSize> Pool_CurvePrivkey;
MutatorPool<CurveKeypair_Pair, cryptofuzz::config::kMutatorPoolSize> Pool_CurveKeypair;
MutatorPool<CurveECDSASignature_Pair, cryptofuzz::config::kMutatorPoolSize> Pool_CurveECDSASignature;
MutatorPool<CurveECC_Point_Pair, cryptofuzz::config::kMutatorPoolSize> Pool_CurveECC_Point;
MutatorPool<CurveBLSSignature_Pair, cryptofuzz::config::kMutatorPoolSize> Pool_CurveBLSSignature;
MutatorPool<CurveBLSG1_Pair, cryptofuzz::config::kMutatorPoolSize> Pool_CurveBLSG1;
MutatorPool<CurveBLSG2_Pair, cryptofuzz::config::kMutatorPoolSize> Pool_CurveBLSG2;
MutatorPool<SingleString, cryptofuzz::config::kMutatorPoolSize> Pool_Bignum;
MutatorPool<SingleString, cryptofuzz::config::kMutatorPoolSize> Pool_DH_PrivateKey;
MutatorPool<SingleString, cryptofuzz::config::kMutatorPoolSize> Pool_DH_PublicKey;
MutatorPool<CurveBLSG1_Compress, cryptofuzz::config::kMutatorPoolSize> Pool_CurveBLSG1_Compress;
MutatorPool<CurveBLSG2_Compress, cryptofuzz::config::kMutatorPoolSize> Pool_CurveBLSG2_Compress;

MutatorPool<EncryptionKey, cryptofuzz::config::kMutatorPoolSize> Pool_BlockCipherEncrypt;

std::map<uint64_t, MutatorPool<CurveECC_Point_Pair, cryptofuzz::config::kMutatorPoolSize>> CurveToPool;
std::mutex mt1, mt2, mt3, mt4, mt5;
std::FILE *fp;
template class MutatorPool<CurvePrivkey_Pair, cryptofuzz::config::kMutatorPoolSize>;
template class MutatorPool<CurveKeypair_Pair, cryptofuzz::config::kMutatorPoolSize>;
template class MutatorPool<CurveECDSASignature_Pair, cryptofuzz::config::kMutatorPoolSize>;
template class MutatorPool<CurveECC_Point_Pair, cryptofuzz::config::kMutatorPoolSize>;
template class MutatorPool<CurveBLSSignature_Pair, cryptofuzz::config::kMutatorPoolSize>;
template class MutatorPool<CurveBLSG1_Pair, cryptofuzz::config::kMutatorPoolSize>;
template class MutatorPool<CurveBLSG2_Pair, cryptofuzz::config::kMutatorPoolSize>;
template class MutatorPool<SingleString, cryptofuzz::config::kMutatorPoolSize>;
template class MutatorPool<CurveBLSG1_Compress, cryptofuzz::config::kMutatorPoolSize>;
template class MutatorPool<CurveBLSG2_Compress, cryptofuzz::config::kMutatorPoolSize>;
template class MutatorPool<EncryptionKey, cryptofuzz::config::kMutatorPoolSize>;