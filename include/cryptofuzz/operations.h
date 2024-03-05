#pragma once

#include <cryptofuzz/components.h>
#include <cryptofuzz/repository.h>
#include <fuzzing/datasource/datasource.hpp>
#include "../../third_party/json/json.hpp"
#include <map>

using namespace std;

namespace cryptofuzz {
namespace operation {

using fuzzing::datasource::Datasource;

class Operation {
    public:
        component::Modifier modifier;

        Operation(component::Modifier modifier) :
            modifier(std::move(modifier))
        { }

        Operation(nlohmann::json modifier) :
            modifier(modifier)
        { }

        virtual std::string Name(void) const = 0;
        virtual std::string ToString(void) const = 0;
        virtual nlohmann::json ToJSON(void) const = 0;
        virtual std::string GetAlgorithmString(void) const {
            return "(no algorithm)";
        }
};

static map <uint64_t, bool> Digests = {
            {CF_DIGEST("ADLER32"), false},
            {CF_DIGEST("BLAKE2B160"), false},
            {CF_DIGEST("BLAKE2B256"), false},
            {CF_DIGEST("BLAKE2B384"), false},
            {CF_DIGEST("BLAKE2B512"), false},
            {CF_DIGEST("BLAKE2B_MAC"), false},
            {CF_DIGEST("BLAKE2S128"), false},
            {CF_DIGEST("BLAKE2S160"), false},
            {CF_DIGEST("BLAKE2S224"), false},
            {CF_DIGEST("BLAKE2S256"), false},
            {CF_DIGEST("BLAKE2S_MAC"), false},
            {CF_DIGEST("BLAKE3"), false},
            {CF_DIGEST("CITYHASH128"), false},
            {CF_DIGEST("CITYHASH128SEED16"), false},
            {CF_DIGEST("CITYHASH32"), false},
            {CF_DIGEST("CITYHASH64"), false},
            {CF_DIGEST("CITYHASH64SEED16"), false},
            {CF_DIGEST("CITYHASH64SEED8"), false},
            {CF_DIGEST("CITYHASHCRC128"), false},
            {CF_DIGEST("CITYHASHCRC128SEED16"), false},
            {CF_DIGEST("CITYHASHCRC256"), false},
            {CF_DIGEST("CRC32"), false},
            {CF_DIGEST("CRC32-RFC1510"), false},
            {CF_DIGEST("CRC32-RFC2440"), false},
            {CF_DIGEST("GOST-28147-89"), false},
            {CF_DIGEST("GOST-R-34.11-94"), false},
            {CF_DIGEST("GOST-R-34.11-94-NO-CRYPTOPRO"), false},
            {CF_DIGEST("GROESTL_224"), false},
            {CF_DIGEST("GROESTL_256"), false},
            {CF_DIGEST("GROESTL_384"), false},
            {CF_DIGEST("GROESTL_512"), false},
            {CF_DIGEST("JH_224"), false},
            {CF_DIGEST("JH_256"), false},
            {CF_DIGEST("JH_384"), false},
            {CF_DIGEST("JH_512"), false},
            {CF_DIGEST("KECCAK_224"), false},
            {CF_DIGEST("KECCAK_256"), false},
            {CF_DIGEST("KECCAK_384"), false},
            {CF_DIGEST("KECCAK_512"), false},
            {CF_DIGEST("MD2"), false},
            {CF_DIGEST("MD4"), false},
            {CF_DIGEST("MD5"), false},
            {CF_DIGEST("MD5_SHA1"), false},
            {CF_DIGEST("MDC2"), false},
            {CF_DIGEST("NULL"), false},
            {CF_DIGEST("PANAMA"), false},
            {CF_DIGEST("RIPEMD128"), false},
            {CF_DIGEST("RIPEMD160"), false},
            {CF_DIGEST("RIPEMD256"), false},
            {CF_DIGEST("RIPEMD320"), false},
            {CF_DIGEST("SHA1"), false},
            {CF_DIGEST("SHA224"), false},
            {CF_DIGEST("SHA256"), false},
            {CF_DIGEST("SHA3-224"), false},
            {CF_DIGEST("SHA3-256"), false},
            {CF_DIGEST("SHA3-384"), false},
            {CF_DIGEST("SHA3-512"), false},
            {CF_DIGEST("SHA384"), false},
            {CF_DIGEST("SHA512"), false},
            {CF_DIGEST("SHA512-224"), false},
            {CF_DIGEST("SHA512-256"), false},
            {CF_DIGEST("SHAKE128"), false},
            {CF_DIGEST("SHAKE256"), false},
            {CF_DIGEST("SIPHASH128"), false},
            {CF_DIGEST("SIPHASH64"), false},
            {CF_DIGEST("SKEIN_1024"), false},
            {CF_DIGEST("SKEIN_256"), false},
            {CF_DIGEST("SKEIN_512"), false},
            {CF_DIGEST("SM3"), false},
            {CF_DIGEST("STREEBOG-256"), false},
            {CF_DIGEST("STREEBOG-512"), false},
            {CF_DIGEST("T1HA-128"), false},
            {CF_DIGEST("T1HA-64"), false},
            {CF_DIGEST("TIGER"), false},
            {CF_DIGEST("WHIRLPOOL"), false},
            {CF_DIGEST("XXHASH32"), false},
            {CF_DIGEST("XXHASH64"), false},
                  
};

static map <uint64_t, bool> Curves = {
    {CF_ECC_CURVE("secp112r2"), false},
            {CF_ECC_CURVE("secp256r1"), false},
            {CF_ECC_CURVE("secp256k1"), false},
            {CF_ECC_CURVE("brainpool160r1"), false},
            {CF_ECC_CURVE("brainpool160t1"), false},
            {CF_ECC_CURVE("sect131r2"), false},
            {CF_ECC_CURVE("sect131r1"), false},
            {CF_ECC_CURVE("secp160r2"), false},
            {CF_ECC_CURVE("secp160k1"), false},
            {CF_ECC_CURVE("wap_wsg_idm_ecid_wtls9"), false},
            {CF_ECC_CURVE("secp160r1"), false},
            {CF_ECC_CURVE("wap_wsg_idm_ecid_wtls7"), false},
            {CF_ECC_CURVE("brainpool320r1"), false},
            {CF_ECC_CURVE("brainpool320t1"), false},
            {CF_ECC_CURVE("sect571k1"), false},
            {CF_ECC_CURVE("brainpool384r1"), false},
            {CF_ECC_CURVE("brainpool384t1"), false},
            {CF_ECC_CURVE("sect239k1"), false},
            {CF_ECC_CURVE("brainpool224r1"), false},
            {CF_ECC_CURVE("brainpool224t1"), false},
            {CF_ECC_CURVE("secp224r1"), false},
            {CF_ECC_CURVE("wap_wsg_idm_ecid_wtls12"), false},
            {CF_ECC_CURVE("secp224k1"), false},
            {CF_ECC_CURVE("sect409k1"), false},
            {CF_ECC_CURVE("secp128r1"), false},
            {CF_ECC_CURVE("sect233k1"), false},
            {CF_ECC_CURVE("wap_wsg_idm_ecid_wtls10"), false},
            {CF_ECC_CURVE("sect571r1"), false},
            {CF_ECC_CURVE("sect283k1"), false},
            {CF_ECC_CURVE("secp384r1"), false},
            {CF_ECC_CURVE("secp112r1"), false},
            {CF_ECC_CURVE("wap_wsg_idm_ecid_wtls6"), false},
            {CF_ECC_CURVE("brainpool192r1"), false},
            {CF_ECC_CURVE("brainpool192t1"), false},
            {CF_ECC_CURVE("wap_wsg_idm_ecid_wtls1"), false},
            {CF_ECC_CURVE("sect113r1"), false},
            {CF_ECC_CURVE("wap_wsg_idm_ecid_wtls4"), false},
            {CF_ECC_CURVE("sect113r2"), false},
            {CF_ECC_CURVE("wap_wsg_idm_ecid_wtls8"), false},
            {CF_ECC_CURVE("sect163r1"), false},
            {CF_ECC_CURVE("wap_wsg_idm_ecid_wtls5"), false},
            {CF_ECC_CURVE("sect163k1"), false},
            {CF_ECC_CURVE("wap_wsg_idm_ecid_wtls3"), false},
            {CF_ECC_CURVE("sect163r2"), false},
            {CF_ECC_CURVE("secp192k1"), false},
            {CF_ECC_CURVE("secp192r1"), false},
            {CF_ECC_CURVE("sect193r1"), false},
            {CF_ECC_CURVE("sect193r2"), false},
            {CF_ECC_CURVE("sect409r1"), false},
            {CF_ECC_CURVE("secp521r1"), false},
            {CF_ECC_CURVE("sect233r1"), false},
            {CF_ECC_CURVE("wap_wsg_idm_ecid_wtls11"), false},
            {CF_ECC_CURVE("brainpool256r1"), false},
            {CF_ECC_CURVE("brainpool256t1"), false},
            {CF_ECC_CURVE("sect283r1"), false},
            {CF_ECC_CURVE("secp128r2"), false},
            {CF_ECC_CURVE("brainpool512r1"), false},
            {CF_ECC_CURVE("brainpool512t1"), false},
            {CF_ECC_CURVE("frp256v1"), false},
            {CF_ECC_CURVE("ed25519"), false},
            {CF_ECC_CURVE("ed448"), false},
            {CF_ECC_CURVE("BLS12_381"), false},
            {CF_ECC_CURVE("gost_256A"), false},
            {CF_ECC_CURVE("gost_512A"), false},
            {CF_ECC_CURVE("gostr3410_2001_cryptopro_a"), false},
            {CF_ECC_CURVE("gostr3410_2001_cryptopro_b"), false},
            {CF_ECC_CURVE("gostr3410_2001_cryptopro_c"), false},
            {CF_ECC_CURVE("gostr3410_2001_cryptopro_xcha"), false},
            {CF_ECC_CURVE("gostr3410_2001_cryptopro_xchb"), false},
            {CF_ECC_CURVE("gostr3410_2001_test"), false},
            {CF_ECC_CURVE("ipsec3"), false},
            {CF_ECC_CURVE("ipsec4"), false},
            {CF_ECC_CURVE("numsp256t1"), false},
            {CF_ECC_CURVE("numsp384t1"), false},
            {CF_ECC_CURVE("numsp512t1"), false},
            {CF_ECC_CURVE("sm2p256v1"), false},
            {CF_ECC_CURVE("tc26_gost_3410_12_256_a"), false},
            {CF_ECC_CURVE("tc26_gost_3410_12_256_b"), false},
            {CF_ECC_CURVE("tc26_gost_3410_12_256_c"), false},
            {CF_ECC_CURVE("tc26_gost_3410_12_256_d"), false},
            {CF_ECC_CURVE("tc26_gost_3410_12_512_a"), false},
            {CF_ECC_CURVE("tc26_gost_3410_12_512_b"), false},
            {CF_ECC_CURVE("tc26_gost_3410_12_512_c"), false},
            {CF_ECC_CURVE("tc26_gost_3410_12_512_test"), false},
            {CF_ECC_CURVE("x25519"), false},
            {CF_ECC_CURVE("x448"), false},
            {CF_ECC_CURVE("x962_c2pnb163v1"), false},
            {CF_ECC_CURVE("x962_c2pnb163v2"), false},
            {CF_ECC_CURVE("x962_c2pnb163v3"), false},
            {CF_ECC_CURVE("x962_c2pnb176v1"), false},
            {CF_ECC_CURVE("x962_c2pnb208w1"), false},
            {CF_ECC_CURVE("x962_c2pnb272w1"), false},
            {CF_ECC_CURVE("x962_c2pnb304w1"), false},
            {CF_ECC_CURVE("x962_c2pnb368w1"), false},
            {CF_ECC_CURVE("x962_c2tnb191v1"), false},
            {CF_ECC_CURVE("x962_c2tnb191v2"), false},
            {CF_ECC_CURVE("x962_c2tnb191v3"), false},
            {CF_ECC_CURVE("x962_c2tnb239v1"), false},
            {CF_ECC_CURVE("x962_c2tnb239v2"), false},
            {CF_ECC_CURVE("x962_c2tnb239v3"), false},
            {CF_ECC_CURVE("x962_c2tnb359v1"), false},
            {CF_ECC_CURVE("x962_c2tnb431r1"), false},
            {CF_ECC_CURVE("x962_p192v1"), false},
            {CF_ECC_CURVE("x962_p192v2"), false},
            {CF_ECC_CURVE("x962_p192v3"), false},
            {CF_ECC_CURVE("x962_p239v1"), false},
            {CF_ECC_CURVE("x962_p239v2"), false},
            {CF_ECC_CURVE("x962_p239v3"), false},
            {CF_ECC_CURVE("x962_p256v1"), false},
            {CF_ECC_CURVE("BN256"), false},
            {CF_ECC_CURVE("BN384"), false},
            {CF_ECC_CURVE("BN512"), false},
            
};

static map <uint64_t, bool> Calcs = {
            {CF_CALCOP("Abs(A)"), false},
            {CF_CALCOP("Add(A,B)"), false},
            {CF_CALCOP("AddMod(A,B,C)"), false},
            {CF_CALCOP("And(A,B)"), false},
            {CF_CALCOP("Bit(A,B)"), false},
            {CF_CALCOP("ClearBit(A,B)"), false},
            {CF_CALCOP("Cmp(A,B)"), false},
            {CF_CALCOP("CmpAbs(A,B)"), false},
            {CF_CALCOP("CondSet(A,B)"), false},
            {CF_CALCOP("Div(A,B)"), false},
            {CF_CALCOP("Exp(A,B)"), false},
            {CF_CALCOP("Exp2(A)"), false},
            {CF_CALCOP("ExpMod(A,B,C)"), false},
            {CF_CALCOP("GCD(A,B)"), false},
            {CF_CALCOP("InvMod(A,B)"), false},
            {CF_CALCOP("IsCoprime(A,B)"), false},
            {CF_CALCOP("IsEq(A,B)"), false},
            {CF_CALCOP("IsEven(A)"), false},
            {CF_CALCOP("IsGt(A,B)"), false},
            {CF_CALCOP("IsGte(A,B)"), false},
            {CF_CALCOP("IsLt(A,B)"), false},
            {CF_CALCOP("IsLte(A,B)"), false},
            {CF_CALCOP("IsNeg(A)"), false},
            {CF_CALCOP("IsNotZero(A)"), false},
            {CF_CALCOP("IsOdd(A)"), false},
            {CF_CALCOP("IsOne(A)"), false},
            {CF_CALCOP("IsPow2(A)"), false},
            {CF_CALCOP("IsPrime(A)"), false},
            {CF_CALCOP("IsZero(A)"), false},
            {CF_CALCOP("Jacobi(A,B)"), false},
            {CF_CALCOP("LCM(A,B)"), false},
            {CF_CALCOP("LShift1(A)"), false},
            {CF_CALCOP("Log10(A)"), false},
            {CF_CALCOP("MSB(A)"), false},
            {CF_CALCOP("Mask(A,B)"), false},
            {CF_CALCOP("Max(A,B)"), false},
            {CF_CALCOP("Min(A,B)"), false},
            {CF_CALCOP("Mod(A,B)"), false},
            {CF_CALCOP("ModLShift(A,B,C)"), false},
            {CF_CALCOP("Mod_NIST_192(A)"), false},
            {CF_CALCOP("Mod_NIST_224(A)"), false},
            {CF_CALCOP("Mod_NIST_256(A)"), false},
            {CF_CALCOP("Mod_NIST_384(A)"), false},
            {CF_CALCOP("Mod_NIST_521(A)"), false},
            {CF_CALCOP("Mul(A,B)"), false},
            {CF_CALCOP("MulAdd(A,B,C)"), false},
            {CF_CALCOP("MulMod(A,B,C)"), false},
            {CF_CALCOP("Neg(A)"), false},
            {CF_CALCOP("Not(A)"), false},
            {CF_CALCOP("NumBits(A)"), false},
            {CF_CALCOP("NumLSZeroBits(A)"), false},
            {CF_CALCOP("Or(A,B)"), false},
            {CF_CALCOP("RShift(A,B)"), false},
            {CF_CALCOP("Rand()"), false},
            {CF_CALCOP("Ressol(A,B)"), false},
            {CF_CALCOP("Set(A)"), false},
            {CF_CALCOP("SetBit(A,B)"), false},
            {CF_CALCOP("Sqr(A)"), false},
            {CF_CALCOP("SqrMod(A,B)"), false},
            {CF_CALCOP("Sqrt(A)"), false},
            {CF_CALCOP("SqrtMod(A,B)"), false},
            {CF_CALCOP("Sub(A,B)"), false},
            {CF_CALCOP("SubMod(A,B,C)"), false},
            {CF_CALCOP("Xor(A,B)"), false},
            
};

static uint64_t getDigestType(Datasource& ds){
    const auto origin_digest = ds.Get<uint64_t>(0);
    auto new_digest = CF_DIGEST("SHA1");
    if(Digests.count(origin_digest) != 0){
        return origin_digest;
    }
    return new_digest;
}

static uint64_t getEccCurveType(Datasource& ds){
    const auto origin_ECCcurve = ds.Get<uint64_t>(0);
    auto new_ECCcurve = CF_ECC_CURVE("secp112r1");
    if(Curves.count(origin_ECCcurve) != 0){
        return origin_ECCcurve;
    }
    return new_ECCcurve;
}

static uint64_t getCalcOp(Datasource& ds){
    const auto origin_op = ds.Get<uint64_t>(0);
    auto new_Op = CF_DIGEST("SHA1");
    if(Calcs.count(origin_op) != 0){
        return origin_op;
    }
    return new_Op;
}

class Digest : public Operation {
    public:
        const component::Cleartext cleartext;
        const component::DigestType digestType;

        Digest(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            cleartext(ds),
            digestType(getDigestType(ds))
        { }

        Digest(nlohmann::json json) :
            Operation(json["modifier"]),
            cleartext(json["cleartext"]),
            digestType(json["digestType"])
        { }


        static size_t MaxOperations(void) { return 20; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        std::string GetAlgorithmString(void) const override {
            return repository::DigestToString(digestType.Get());
        }
        inline bool operator==(const Digest& rhs) const {
            return
                (cleartext == rhs.cleartext) &&
                (digestType == rhs.digestType) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            cleartext.Serialize(ds);
            digestType.Serialize(ds);
        }
};

class HMAC : public Operation {
    public:
        const component::Cleartext cleartext;
        const component::DigestType digestType;
        const component::SymmetricCipher cipher;

        HMAC(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            cleartext(ds),
            digestType(getDigestType(ds)),
            cipher(ds)
        { }
        HMAC(nlohmann::json json) :
            Operation(json["modifier"]),
            cleartext(json["cleartext"]),
            digestType(json["digestType"]),
            cipher(json["cipher"])
        { }

        static size_t MaxOperations(void) { return 20; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        std::string GetAlgorithmString(void) const override {
            return repository::DigestToString(digestType.Get());
        }
        inline bool operator==(const HMAC& rhs) const {
            return
                (cleartext == rhs.cleartext) &&
                (digestType == rhs.digestType) &&
                (cipher == rhs.cipher) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            cleartext.Serialize(ds);
            digestType.Serialize(ds);
            cipher.Serialize(ds);
        }
};

class SymmetricEncrypt : public Operation {
    public:
        const component::Cleartext cleartext;
        const component::SymmetricCipher cipher;
        const std::optional<component::AAD> aad;

        const uint64_t ciphertextSize;
        const std::optional<uint64_t> tagSize;

        SymmetricEncrypt(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            cleartext(ds),
            cipher(ds),
            aad(ds.Get<bool>() ? std::nullopt : std::make_optional<component::AAD>(ds)),
            ciphertextSize(ds.Get<uint64_t>() % (10*1024*1024)),
            tagSize( ds.Get<bool>() ?
                    std::nullopt :
                    std::make_optional<uint64_t>(ds.Get<uint64_t>() % (10*1024*1024)) )
        { }
        SymmetricEncrypt(nlohmann::json json) :
            Operation(json["modifier"]),
            cleartext(json["cleartext"]),
            cipher(json["cipher"]),
            aad(
                    json["aad_enabled"].get<bool>() ?
                        std::optional<component::AAD>(json["aad"]) :
                        std::optional<component::AAD>(std::nullopt)
            ),
            ciphertextSize(json["ciphertextSize"].get<uint64_t>()),
            tagSize(
                    json["tagSize_enabled"].get<bool>() ?
                        std::optional<uint64_t>(json["tagSize"].get<uint64_t>()) :
                        std::optional<uint64_t>(std::nullopt)
            )
        { }

        static size_t MaxOperations(void) { return 20; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        std::string GetAlgorithmString(void) const override {
            return repository::CipherToString(cipher.cipherType.Get());
        }
        inline bool operator==(const SymmetricEncrypt& rhs) const {
            return
                (cleartext == rhs.cleartext) &&
                (cipher == rhs.cipher) &&
                (aad == rhs.aad) &&
                (ciphertextSize == rhs.ciphertextSize) &&
                (tagSize == rhs.tagSize) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            cleartext.Serialize(ds);
            cipher.Serialize(ds);
            if ( aad == std::nullopt ) {
                ds.Put<bool>(true);
            } else {
                ds.Put<bool>(false);
                aad->Serialize(ds);
            }
            ds.Put<>(ciphertextSize);
            if ( tagSize == std::nullopt ) {
                ds.Put<bool>(true);
            } else {
                ds.Put<bool>(false);
                ds.Put<>(*tagSize);
            }
        }
};

class SymmetricDecrypt : public Operation {
    public:
        const Buffer ciphertext;
        const component::SymmetricCipher cipher;
        const std::optional<component::Tag> tag;
        const std::optional<component::AAD> aad;

        const uint64_t cleartextSize;
        const uint8_t expected;

        SymmetricDecrypt(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            ciphertext(ds),
            cipher(ds),
            tag(ds.Get<bool>() ? std::nullopt : std::make_optional<component::Tag>(ds)),
            aad(ds.Get<bool>() ? std::nullopt : std::make_optional<component::AAD>(ds)),
            cleartextSize(ds.Get<uint64_t>() % (10*1024*1024)),
            expected(ds.Get<uint8_t>())
        { }
        SymmetricDecrypt(const SymmetricEncrypt& opSymmetricEncrypt, const component::Ciphertext ciphertext, const uint64_t cleartextSize, std::optional<component::AAD> aad, component::Modifier modifier);
        SymmetricDecrypt(nlohmann::json json) :
            Operation(json["modifier"]),
            ciphertext(json["ciphertext"]),
            cipher(json["cipher"]),
            tag(
                    json["tag_enabled"].get<bool>() ?
                        std::optional<component::Tag>(json["tag"]) :
                        std::optional<component::Tag>(std::nullopt)
            ),
            aad(
                    json["aad_enabled"].get<bool>() ?
                        std::optional<component::AAD>(json["aad"]) :
                        std::optional<component::AAD>(std::nullopt)
            ),
            cleartextSize(json["cleartextSize"].get<uint64_t>()),
            expected(json["expected"].get<uint8_t>())
            
        { }

        static size_t MaxOperations(void) { return 20; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        std::string GetAlgorithmString(void) const override {
            return repository::CipherToString(cipher.cipherType.Get());
        }
        inline bool operator==(const SymmetricDecrypt& rhs) const {
            return
                (ciphertext == rhs.ciphertext) &&
                (cipher == rhs.cipher) &&
                (tag == rhs.tag) &&
                (aad == rhs.aad) &&
                (cleartextSize == rhs.cleartextSize) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            ciphertext.Serialize(ds);
            cipher.Serialize(ds);
            if ( tag == std::nullopt ) {
                ds.Put<bool>(true);
            } else {
                ds.Put<bool>(false);
                tag->Serialize(ds);
            }
            if ( aad == std::nullopt ) {
                ds.Put<bool>(true);
            } else {
                ds.Put<bool>(false);
                aad->Serialize(ds);
            }
            ds.Put<>(cleartextSize);
        }
};

class KDF_SCRYPT : public Operation {
    public:
        const component::Cleartext password;
        const component::Cleartext salt;
        const uint64_t N;
        const uint64_t r;
        const uint64_t p;

        const uint64_t keySize;

        KDF_SCRYPT(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            password(ds),
            salt(ds),
            N(ds.Get<uint64_t>() % 5),
            r(ds.Get<uint64_t>() % 9),
            p(ds.Get<uint64_t>() % 5),
            keySize(ds.Get<uint64_t>() % 1024)
        { }
        KDF_SCRYPT(nlohmann::json json) :
            Operation(json["modifier"]),
            password(json["password"]),
            salt(json["salt"]),
            N(json["N"].get<uint64_t>()),
            r(json["r"].get<uint64_t>()),
            p(json["p"].get<uint64_t>()),
            keySize(json["keySize"].get<uint64_t>())
        { }

        static size_t MaxOperations(void) { return 20; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const KDF_SCRYPT& rhs) const {
            return
                (password == rhs.password) &&
                (salt == rhs.salt) &&
                (N == rhs.N) &&
                (r == rhs.r) &&
                (p == rhs.p) &&
                (keySize == rhs.keySize) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            password.Serialize(ds);
            salt.Serialize(ds);
            ds.Put<>(N);
            ds.Put<>(r);
            ds.Put<>(p);
            ds.Put<>(keySize);
        }
};

class KDF_HKDF : public Operation {
    public:
        const component::DigestType digestType;
        const component::Cleartext password;
        const component::Cleartext salt;
        const component::Cleartext info;

        const uint64_t keySize;

        KDF_HKDF(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            digestType(getDigestType(ds)),
            password(ds),
            salt(ds),
            info(ds),
            keySize(ds.Get<uint64_t>() % 17000)
        { }
        KDF_HKDF(nlohmann::json json) :
            Operation(json["modifier"]),
            digestType(json["digestType"]),
            password(json["password"]),
            salt(json["salt"]),
            info(json["info"]),
            keySize(json["keySize"].get<uint64_t>())
        { }

        static size_t MaxOperations(void) { return 20; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const KDF_HKDF& rhs) const {
            return
                (digestType == rhs.digestType) &&
                (password == rhs.password) &&
                (salt == rhs.salt) &&
                (info == rhs.info) &&
                (keySize == rhs.keySize) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            digestType.Serialize(ds);
            password.Serialize(ds);
            salt.Serialize(ds);
            info.Serialize(ds);
            ds.Put<>(keySize);
        }
};

class KDF_TLS1_PRF : public Operation {
    public:
        const component::DigestType digestType;
        const component::Cleartext secret;
        const component::Cleartext seed;

        const uint64_t keySize;

        KDF_TLS1_PRF(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            digestType(getDigestType(ds)),
            secret(ds),
            seed(ds),
            keySize(ds.Get<uint64_t>() % 1024)
        { }
        KDF_TLS1_PRF(nlohmann::json json) :
            Operation(json["modifier"]),
            digestType(json["digestType"]),
            secret(json["secret"]),
            seed(json["seed"]),
            keySize(json["keySize"].get<uint64_t>())
        { }

        static size_t MaxOperations(void) { return 20; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const KDF_TLS1_PRF& rhs) const {
            return
                (digestType == rhs.digestType) &&
                (secret == rhs.secret) &&
                (seed == rhs.seed) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            digestType.Serialize(ds);
            secret.Serialize(ds);
            seed.Serialize(ds);
            ds.Put<>(keySize);
        }
};

class KDF_PBKDF : public Operation {
    public:
        const component::DigestType digestType;
        const component::Cleartext password;
        const component::Cleartext salt;
        const uint64_t iterations;

        const uint64_t keySize;

        KDF_PBKDF(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            digestType(getDigestType(ds)),
            password(ds),
            salt(ds),
            iterations(ds.Get<uint64_t>() % 5),
            keySize(ds.Get<uint64_t>() % 1024)
        { }
        KDF_PBKDF(nlohmann::json json) :
            Operation(json["modifier"]),
            digestType(json["digestType"]),
            password(json["password"]),
            salt(json["salt"]),
            iterations(json["iterations"].get<uint64_t>()),
            keySize(json["keySize"].get<uint64_t>())
        { }

        static size_t MaxOperations(void) { return 20; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const KDF_PBKDF& rhs) const {
            return
                (digestType == rhs.digestType) &&
                (password == rhs.password) &&
                (salt == rhs.salt) &&
                (iterations == rhs.iterations) &&
                (keySize == rhs.keySize) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            digestType.Serialize(ds);
            password.Serialize(ds);
            salt.Serialize(ds);
            ds.Put<>(iterations);
            ds.Put<>(keySize);
        }
};

class KDF_PBKDF1 : public Operation {
    public:
        const component::DigestType digestType;
        const component::Cleartext password;
        const component::Cleartext salt;
        const uint64_t iterations;

        const uint64_t keySize;

        KDF_PBKDF1(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            digestType(getDigestType(ds)),
            password(ds),
            salt(ds),
            iterations(ds.Get<uint64_t>() % 5),
            keySize(ds.Get<uint64_t>() % 1024)
        { }
        KDF_PBKDF1(nlohmann::json json) :
            Operation(json["modifier"]),
            digestType(json["digestType"]),
            password(json["password"]),
            salt(json["salt"]),
            iterations(json["iterations"].get<uint64_t>()),
            keySize(json["keySize"].get<uint64_t>())
        { }

        static size_t MaxOperations(void) { return 20; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const KDF_PBKDF1& rhs) const {
            return
                (digestType == rhs.digestType) &&
                (password == rhs.password) &&
                (salt == rhs.salt) &&
                (iterations == rhs.iterations) &&
                (keySize == rhs.keySize) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            digestType.Serialize(ds);
            password.Serialize(ds);
            salt.Serialize(ds);
            ds.Put<>(iterations);
            ds.Put<>(keySize);
        }
};

class KDF_PBKDF2 : public Operation {
    public:
        const component::DigestType digestType;
        const component::Cleartext password;
        const component::Cleartext salt;
        const uint64_t iterations;

        const uint64_t keySize;

        KDF_PBKDF2(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            digestType(getDigestType(ds)),
            password(ds),
            salt(ds),
            iterations(ds.Get<uint64_t>() % 5),
            keySize(ds.Get<uint64_t>() % 1024)
        { }
        KDF_PBKDF2(nlohmann::json json) :
            Operation(json["modifier"]),
            digestType(json["digestType"]),
            password(json["password"]),
            salt(json["salt"]),
            iterations(json["iterations"].get<uint64_t>()),
            keySize(json["keySize"].get<uint64_t>())
        { }

        static size_t MaxOperations(void) { return 20; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const KDF_PBKDF2& rhs) const {
            return
                (digestType == rhs.digestType) &&
                (password == rhs.password) &&
                (salt == rhs.salt) &&
                (iterations == rhs.iterations) &&
                (keySize == rhs.keySize) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            digestType.Serialize(ds);
            password.Serialize(ds);
            salt.Serialize(ds);
            ds.Put<>(iterations);
            ds.Put<>(keySize);
        }
};

class KDF_ARGON2 : public Operation {
    public:
        const component::Cleartext password;
        const component::Cleartext salt;
        const uint8_t type;
        const uint8_t threads;
        const uint32_t memory;
        const uint32_t iterations;
        const uint32_t keySize;

        KDF_ARGON2(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            password(ds),
            salt(ds),
            type(ds.Get<uint8_t>()),
            threads(ds.Get<uint8_t>() % 1 + 1),
            memory(ds.Get<uint32_t>() % (64*1024)),
            iterations(ds.Get<uint32_t>() % 3 + 3),
            keySize(ds.Get<uint32_t>() % 1008 + 16)
        { }
        KDF_ARGON2(nlohmann::json json) :
            Operation(json["modifier"]),
            password(json["password"]),
            salt(json["salt"]),
            type(json["type"].get<uint8_t>()),
            threads(json["threads"].get<uint8_t>()),
            memory(json["memory"].get<uint32_t>()),
            iterations(json["iterations"].get<uint32_t>()),
            keySize(json["keySize"].get<uint32_t>())
        { }

        static size_t MaxOperations(void) { return 3; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const KDF_ARGON2& rhs) const {
            return
                (password == rhs.password) &&
                (salt == rhs.salt) &&
                (type == rhs.type) &&
                (threads == rhs.threads) &&
                (memory == rhs.memory) &&
                (iterations == rhs.iterations) &&
                (keySize == rhs.keySize) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            password.Serialize(ds);
            salt.Serialize(ds);
            ds.Put<>(type);
            ds.Put<>(threads);
            ds.Put<>(memory);
            ds.Put<>(iterations);
            ds.Put<>(keySize);
        }
};

class KDF_SSH : public Operation {
    public:
        const component::DigestType digestType;
        const component::Cleartext key;
        const component::Cleartext xcghash;
        const component::Cleartext session_id;
        const component::Cleartext type;
        const uint64_t keySize;

        KDF_SSH(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            digestType(getDigestType(ds)),
            key(ds),
            xcghash(ds),
            session_id(ds),
            type(ds),
            keySize(ds.Get<uint64_t>() % 1024)
        { }
        KDF_SSH(nlohmann::json json) :
            Operation(json["modifier"]),
            digestType(json["digestType"]),
            key(json["key"]),
            xcghash(json["xcghash"]),
            session_id(json["session_id"]),
            type(json["type"]),
            keySize(json["keySize"].get<uint64_t>())
        { }

        static size_t MaxOperations(void) { return 20; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const KDF_SSH& rhs) const {
            return
                (digestType == rhs.digestType) &&
                (key == rhs.key) &&
                (xcghash == rhs.xcghash) &&
                (session_id == rhs.session_id) &&
                (type == rhs.type) &&
                (keySize == rhs.keySize) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            digestType.Serialize(ds);
            key.Serialize(ds);
            xcghash.Serialize(ds);
            session_id.Serialize(ds);
            type.Serialize(ds);
            ds.Put<>(keySize);
        }
};

class KDF_X963 : public Operation {
    public:
        const component::DigestType digestType;
        const component::Cleartext secret;
        const component::Cleartext info;
        const uint64_t keySize;

        KDF_X963(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            digestType(getDigestType(ds)),
            secret(ds),
            info(ds),
            keySize(ds.Get<uint64_t>() % 1024)
        { }
        KDF_X963(nlohmann::json json) :
            Operation(json["modifier"]),
            digestType(json["digestType"]),
            secret(json["secret"]),
            info(json["info"]),
            keySize(json["keySize"].get<uint64_t>())
        { }

        static size_t MaxOperations(void) { return 20; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const KDF_X963& rhs) const {
            return
                (digestType == rhs.digestType) &&
                (secret == rhs.secret) &&
                (info == rhs.info) &&
                (keySize == rhs.keySize) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            digestType.Serialize(ds);
            secret.Serialize(ds);
            info.Serialize(ds);
            ds.Put<>(keySize);
        }
};

class KDF_BCRYPT : public Operation {
    public:
        const component::DigestType digestType;
        const component::Cleartext secret;
        const component::Cleartext salt;
        const uint32_t iterations;
        const uint64_t keySize;

        KDF_BCRYPT(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            digestType(getDigestType(ds)),
            secret(ds),
            salt(ds),
            iterations(ds.Get<uint32_t>() % 3),
            keySize(ds.Get<uint64_t>() % 1024)
        { }
        KDF_BCRYPT(nlohmann::json json) :
            Operation(json["modifier"]),
            digestType(json["digestType"]),
            secret(json["secret"]),
            salt(json["salt"]),
            iterations(json["iterations"].get<uint32_t>()),
            keySize(json["keySize"].get<uint64_t>())
        { }

        static size_t MaxOperations(void) { return 2; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const KDF_BCRYPT& rhs) const {
            return
                (digestType == rhs.digestType) &&
                (secret == rhs.secret) &&
                (salt == rhs.salt) &&
                (iterations == rhs.iterations) &&
                (keySize == rhs.keySize) &&
                (modifier == rhs.modifier);
        }
};

class KDF_SP_800_108 : public Operation {
    public:
        const component::MACType mech;
        const component::Cleartext secret;
        const component::Cleartext salt;
        const component::Cleartext label;
        const uint8_t mode;
        const uint64_t keySize;

        KDF_SP_800_108(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            mech(ds),
            secret(ds),
            salt(ds),
            label(ds),
            mode(ds.Get<uint8_t>()),
            keySize(ds.Get<uint64_t>() % 17000)
        { }
        KDF_SP_800_108(nlohmann::json json) :
            Operation(json["modifier"]),
            mech(json["mech"]),
            secret(json["secret"]),
            salt(json["salt"]),
            label(json["label"]),
            mode(json["mode"].get<uint8_t>()),
            keySize(json["keySize"].get<uint64_t>())
        { }

        static size_t MaxOperations(void) { return 20; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const KDF_SP_800_108& rhs) const {
            return
                (mech == rhs.mech) &&
                (secret == rhs.secret) &&
                (salt == rhs.salt) &&
                (label == rhs.label) &&
                (mode == rhs.mode) &&
                (keySize == rhs.keySize) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            mech.Serialize(ds);
            secret.Serialize(ds);
            salt.Serialize(ds);
            label.Serialize(ds);
            ds.Put<>(mode);
            ds.Put<>(keySize);
        }
};

class CMAC : public Operation {
    public:
        const component::Cleartext cleartext;
        const component::SymmetricCipher cipher;

        CMAC(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            cleartext(ds),
            cipher(ds)
        { }
        CMAC(nlohmann::json json) :
            Operation(json["modifier"]),
            cleartext(json["cleartext"]),
            cipher(json["cipher"])
        { }

        static size_t MaxOperations(void) { return 20; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const CMAC& rhs) const {
            return
                (cleartext == rhs.cleartext) &&
                (cipher == rhs.cipher) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            cleartext.Serialize(ds);
            cipher.Serialize(ds);
        }
};

class ECC_PrivateToPublic : public Operation {
    public:
        const component::CurveType curveType;
        const component::ECC_PrivateKey priv;

        ECC_PrivateToPublic(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            curveType(getEccCurveType(ds)),
            priv(ds)
        { }
        ECC_PrivateToPublic(nlohmann::json json) :
            Operation(json["modifier"]),
            curveType(json["curveType"]),
            priv(json["priv"])
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const ECC_PrivateToPublic& rhs) const {
            return
                (curveType == rhs.curveType) &&
                (priv == rhs.priv) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            curveType.Serialize(ds);
            priv.Serialize(ds);
        }
};

class ECC_ValidatePubkey : public Operation {
    public:
        const component::CurveType curveType;
        const component::ECC_PublicKey pub;
        const uint8_t id;

        ECC_ValidatePubkey(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            curveType(getEccCurveType(ds)),
            pub(ds),
            id(ds.Get<uint8_t>())
        { }
        ECC_ValidatePubkey(nlohmann::json json) :
            Operation(json["modifier"]),
            curveType(json["curveType"]),
            pub(json["pub_x"], json["pub_y"]),
            id(json["id"].get<uint8_t>())
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const ECC_ValidatePubkey& rhs) const {
            return
                (curveType == rhs.curveType) &&
                (pub == rhs.pub) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            curveType.Serialize(ds);
            pub.Serialize(ds);
            ds.Put<>(id);
        }
};

class ECC_GenerateKeyPair : public Operation {
    public:
        const component::CurveType curveType;

        ECC_GenerateKeyPair(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            curveType(getEccCurveType(ds))
        { }

        ECC_GenerateKeyPair(nlohmann::json json) :
            Operation(json["modifier"]),
            curveType(json["curveType"])
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const ECC_GenerateKeyPair& rhs) const {
            return
                (curveType == rhs.curveType) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            curveType.Serialize(ds);
        }
};

class ECDSA_Sign : public Operation {
    public:
        const component::CurveType curveType;
        const component::ECC_PrivateKey priv;
        const component::Bignum nonce;
        const component::Cleartext cleartext;
        const uint8_t nonceSource;
        const component::DigestType digestType;

        ECDSA_Sign(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            curveType(getEccCurveType(ds)),
            priv(ds),
            nonce(ds),
            cleartext(ds),
            nonceSource(ds.Get<uint8_t>()),
            digestType(getDigestType(ds))
        { }
        ECDSA_Sign(nlohmann::json json) :
            Operation(json["modifier"]),
            curveType(json["curveType"]),
            priv(json["priv"]),
            nonce(json["nonce"]),
            cleartext(json["cleartext"]),
            nonceSource(json["nonceSource"].get<uint8_t>()),
            digestType(json["digestType"])
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const ECDSA_Sign& rhs) const {
            return
                (curveType == rhs.curveType) &&
                (priv == rhs.priv) &&
                (nonce == rhs.nonce) &&
                (cleartext == rhs.cleartext) &&
                (nonceSource == rhs.nonceSource ) &&
                (digestType == rhs.digestType ) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            curveType.Serialize(ds);
            priv.Serialize(ds);
            nonce.Serialize(ds);
            cleartext.Serialize(ds);
            ds.Put<>(nonceSource);
            digestType.Serialize(ds);
        }
        bool UseRandomNonce(void) const {
            return nonceSource == 0;
        }
        bool UseRFC6979Nonce(void) const {
            return nonceSource == 1;
        }
        bool UseSpecifiedNonce(void) const {
            return nonceSource == 2;
        }
};

class ECGDSA_Sign : public Operation {
    public:
        const component::CurveType curveType;
        const component::ECC_PrivateKey priv;
        const component::Bignum nonce;
        const component::Cleartext cleartext;
        const uint8_t nonceSource;
        const component::DigestType digestType;

        ECGDSA_Sign(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            curveType(getEccCurveType(ds)),
            priv(ds),
            nonce(ds),
            cleartext(ds),
            nonceSource(ds.Get<uint8_t>()),
            digestType(getDigestType(ds))
        { }
        ECGDSA_Sign(nlohmann::json json) :
            Operation(json["modifier"]),
            curveType(json["curveType"]),
            priv(json["priv"]),
            nonce(json["nonce"]),
            cleartext(json["cleartext"]),
            nonceSource(json["nonceSource"].get<uint8_t>()),
            digestType(json["digestType"])
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const ECGDSA_Sign& rhs) const {
            return
                (curveType == rhs.curveType) &&
                (priv == rhs.priv) &&
                (nonce == rhs.nonce) &&
                (cleartext == rhs.cleartext) &&
                (nonceSource == rhs.nonceSource ) &&
                (digestType == rhs.digestType ) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            curveType.Serialize(ds);
            priv.Serialize(ds);
            nonce.Serialize(ds);
            cleartext.Serialize(ds);
            ds.Put<>(nonceSource);
            digestType.Serialize(ds);
        }
        bool UseRandomNonce(void) const {
            return nonceSource == 0;
        }
        bool UseRFC6979Nonce(void) const {
            return nonceSource == 1;
        }
        bool UseSpecifiedNonce(void) const {
            return nonceSource == 2;
        }
};

class ECRDSA_Sign : public Operation {
    public:
        const component::CurveType curveType;
        const component::ECC_PrivateKey priv;
        const component::Bignum nonce;
        const component::Cleartext cleartext;
        const uint8_t nonceSource;
        const component::DigestType digestType;

        ECRDSA_Sign(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            curveType(getEccCurveType(ds)),
            priv(ds),
            nonce(ds),
            cleartext(ds),
            nonceSource(ds.Get<uint8_t>()),
            digestType(getDigestType(ds))
        { }
        ECRDSA_Sign(nlohmann::json json) :
            Operation(json["modifier"]),
            curveType(json["curveType"]),
            priv(json["priv"]),
            nonce(json["nonce"]),
            cleartext(json["cleartext"]),
            nonceSource(json["nonceSource"].get<uint8_t>()),
            digestType(json["digestType"])
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const ECRDSA_Sign& rhs) const {
            return
                (curveType == rhs.curveType) &&
                (priv == rhs.priv) &&
                (nonce == rhs.nonce) &&
                (cleartext == rhs.cleartext) &&
                (nonceSource == rhs.nonceSource ) &&
                (digestType == rhs.digestType ) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            curveType.Serialize(ds);
            priv.Serialize(ds);
            nonce.Serialize(ds);
            cleartext.Serialize(ds);
            ds.Put<>(nonceSource);
            digestType.Serialize(ds);
        }
        bool UseRandomNonce(void) const {
            return nonceSource == 0;
        }
        bool UseRFC6979Nonce(void) const {
            return nonceSource == 1;
        }
        bool UseSpecifiedNonce(void) const {
            return nonceSource == 2;
        }
};

class Schnorr_Sign : public Operation {
    public:
        const component::CurveType curveType;
        const component::ECC_PrivateKey priv;
        const component::Bignum nonce;
        const component::Cleartext cleartext;
        const uint8_t nonceSource;
        const component::DigestType digestType;

        Schnorr_Sign(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            curveType(getEccCurveType(ds)),
            priv(ds),
            nonce(ds),
            cleartext(ds),
            nonceSource(ds.Get<uint8_t>()),
            digestType(getDigestType(ds))
        { }
        Schnorr_Sign(nlohmann::json json) :
            Operation(json["modifier"]),
            curveType(json["curveType"]),
            priv(json["priv"]),
            nonce(json["nonce"]),
            cleartext(json["cleartext"]),
            nonceSource(json["nonceSource"].get<uint8_t>()),
            digestType(json["digestType"])
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const Schnorr_Sign& rhs) const {
            return
                (curveType == rhs.curveType) &&
                (priv == rhs.priv) &&
                (nonce == rhs.nonce) &&
                (cleartext == rhs.cleartext) &&
                (nonceSource == rhs.nonceSource ) &&
                (digestType == rhs.digestType ) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            curveType.Serialize(ds);
            priv.Serialize(ds);
            nonce.Serialize(ds);
            cleartext.Serialize(ds);
            ds.Put<>(nonceSource);
            digestType.Serialize(ds);
        }
        bool UseRandomNonce(void) const {
            return nonceSource == 0;
        }
        bool UseBIP340Nonce(void) const {
            return nonceSource == 1;
        }
        bool UseSpecifiedNonce(void) const {
            return nonceSource == 2;
        }
};

class ECDSA_Verify : public Operation {
    public:
        const component::CurveType curveType;
        const component::Cleartext cleartext;
        const component::ECDSA_Signature signature;
        const component::DigestType digestType;

        const uint8_t id;

        ECDSA_Verify(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            curveType(getEccCurveType(ds)),
            cleartext(ds),
            signature(ds),
            digestType(getDigestType(ds)),
            id(ds.Get<uint8_t>())
        { 
        }
        ECDSA_Verify(nlohmann::json json) :
            Operation(json["modifier"]),
            curveType(json["curveType"]),
            cleartext(json["cleartext"]),
            signature(json["signature"]),
            digestType(json["digestType"]),
            id(json["id"].get<uint8_t>())
        { 
        }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const ECDSA_Verify& rhs) const {
            return
                (curveType == rhs.curveType) &&
                (cleartext == rhs.cleartext) &&
                (signature == rhs.signature) &&
                (digestType == rhs.digestType) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            curveType.Serialize(ds);
            cleartext.Serialize(ds);
            signature.Serialize(ds);
            digestType.Serialize(ds);
            ds.Put<>(id);
        }
};

class ECGDSA_Verify : public Operation {
    public:
        const component::CurveType curveType;
        const component::Cleartext cleartext;
        const component::ECGDSA_Signature signature;
        const component::DigestType digestType;

        ECGDSA_Verify(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            curveType(getEccCurveType(ds)),
            cleartext(ds),
            signature(ds),
            digestType(getDigestType(ds))
        { }
        ECGDSA_Verify(nlohmann::json json) :
            Operation(json["modifier"]),
            curveType(json["curveType"]),
            cleartext(json["cleartext"]),
            signature(json["signature"]),
            digestType(json["digestType"])
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const ECGDSA_Verify& rhs) const {
            return
                (curveType == rhs.curveType) &&
                (cleartext == rhs.cleartext) &&
                (signature == rhs.signature) &&
                (digestType == rhs.digestType) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            curveType.Serialize(ds);
            cleartext.Serialize(ds);
            signature.Serialize(ds);
            digestType.Serialize(ds);
        }
};

class ECRDSA_Verify : public Operation {
    public:
        const component::CurveType curveType;
        const component::Cleartext cleartext;
        const component::ECRDSA_Signature signature;
        const component::DigestType digestType;

        ECRDSA_Verify(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            curveType(getEccCurveType(ds)),
            cleartext(ds),
            signature(ds),
            digestType(getDigestType(ds))
        { }
        ECRDSA_Verify(nlohmann::json json) :
            Operation(json["modifier"]),
            curveType(json["curveType"]),
            cleartext(json["cleartext"]),
            signature(json["signature"]),
            digestType(json["digestType"])
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const ECRDSA_Verify& rhs) const {
            return
                (curveType == rhs.curveType) &&
                (cleartext == rhs.cleartext) &&
                (signature == rhs.signature) &&
                (digestType == rhs.digestType) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            curveType.Serialize(ds);
            cleartext.Serialize(ds);
            signature.Serialize(ds);
            digestType.Serialize(ds);
        }
};

class ECDSA_Recover : public Operation {
    public:
        const component::CurveType curveType;
        const component::Cleartext cleartext;
        const component::BignumPair signature;
        const component::DigestType digestType;
        const uint8_t id;

        ECDSA_Recover(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            curveType(getEccCurveType(ds)),
            cleartext(ds),
            signature(ds),
            digestType(getDigestType(ds)),
            id(ds.Get<uint8_t>())
        { }
        ECDSA_Recover(nlohmann::json json) :
            Operation(json["modifier"]),
            curveType(json["curveType"]),
            cleartext(json["cleartext"]),
            signature(json["signature"]),
            digestType(json["digestType"]),
            id(json["id"].get<uint8_t>())
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const ECDSA_Recover& rhs) const {
            return
                (curveType == rhs.curveType) &&
                (cleartext == rhs.cleartext) &&
                (signature == rhs.signature) &&
                (digestType == rhs.digestType) &&
                (id == rhs.id) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            curveType.Serialize(ds);
            cleartext.Serialize(ds);
            signature.Serialize(ds);
            digestType.Serialize(ds);
            ds.Put<>(id);
        }
};

class Schnorr_Verify : public Operation {
    public:
        const component::CurveType curveType;
        const component::Cleartext cleartext;
        const component::ECDSA_Signature signature;
        const component::DigestType digestType;

        Schnorr_Verify(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            curveType(getEccCurveType(ds)),
            cleartext(ds),
            signature(ds),
            digestType(getDigestType(ds))
        { }
        Schnorr_Verify(nlohmann::json json) :
            Operation(json["modifier"]),
            curveType(json["curveType"]),
            cleartext(json["cleartext"]),
            signature(json["signature"]),
            digestType(json["digestType"])
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const Schnorr_Verify& rhs) const {
            return
                (curveType == rhs.curveType) &&
                (cleartext == rhs.cleartext) &&
                (signature == rhs.signature) &&
                (digestType == rhs.digestType) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            curveType.Serialize(ds);
            cleartext.Serialize(ds);
            signature.Serialize(ds);
            digestType.Serialize(ds);
        }
};

class ECDH_Derive : public Operation {
    public:
        const component::CurveType curveType;
        const component::ECC_PrivateKey priv;
        const component::ECC_PublicKey pub;

        ECDH_Derive(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            curveType(getEccCurveType(ds)),
            priv(ds),
            pub(ds)
        { }
        ECDH_Derive(nlohmann::json json) :
            Operation(json["modifier"]),
            curveType(json["curveType"]),
            priv(json["priv"]),
            pub(json["pub_x"], json["pub_y"])
        { }
        ECDH_Derive(
                component::Modifier modifier,
                component::CurveType curveType,
                component::ECC_PrivateKey priv,
                component::ECC_PublicKey pub) :
            Operation(std::move(modifier)),
            curveType(curveType),
            priv(priv),
            pub(pub)
        { }


        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const ECDH_Derive& rhs) const {
            return
                (curveType == rhs.curveType) &&
                (priv == rhs.priv) &&
                (pub == rhs.pub) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            curveType.Serialize(ds);
            priv.Serialize(ds);
            pub.Serialize(ds);
        }
};

class ECIES_Encrypt : public Operation {
    public:
        const component::Cleartext cleartext;
        const component::CurveType curveType;
        const component::ECC_PrivateKey priv;
        const component::ECC_PublicKey pub;
        const component::SymmetricCipherType cipherType;
        const std::optional<component::SymmetricIV> iv;
        /* TODO kdf type */
        /* TODO mac type */

        ECIES_Encrypt(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            cleartext(ds),
            curveType(getEccCurveType(ds)),
            priv(ds),
            pub(ds),
            cipherType(ds),
            iv(ds.Get<bool>() ? std::nullopt : std::make_optional<component::SymmetricIV>(ds))
        { }
        ECIES_Encrypt(nlohmann::json json) :
            Operation(json["modifier"]),
            cleartext(json["cleartext"]),
            curveType(json["curveType"]),
            priv(json["priv"]),
            pub(json["pub_x"], json["pub_y"]),
            cipherType(json["cipherType"]),
            iv(
                    json["iv_enabled"].get<bool>() ?
                        std::optional<component::SymmetricIV>(json["iv"]) :
                        std::optional<component::SymmetricIV>(std::nullopt)
            )
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const ECIES_Encrypt& rhs) const {
            return
                (cleartext == rhs.cleartext) &&
                (curveType == rhs.curveType) &&
                (priv == rhs.priv) &&
                (pub == rhs.pub) &&
                (cipherType == rhs.cipherType) &&
                (iv == rhs.iv) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            cleartext.Serialize(ds);
            curveType.Serialize(ds);
            priv.Serialize(ds);
            pub.Serialize(ds);
            cipherType.Serialize(ds);
            if ( iv == std::nullopt ) {
                ds.Put<bool>(true);
            } else {
                ds.Put<bool>(false);
                iv->Serialize(ds);
            }
        }
};

class ECIES_Decrypt : public Operation {
    public:
        const Buffer ciphertext;
        const component::CurveType curveType;
        const component::ECC_PrivateKey priv;
        const component::ECC_PublicKey pub;
        const component::SymmetricCipherType cipherType;
        const std::optional<component::SymmetricIV> iv;
        /* TODO kdf type */
        /* TODO mac type */

        ECIES_Decrypt(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            ciphertext(ds),
            curveType(getEccCurveType(ds)),
            priv(ds),
            pub(ds),
            cipherType(ds),
            iv(ds.Get<bool>() ? std::nullopt : std::make_optional<component::SymmetricIV>(ds))
        { }
        ECIES_Decrypt(nlohmann::json json) :
            Operation(json["modifier"]),
            ciphertext(json["ciphertext"]),
            curveType(json["curveType"]),
            priv(json["priv"]),
            pub(json["pub_x"], json["pub_y"]),
            cipherType(json["cipherType"]),
            iv(
                    json["iv_enabled"].get<bool>() ?
                        std::optional<component::SymmetricIV>(json["iv"]) :
                        std::optional<component::SymmetricIV>(std::nullopt)
            )
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const ECIES_Decrypt& rhs) const {
            return
                (ciphertext == rhs.ciphertext) &&
                (curveType == rhs.curveType) &&
                (priv == rhs.priv) &&
                (pub == rhs.pub) &&
                (cipherType == rhs.cipherType) &&
                (iv == rhs.iv) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            ciphertext.Serialize(ds);
            curveType.Serialize(ds);
            priv.Serialize(ds);
            pub.Serialize(ds);
            cipherType.Serialize(ds);
            if ( iv == std::nullopt ) {
                ds.Put<bool>(true);
            } else {
                ds.Put<bool>(false);
                iv->Serialize(ds);
            }
        }
};

class ECC_Point_Add : public Operation {
    public:
        const component::CurveType curveType;
        const component::ECC_Point a, b;

        ECC_Point_Add(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            curveType(getEccCurveType(ds)),
            a(ds),
            b(ds)
        { }
        ECC_Point_Add(nlohmann::json json) :
            Operation(json["modifier"]),
            curveType(json["curveType"]),
            a(json["a_x"], json["a_y"]),
            b(json["b_x"], json["b_y"])
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const ECC_Point_Add& rhs) const {
            return
                (curveType == rhs.curveType) &&
                (a == rhs.a) &&
                (b == rhs.b) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            curveType.Serialize(ds);
            a.Serialize(ds);
            b.Serialize(ds);
        }
};

class ECC_Point_Mul : public Operation {
    public:
        const component::CurveType curveType;
        const component::ECC_Point a;
        const component::Bignum b;

        ECC_Point_Mul(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            curveType(getEccCurveType(ds)),
            a(ds),
            b(ds)
        { }
        ECC_Point_Mul(nlohmann::json json) :
            Operation(json["modifier"]),
            curveType(json["curveType"]),
            a(json["a_x"], json["a_y"]),
            b(json["b"])
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const ECC_Point_Mul& rhs) const {
            return
                (curveType == rhs.curveType) &&
                (a == rhs.a) &&
                (b == rhs.b) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            curveType.Serialize(ds);
            a.Serialize(ds);
            b.Serialize(ds);
        }
};

class DH_GenerateKeyPair : public Operation {
    public:
        const component::Bignum prime;
        const component::Bignum base;

        DH_GenerateKeyPair(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            prime(ds),
            base(ds)
        { }
        DH_GenerateKeyPair(nlohmann::json json) :
            Operation(json["modifier"]),
            prime(json["prime"]),
            base(json["base"])
        { }
        DH_GenerateKeyPair(
                component::Modifier modifier,
                component::Bignum prime,
                component::Bignum base) :
            Operation(std::move(modifier)),
            prime(prime),
            base(base)
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const DH_GenerateKeyPair& rhs) const {
            return
                (prime == rhs.prime) &&
                (base  == rhs.base) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            prime.Serialize(ds);
            base.Serialize(ds);
        }
};

class DH_Derive : public Operation {
    public:
        const component::Bignum prime;
        const component::Bignum base;
        const component::Bignum pub;
        const component::Bignum priv;

        DH_Derive(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            prime(ds),
            base(ds),
            pub(ds),
            priv(ds)
        { }
        DH_Derive(nlohmann::json json) :
            Operation(json["modifier"]),
            prime(json["prime"]),
            base(json["base"]),
            pub(json["pub"]),
            priv(json["priv"])
        { }
        DH_Derive(
                component::Modifier modifier,
                component::Bignum prime,
                component::Bignum base,
                component::Bignum pub,
                component::Bignum priv) :
            Operation(std::move(modifier)),
            prime(prime),
            base(base),
            pub(pub),
            priv(priv)
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const DH_Derive& rhs) const {
            return
                (prime == rhs.prime) &&
                (base  == rhs.base) &&
                (pub == rhs.pub) &&
                (priv == rhs.priv) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            prime.Serialize(ds);
            base.Serialize(ds);
            pub.Serialize(ds);
            priv.Serialize(ds);
        }
};

class BignumCalc : public Operation {
    public:
        const component::CalcOp calcOp;
        const component::Bignum bn0;
        const component::Bignum bn1;
        const component::Bignum bn2;
        const component::Bignum bn3;
        std::optional<component::Bignum> modulo;

        BignumCalc(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            calcOp(getCalcOp(ds)),
            bn0(ds),
            bn1(ds),
            bn2(ds),
            bn3(ds)
        { }
        BignumCalc(nlohmann::json json) :
            Operation(json["modifier"]),
            calcOp(json["calcOp"]),
            bn0(json["bn1"]),
            bn1(json["bn2"]),
            bn2(json["bn3"]),
            bn3(json["bn4"])
        { }
        BignumCalc(
                component::Modifier modifier,
                component::CurveType calcOp,
                component::Bignum bn0,
                component::Bignum bn1,
                component::Bignum bn2,
                component::Bignum bn3) :
            Operation(std::move(modifier)),
            calcOp(calcOp),
            bn0(bn0),
            bn1(bn1),
            bn2(bn2),
            bn3(bn3)
        { }


        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const BignumCalc& rhs) const {
            return
                (calcOp == rhs.calcOp) &&
                (bn0 == rhs.bn0) &&
                (bn1 == rhs.bn1) &&
                (bn2 == rhs.bn2) &&
                (bn3 == rhs.bn3) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            calcOp.Serialize(ds);
            bn0.Serialize(ds);
            bn1.Serialize(ds);
            bn2.Serialize(ds);
            bn3.Serialize(ds);
        }
        void SetModulo(component::Bignum& modulo);
};

class BLS_PrivateToPublic : public Operation {
    public:
        const component::CurveType curveType;
        const component::BLS_PrivateKey priv;

        BLS_PrivateToPublic(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            curveType(getEccCurveType(ds)),
            priv(ds)
        { }
        BLS_PrivateToPublic(nlohmann::json json) :
            Operation(json["modifier"]),
            curveType(json["curveType"]),
            priv(json["priv"])
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const BLS_PrivateToPublic& rhs) const {
            return
                (curveType == rhs.curveType) &&
                (priv == rhs.priv) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            curveType.Serialize(ds);
            priv.Serialize(ds);
        }
};

class BLS_PrivateToPublic_G2 : public Operation {
    public:
        const component::CurveType curveType;
        const component::BLS_PrivateKey priv;

        BLS_PrivateToPublic_G2(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            curveType(getEccCurveType(ds)),
            priv(ds)
        { }
        BLS_PrivateToPublic_G2(nlohmann::json json) :
            Operation(json["modifier"]),
            curveType(json["curveType"]),
            priv(json["priv"])
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const BLS_PrivateToPublic_G2& rhs) const {
            return
                (curveType == rhs.curveType) &&
                (priv == rhs.priv) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            curveType.Serialize(ds);
            priv.Serialize(ds);
        }
};

class BLS_Sign : public Operation {
    public:
        const component::CurveType curveType;
        const component::BLS_PrivateKey priv;
        const bool hashOrPoint;
        const component::G2 point;
        const component::Cleartext cleartext;
        const component::Cleartext dest;
        const component::Cleartext aug;

        BLS_Sign(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            curveType(getEccCurveType(ds)),
            priv(ds),
            hashOrPoint(ds.Get<bool>()),
            point(ds),
            cleartext(ds),
            dest(ds),
            aug(ds)
        { }
        BLS_Sign(nlohmann::json json) :
            Operation(json["modifier"]),
            curveType(json["curveType"]),
            priv(json["priv"]),
            hashOrPoint(json["hashOrPoint"]),
            point(json["point_v"], json["point_w"], json["point_x"], json["point_y"]),
            cleartext(json["cleartext"]),
            dest(json["dest"]),
            aug(json["aug"])
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const BLS_Sign& rhs) const {
            return
                (curveType == rhs.curveType) &&
                (priv == rhs.priv) &&
                (hashOrPoint == rhs.hashOrPoint) &&
                (point == rhs.point) &&
                (cleartext == rhs.cleartext) &&
                (dest == rhs.dest) &&
                (aug == rhs.aug) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            curveType.Serialize(ds);
            priv.Serialize(ds);
            ds.Put<bool>(hashOrPoint);
            point.Serialize(ds);
            cleartext.Serialize(ds);
            dest.Serialize(ds);
            aug.Serialize(ds);
        }
};

class BLS_Verify : public Operation {
    public:
        const component::CurveType curveType;
        const component::BLS_PublicKey pub;
        const bool hashOrPoint;
        const component::G2 point;
        const component::Cleartext cleartext;
        const component::Cleartext dest;
        const component::G2 signature;

        const uint8_t expected;

        BLS_Verify(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            curveType(getEccCurveType(ds)),
            pub(ds),
            hashOrPoint(ds.Get<bool>()),
            point(ds),
            cleartext(ds),
            dest(ds),
            signature(ds),
            expected(ds.Get<uint8_t>())
        { }
        BLS_Verify(nlohmann::json json) :
            Operation(json["modifier"]),
            curveType(json["curveType"]),
            pub(json["pub_x"], json["pub_y"]),
            hashOrPoint(json["hashOrPoint"]),
            point(json["point_v"], json["point_w"], json["point_x"], json["point_y"]),
            cleartext(json["cleartext"]),
            dest(json["dest"]),
            signature(json["sig_v"], json["sig_w"], json["sig_x"], json["sig_y"]),
            expected(json["expected"].get<uint8_t>())
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const BLS_Verify& rhs) const {
            return
                (curveType == rhs.curveType) &&
                (pub == rhs.pub) &&
                (hashOrPoint == rhs.hashOrPoint) &&
                (point == rhs.point) &&
                (cleartext == rhs.cleartext) &&
                (dest == rhs.dest) &&
                (signature == rhs.signature) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            curveType.Serialize(ds);
            pub.Serialize(ds);
            ds.Put<bool>(hashOrPoint);
            point.Serialize(ds);
            cleartext.Serialize(ds);
            dest.Serialize(ds);
            signature.Serialize(ds);
            ds.Put<>(expected);
        }
};

class BLS_Aggregate_G1 : public Operation {
    public:
        const component::CurveType curveType;
        component::BLS_G1_Vector points;

        BLS_Aggregate_G1(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            curveType(getEccCurveType(ds)),
            points(ds)
        { }
        BLS_Aggregate_G1(nlohmann::json json) :
            Operation(json["modifier"]),
            curveType(json["curveType"]),
            points(json["points"])
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const BLS_Aggregate_G1& rhs) const {
            return
                (curveType == rhs.curveType) &&
                (points == rhs.points) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            curveType.Serialize(ds);
            points.Serialize(ds);
        }
};

class BLS_Aggregate_G2 : public Operation {
    public:
        const component::CurveType curveType;
        component::BLS_G2_Vector points;

        BLS_Aggregate_G2(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            curveType(getEccCurveType(ds)),
            points(ds)
        { }
        BLS_Aggregate_G2(nlohmann::json json) :
            Operation(json["modifier"]),
            curveType(json["curveType"]),
            points(json["points"])
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const BLS_Aggregate_G2& rhs) const {
            return
                (curveType == rhs.curveType) &&
                (points == rhs.points) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            curveType.Serialize(ds);
            points.Serialize(ds);
        }
};

class BLS_Pairing : public Operation {
    public:
        const component::CurveType curveType;
        const component::Cleartext dest;
        component::BLS_PairingComponents components;

        BLS_Pairing(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            curveType(getEccCurveType(ds)),
            dest(ds),
            components(ds)
        { }
        BLS_Pairing(nlohmann::json json) :
            Operation(json["modifier"]),
            curveType(json["curveType"]),
            dest(json["dest"]),
            components(json["components"])
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const BLS_Pairing& rhs) const {
            return
                (curveType == rhs.curveType) &&
                (dest == rhs.dest) &&
                (components == rhs.components) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            curveType.Serialize(ds);
            dest.Serialize(ds);
            components.Serialize(ds);
        }
};

class BLS_HashToG1 : public Operation {
    public:
        const component::CurveType curveType;
        const component::Cleartext cleartext;
        const component::Cleartext dest;
        const component::Cleartext aug;

        BLS_HashToG1(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            curveType(getEccCurveType(ds)),
            cleartext(ds),
            dest(ds),
            aug(ds)
        { }
        BLS_HashToG1(const component::CurveType curveType, const component::Cleartext cleartext, const component::Cleartext dest, const component::Cleartext aug, component::Modifier modifier) :
            Operation(std::move(modifier)),
            curveType(curveType),
            cleartext(cleartext),
            dest(dest),
            aug(aug)
        { }
        BLS_HashToG1(nlohmann::json json) :
            Operation(json["modifier"]),
            curveType(json["curveType"]),
            cleartext(json["cleartext"]),
            dest(json["dest"]),
            aug(json["aug"])
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const BLS_HashToG1& rhs) const {
            return
                (curveType == rhs.curveType) &&
                (cleartext == rhs.cleartext) &&
                (dest == rhs.dest) &&
                (aug == rhs.aug) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            curveType.Serialize(ds);
            cleartext.Serialize(ds);
            dest.Serialize(ds);
            aug.Serialize(ds);
        }
};

class BLS_HashToG2 : public Operation {
    public:
        const component::CurveType curveType;
        const component::Cleartext cleartext;
        const component::Cleartext dest;
        const component::Cleartext aug;

        BLS_HashToG2(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            curveType(getEccCurveType(ds)),
            cleartext(ds),
            dest(ds),
            aug(ds)
        { }
        BLS_HashToG2(const component::CurveType curveType, const component::Cleartext cleartext, const component::Cleartext dest, const component::Cleartext aug, component::Modifier modifier) :
            Operation(std::move(modifier)),
            curveType(curveType),
            cleartext(cleartext),
            dest(dest),
            aug(aug)
        { }
        BLS_HashToG2(nlohmann::json json) :
            Operation(json["modifier"]),
            curveType(json["curveType"]),
            cleartext(json["cleartext"]),
            dest(json["dest"]),
            aug(json["aug"])
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const BLS_HashToG2& rhs) const {
            return
                (curveType == rhs.curveType) &&
                (cleartext == rhs.cleartext) &&
                (dest == rhs.dest) &&
                (aug == rhs.aug) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            curveType.Serialize(ds);
            cleartext.Serialize(ds);
            dest.Serialize(ds);
            aug.Serialize(ds);
        }
};

class BLS_IsG1OnCurve : public Operation {
    public:
        const component::CurveType curveType;
        const component::G1 g1;

        const uint8_t expected;

        BLS_IsG1OnCurve(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            curveType(getEccCurveType(ds)),
            g1(ds),
            expected(ds.Get<uint8_t>())
        { }
        BLS_IsG1OnCurve(nlohmann::json json) :
            Operation(json["modifier"]),
            curveType(json["curveType"]),
            g1(json["g1_x"], json["g1_y"]),
            expected(json["expected"].get<uint8_t>())
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const BLS_IsG1OnCurve& rhs) const {
            return
                (curveType == rhs.curveType) &&
                (g1 == rhs.g1) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            curveType.Serialize(ds);
            g1.Serialize(ds);
            ds.Put<>(expected);
        }
};

class BLS_IsG2OnCurve : public Operation {
    public:
        const component::CurveType curveType;
        const component::G2 g2;

        const uint8_t expected;
        BLS_IsG2OnCurve(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            curveType(getEccCurveType(ds)),
            g2(ds),
            expected(ds.Get<uint8_t>())
        { }
        BLS_IsG2OnCurve(nlohmann::json json) :
            Operation(json["modifier"]),
            curveType(json["curveType"]),
            g2(json["g2_v"], json["g2_w"], json["g2_x"], json["g2_y"]),
            expected(json["expected"].get<uint8_t>())
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const BLS_IsG2OnCurve& rhs) const {
            return
                (curveType == rhs.curveType) &&
                (g2 == rhs.g2) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            curveType.Serialize(ds);
            g2.Serialize(ds);
            ds.Put<>(expected);
        }
};

class BLS_GenerateKeyPair : public Operation {
    public:
        const component::CurveType curveType;
        const component::Cleartext ikm;
        const component::Cleartext info;

        BLS_GenerateKeyPair(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            curveType(getEccCurveType(ds)),
            ikm(ds),
            info(ds)
        { }

        BLS_GenerateKeyPair(nlohmann::json json) :
            Operation(json["modifier"]),
            curveType(json["curveType"]),
            ikm(json["ikm"]),
            info(json["info"])
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const BLS_GenerateKeyPair& rhs) const {
            return
                (curveType == rhs.curveType) &&
                (ikm == rhs.ikm) &&
                (info == rhs.info) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            curveType.Serialize(ds);
            ikm.Serialize(ds);
            info.Serialize(ds);
        }
};

class BLS_Decompress_G1 : public Operation {
    public:
        const component::CurveType curveType;
        const component::Bignum compressed;

        BLS_Decompress_G1(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            curveType(getEccCurveType(ds)),
            compressed(ds)
        { }
        BLS_Decompress_G1(nlohmann::json json) :
            Operation(json["modifier"]),
            curveType(json["curveType"]),
            compressed(json["compressed"])
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const BLS_Decompress_G1& rhs) const {
            return
                (curveType == rhs.curveType) &&
                (compressed == rhs.compressed) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            curveType.Serialize(ds);
            compressed.Serialize(ds);
        }
};

class BLS_Compress_G1 : public Operation {
    public:
        const component::CurveType curveType;
        const component::G1 uncompressed;
        const component::Bignum compressed;
        const uint8_t expected;

        BLS_Compress_G1(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            curveType(getEccCurveType(ds)),
            uncompressed(ds),
            compressed(ds),
            expected(ds.Get<uint8_t>())
        { }
        BLS_Compress_G1(nlohmann::json json) :
            Operation(json["modifier"]),
            curveType(json["curveType"]),
            uncompressed(json["g1_x"], json["g1_y"]),
            compressed(json["compressed"]),
            expected(json["expected"].get<uint8_t>())
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const BLS_Compress_G1& rhs) const {
            return
                (curveType == rhs.curveType) &&
                (uncompressed == rhs.uncompressed) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            curveType.Serialize(ds);
            uncompressed.Serialize(ds);
            compressed.Serialize(ds);
            ds.Put<>(expected);
        }
};

class BLS_Decompress_G2 : public Operation {
    public:
        const component::CurveType curveType;
        const component::G1 compressed;

        BLS_Decompress_G2(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            curveType(getEccCurveType(ds)),
            compressed(ds)
        { }
        BLS_Decompress_G2(nlohmann::json json) :
            Operation(json["modifier"]),
            curveType(json["curveType"]),
            compressed(json["g1_x"], json["g1_y"])
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const BLS_Decompress_G2& rhs) const {
            return
                (curveType == rhs.curveType) &&
                (compressed == rhs.compressed) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            curveType.Serialize(ds);
            compressed.Serialize(ds);
        }
};

class BLS_Compress_G2 : public Operation {
    public:
        const component::CurveType curveType;
        const component::G2 uncompressed;
        const component::G1 compressed;
        const uint8_t expected;


        BLS_Compress_G2(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            curveType(getEccCurveType(ds)),
            uncompressed(ds),
            compressed(ds),
            expected(ds.Get<uint8_t>())
        { }
        BLS_Compress_G2(nlohmann::json json) :
            Operation(json["modifier"]),
            curveType(json["curveType"]),
            uncompressed(json["g2_v"], json["g2_w"], json["g2_x"], json["g2_y"]),
            compressed(json["compressed_x"], json["compressed_y"]),
            expected(json["expected"].get<uint8_t>())
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const BLS_Compress_G2& rhs) const {
            return
                (curveType == rhs.curveType) &&
                (uncompressed == rhs.uncompressed) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            curveType.Serialize(ds);
            uncompressed.Serialize(ds);
            compressed.Serialize(ds);
            ds.Put<>(expected);
        }
};

class BLS_G1_Add : public Operation {
    public:
        const component::CurveType curveType;
        const component::G1 a, b;

        BLS_G1_Add(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            curveType(getEccCurveType(ds)),
            a(ds),
            b(ds)
        { }
        BLS_G1_Add(nlohmann::json json) :
            Operation(json["modifier"]),
            curveType(json["curveType"]),
            a(json["a_x"], json["a_y"]),
            b(json["b_x"], json["b_y"])
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const BLS_G1_Add& rhs) const {
            return
                (curveType == rhs.curveType) &&
                (a == rhs.a) &&
                (b == rhs.b) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            curveType.Serialize(ds);
            a.Serialize(ds);
            b.Serialize(ds);
        }
};

class BLS_G1_IsEq : public Operation {
    public:
        const component::CurveType curveType;
        const component::G1 a, b;

        BLS_G1_IsEq(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            curveType(getEccCurveType(ds)),
            a(ds),
            b(ds)
        { }
        BLS_G1_IsEq(nlohmann::json json) :
            Operation(json["modifier"]),
            curveType(json["curveType"]),
            a(json["a_x"], json["a_y"]),
            b(json["b_x"], json["b_y"])
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const BLS_G1_IsEq& rhs) const {
            return
                (curveType == rhs.curveType) &&
                (a == rhs.a) &&
                (b == rhs.b) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            curveType.Serialize(ds);
            a.Serialize(ds);
            b.Serialize(ds);
        }
};

class BLS_G1_Mul : public Operation {
    public:
        const component::CurveType curveType;
        const component::G1 a;
        const component::Bignum b;

        BLS_G1_Mul(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            curveType(getEccCurveType(ds)),
            a(ds),
            b(ds)
        { }
        BLS_G1_Mul(nlohmann::json json) :
            Operation(json["modifier"]),
            curveType(json["curveType"]),
            a(json["a_x"], json["a_y"]),
            b(json["b"])
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const BLS_G1_Mul& rhs) const {
            return
                (curveType == rhs.curveType) &&
                (a == rhs.a) &&
                (b == rhs.b) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            curveType.Serialize(ds);
            a.Serialize(ds);
            b.Serialize(ds);
        }
};

class BLS_G1_Neg : public Operation {
    public:
        const component::CurveType curveType;
        const component::G1 a;

        BLS_G1_Neg(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            curveType(getEccCurveType(ds)),
            a(ds)
        { }
        BLS_G1_Neg(nlohmann::json json) :
            Operation(json["modifier"]),
            curveType(json["curveType"]),
            a(json["a_x"], json["a_y"])
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const BLS_G1_Neg& rhs) const {
            return
                (curveType == rhs.curveType) &&
                (a == rhs.a) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            curveType.Serialize(ds);
            a.Serialize(ds);
        }
};

class BLS_G2_Add : public Operation {
    public:
        const component::CurveType curveType;
        const component::G2 a, b;

        BLS_G2_Add(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            curveType(getEccCurveType(ds)),
            a(ds),
            b(ds)
        { }
        BLS_G2_Add(nlohmann::json json) :
            Operation(json["modifier"]),
            curveType(json["curveType"]),
            a(json["a_v"], json["a_w"], json["a_x"], json["a_y"]),
            b(json["b_v"], json["b_w"], json["b_x"], json["b_y"])
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const BLS_G2_Add& rhs) const {
            return
                (curveType == rhs.curveType) &&
                (a == rhs.a) &&
                (b == rhs.b) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            curveType.Serialize(ds);
            a.Serialize(ds);
            b.Serialize(ds);
        }
};

class BLS_G2_IsEq : public Operation {
    public:
        const component::CurveType curveType;
        const component::G2 a, b;

        BLS_G2_IsEq(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            curveType(getEccCurveType(ds)),
            a(ds),
            b(ds)
        { }
        BLS_G2_IsEq(nlohmann::json json) :
            Operation(json["modifier"]),
            curveType(json["curveType"]),
            a(json["a_v"], json["a_w"], json["a_x"], json["a_y"]),
            b(json["b_v"], json["b_w"], json["b_x"], json["b_y"])
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const BLS_G2_IsEq& rhs) const {
            return
                (curveType == rhs.curveType) &&
                (a == rhs.a) &&
                (b == rhs.b) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            curveType.Serialize(ds);
            a.Serialize(ds);
            b.Serialize(ds);
        }
};

class BLS_G2_Mul : public Operation {
    public:
        const component::CurveType curveType;
        const component::G2 a;
        const component::Bignum b;

        BLS_G2_Mul(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            curveType(getEccCurveType(ds)),
            a(ds),
            b(ds)
        { }
        BLS_G2_Mul(nlohmann::json json) :
            Operation(json["modifier"]),
            curveType(json["curveType"]),
            a(json["a_v"], json["a_w"], json["a_x"], json["a_y"]),
            b(json["b"])
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const BLS_G2_Mul& rhs) const {
            return
                (curveType == rhs.curveType) &&
                (a == rhs.a) &&
                (b == rhs.b) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            curveType.Serialize(ds);
            a.Serialize(ds);
            b.Serialize(ds);
        }
};

class BLS_G2_Neg : public Operation {
    public:
        const component::CurveType curveType;
        const component::G2 a;

        BLS_G2_Neg(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            curveType(getEccCurveType(ds)),
            a(ds)
        { }
        BLS_G2_Neg(nlohmann::json json) :
            Operation(json["modifier"]),
            curveType(json["curveType"]),
            a(json["a_v"], json["a_w"], json["a_x"], json["a_y"])
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const BLS_G2_Neg& rhs) const {
            return
                (curveType == rhs.curveType) &&
                (a == rhs.a) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            curveType.Serialize(ds);
            a.Serialize(ds);
        }
};

class Misc : public Operation {
    public:
        const Type operation;

        Misc(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            operation(ds)
        { }

        Misc(nlohmann::json json) :
            Operation(json["modifier"]),
            operation(json["operation"])
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const Misc& rhs) const {
            return
                (operation == rhs.operation) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            operation.Serialize(ds);
        }
};

class SR25519_Verify : public Operation {
    public:
        const component::Cleartext cleartext;
        const component::SR25519_Signature signature;

        SR25519_Verify(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            cleartext(ds),
            signature(ds)
        { }
        SR25519_Verify(nlohmann::json json) :
            Operation(json["modifier"]),
            cleartext(json["cleartext"]),
            signature(json["signature"])
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const SR25519_Verify& rhs) const {
            return
                (cleartext == rhs.cleartext) &&
                (signature == rhs.signature) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            cleartext.Serialize(ds);
            signature.Serialize(ds);
        }
};

} /* namespace operation */
} /* namespace cryptofuzz */
