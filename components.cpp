#include <cryptofuzz/crypto.h>
#include <cryptofuzz/generic.h>
#include <cryptofuzz/components.h>
#include <cryptofuzz/util.h>
#include <boost/multiprecision/cpp_int.hpp>
#include <cryptofuzz/repository.h>
#include "third_party/json/json.hpp"
#include "config.h"
#include <map>

using namespace std;

namespace cryptofuzz {

/* Type */

Type::Type(Datasource& ds) :
    type ( ds.Get<uint64_t>(0) )
{ }

Type::Type(const Type& other) :
    type(other.type)
{ }

Type::Type(nlohmann::json json) :
    type(json.get<uint64_t>())
{ }

Type::Type(const uint64_t t) :
    type(t)
{ }

uint64_t Type::Get(void) const {
    return type;
}

bool Type::Is(const uint64_t t) const {
    return type == t;
}

bool Type::Is(const std::vector<uint64_t> t) const {
    return std::find(t.begin(), t.end(), type) != t.end();
}

nlohmann::json Type::ToJSON(void) const {
    nlohmann::json j;
    /* Store as string, not as number, because JavaScript's number
     * type has only 53 bits of precision.
     */
    j = std::to_string(type);
    return j;
}

bool Type::operator==(const Type& rhs) const {
    return type == rhs.type;
}

void Type::Serialize(Datasource& ds) const {
    ds.Put<>(type);
}

/* Buffer */

Buffer::Buffer(Datasource& ds) :
    data( ds.GetData(0, 0, (10*1024*1024)) )
{ }

Buffer::Buffer(nlohmann::json json) {
    const auto s = json.get<std::string>();
    boost::algorithm::unhex(s, std::back_inserter(data));
}

Buffer::Buffer(const std::vector<uint8_t>& data) :
    data(data)
{ }

Buffer::Buffer(const uint8_t* data, const size_t size) :
    data(data, data + size)
{ }

Buffer::Buffer(void) { }

std::vector<uint8_t> Buffer::Get(void) const {
    return data;
}

const uint8_t* Buffer::GetPtr(fuzzing::datasource::Datasource* ds) const {
    if ( data.size() == 0 ) {
        return util::GetNullPtr(ds);
    } else {
        return data.data();
    }
}

std::vector<uint8_t>& Buffer::GetVectorPtr(void) {
    return data;
}

const std::vector<uint8_t>& Buffer::GetConstVectorPtr(void) const {
    return data;
}

size_t Buffer::GetSize(void) const {
    return data.size();
}

bool Buffer::operator==(const Buffer& rhs) const {
    return data == rhs.data;
}

nlohmann::json Buffer::ToJSON(void) const {
    nlohmann::json j;
    std::string asHex;
    boost::algorithm::hex(data, std::back_inserter(asHex));
    j = asHex;
    return j;
}

std::string Buffer::ToHex(void) const {
    std::string asHex;
    boost::algorithm::hex(data, std::back_inserter(asHex));
    return asHex;
}

void Buffer::Serialize(Datasource& ds) const {
    ds.PutData(data);
}

Datasource Buffer::AsDatasource(void) const {
    return Datasource(data.data(), data.size());
}

std::string Buffer::AsString(void) const {
    return std::string(data.data(), data.data() + data.size());
}

Buffer Buffer::ECDSA_Pad(const size_t retSize) const {
    size_t bufSize = GetSize();

    if ( bufSize > retSize ) {
        bufSize = retSize;
    }

    std::vector<uint8_t> ret(retSize);

    if ( retSize != 0 ) {
        const size_t delta = retSize - bufSize;

        if ( delta != 0 ) {
            memset(ret.data(), 0, delta);
        }

        if ( bufSize != 0 ) {
            memcpy(ret.data() + delta, GetPtr(), bufSize);
        }
    }

    return Buffer(ret);
}

/* Randomly modify an ECDSA input in such a way that it remains equivalent
 * to ECDSA verify/sign functions
 */
Buffer Buffer::ECDSA_RandomPad(Datasource& ds, const Type& curveType) const {
    return Buffer(data);
    // const auto numBits = cryptofuzz::repository::ECC_CurveToBits(curveType.Get());
    // if ( numBits == std::nullopt ) {
    //     /* The size of this curve is not known, so return the original buffer */
    //     return Buffer(data);
    // }

    // if ( *numBits % 8 != 0 ) {
    //     /* Curve sizes which are not a byte multiple are currently not supported,
    //      * so return the original buffer
    //      */
    //     return Buffer(data);
    // }

    // const size_t numBytes = (*numBits + 7) / 8;

    // std::vector<uint8_t> stripped;
    // {
    //     size_t startPos;
    //     const size_t endPos = GetSize() > numBytes ? numBytes : GetSize();

    //     for (startPos = 0; startPos < endPos; startPos++) {
    //         if ( data[startPos] != 0 ) {
    //             break;
    //         }
    //     }
    //     const auto& ref = GetConstVectorPtr();

    //     stripped.insert(std::end(stripped), std::begin(ref) + startPos, std::begin(ref) + endPos);
    // }

    // /* Decide how many bytes to insert */
    // uint16_t numInserts = 0;
    // try {
    //     numInserts = ds.Get<uint16_t>();
    // } catch ( fuzzing::datasource::Datasource::OutOfData ) { }

    // std::vector<uint8_t> ret;

    // /* Left-pad the input until it is the curve size */
    // {
    //     if ( stripped.size() < numBytes ) {
    //         const size_t needed = numBytes - stripped.size();
    //         const std::vector<uint8_t> zeroes(numInserts > needed ? needed : numInserts, 0);
    //         ret.insert(std::end(ret), std::begin(zeroes), std::end(zeroes));
    //         numInserts -= zeroes.size();
    //     }
    // }

    // /* Insert the input */
    // ret.insert(std::end(ret), std::begin(stripped), std::end(stripped));

    // /* Right-pad the input with random bytes (if available) or zeroes */
    // if ( numInserts > 0 ) {
    //     std::vector<uint8_t> toInsert;
    //     try {
    //         toInsert = ds.GetData(0, numInserts, numInserts);
    //     } catch ( fuzzing::datasource::Datasource::OutOfData ) {
    //         toInsert = std::vector<uint8_t>(numInserts, 0);
    //     }
    //     ret.insert(std::end(ret), std::begin(toInsert), std::end(toInsert));
    // }

    // return Buffer(ret);
}

Buffer Buffer::SHA256(void) const {
    const auto hash = crypto::sha256(Get());
    return Buffer(hash);
}

bool Buffer::IsZero(void) const {
    for (size_t i = 0; i < data.size(); i++) {
        if ( data[i] != 0 ) {
            return false;
        }
    }

    return true;
}

/* Bignum */

Bignum::Bignum(Datasource& ds) :
    data(ds) {
    transform();
}

Bignum::Bignum(nlohmann::json json) :
    Bignum(json.get<std::string>())
{
}

Bignum::Bignum(const std::string s) :
    data((const uint8_t*)s.data(), s.size())
{ }

void Bignum::transform(void) {
    auto& ptr = data.GetVectorPtr();

    for (size_t i = 0; i < ptr.size(); i++) {
        if ( isdigit(ptr[i]) ) continue;
        if ( config::kNegativeIntegers == true ) {
            if ( i == 0 && ptr[i] == '-') continue;
        }
        ptr[i] %= 10;
        ptr[i] += '0';
    }
}

bool Bignum::operator==(const Bignum& rhs) const {
    return data == rhs.data;
}

size_t Bignum::GetSize(void) const {
    return data.GetSize();
}

bool Bignum::IsNegative(void) const {
    return data.GetSize() && data.GetConstVectorPtr()[0] == '-';
}

bool Bignum::IsGreaterThan(const std::string& other) const {
    CF_ASSERT(IsNegative() == false, "IsGreaterThan on negative numbers not supported");
    const auto s = ToTrimmedString();
    if ( s.size() > other.size() ) {
        return true;
    } else if ( s.size() < other.size() ) {
        return false;
    } else {
        for (size_t i = 0; i < s.size(); i++) {
            const int a = s[i];
            const int b = other[i];
            if ( a > b ) {
                return true;
            } else if ( a < b ) {
                return false;
            }
        }
    }

    CF_ASSERT(s == other, "Logic error");
    return false;
}

bool Bignum::IsLessThan(const std::string& other) const {
    boost::multiprecision::cpp_int A(ToTrimmedString());
    boost::multiprecision::cpp_int B(other);
    return A < B;
}

std::string Bignum::ToString(void) const {
    const auto ptr = data.GetPtr();
    return std::string(ptr, ptr + data.GetSize());
}

std::string Bignum::ToTrimmedString(void) const {
    auto s = ToString();
    trim_left_if(s, boost::is_any_of("0"));

    if ( s == "" ) {
        return "0";
    } else {
        return s;
    }
}

/* Prefix the string with a pseudo-random amount of zeroes */
std::string Bignum::ToString(Datasource& ds) const {
    std::string zeros;

    try {
        while ( ds.Get<bool>() == true ) {
            zeros += "0";
        }
    } catch ( fuzzing::datasource::Datasource::OutOfData ) { }

    auto s = ToTrimmedString();
    const bool isNegative = IsNegative();
    if ( s.size() && s[0] == '-' ) {
        s.erase(0, 1);
    }
    return (isNegative ? "-" : "") + zeros + s;
}

nlohmann::json Bignum::ToJSON(void) const {
    return ToString();
}

void Bignum::Serialize(Datasource& ds) const {
    data.Serialize(ds);
}

static map <uint64_t, bool> Ciphers = {
            {CF_CIPHER("AES"), false},
            {CF_CIPHER("AES_128_CBC"), false},
            {CF_CIPHER("AES_128_CBC_HMAC_SHA1"), false},
            {CF_CIPHER("AES_128_CBC_HMAC_SHA256"), false},
            {CF_CIPHER("AES_128_CCM"), false},
            {CF_CIPHER("AES_128_CFB"), false},
            {CF_CIPHER("AES_128_CFB1"), false},
            {CF_CIPHER("AES_128_CFB128"), false},
            {CF_CIPHER("AES_128_CFB8"), false},
            {CF_CIPHER("AES_128_CTR"), false},
            {CF_CIPHER("AES_128_ECB"), false},
            {CF_CIPHER("AES_128_OCB"), false},
            {CF_CIPHER("AES_128_OFB"), false},
            {CF_CIPHER("AES_128_WRAP"), false},
            {CF_CIPHER("AES_128_WRAP_PAD"), false},
            {CF_CIPHER("AES_128_XTS"), false},
            {CF_CIPHER("AES_192_CBC"), false},
            {CF_CIPHER("AES_192_CCM"), false},
            {CF_CIPHER("AES_192_CFB"), false},
            {CF_CIPHER("AES_192_CFB1"), false},
            {CF_CIPHER("AES_192_CFB128"), false},
            {CF_CIPHER("AES_192_CFB8"), false},
            {CF_CIPHER("AES_192_CTR"), false},
            {CF_CIPHER("AES_192_ECB"), false},
            {CF_CIPHER("AES_192_OFB"), false},
            {CF_CIPHER("AES_192_WRAP"), false},
            {CF_CIPHER("AES_192_WRAP_PAD"), false},
            {CF_CIPHER("AES_192_XTS"), false},
            {CF_CIPHER("AES_256_CBC"), false},
            {CF_CIPHER("AES_256_CBC_HMAC_SHA1"), false},
            {CF_CIPHER("AES_256_CCM"), false},
            {CF_CIPHER("AES_256_CFB"), false},
            {CF_CIPHER("AES_256_CFB1"), false},
            {CF_CIPHER("AES_256_CFB128"), false},
            {CF_CIPHER("AES_256_CFB8"), false},
            {CF_CIPHER("AES_256_CTR"), false},
            {CF_CIPHER("AES_256_ECB"), false},
            {CF_CIPHER("AES_256_OCB"), false},
            {CF_CIPHER("AES_256_OFB"), false},
            {CF_CIPHER("AES_256_WRAP"), false},
            {CF_CIPHER("AES_256_WRAP_PAD"), false},
            {CF_CIPHER("AES_256_XTS"), false},
            {CF_CIPHER("AES_512_XTS"), false},
            {CF_CIPHER("ANUBIS_CBC"), false},
            {CF_CIPHER("ANUBIS_CFB"), false},
            {CF_CIPHER("ANUBIS_CTR"), false},
            {CF_CIPHER("ANUBIS_ECB"), false},
            {CF_CIPHER("ANUBIS_OFB"), false},
            {CF_CIPHER("ARIA_128_CBC"), false},
            {CF_CIPHER("ARIA_128_CCM"), false},
            {CF_CIPHER("ARIA_128_CFB"), false},
            {CF_CIPHER("ARIA_128_CFB1"), false},
            {CF_CIPHER("ARIA_128_CFB128"), false},
            {CF_CIPHER("ARIA_128_CFB8"), false},
            {CF_CIPHER("ARIA_128_CTR"), false},
            {CF_CIPHER("ARIA_128_ECB"), false},
            {CF_CIPHER("ARIA_128_OFB"), false},
            {CF_CIPHER("ARIA_192_CBC"), false},
            {CF_CIPHER("ARIA_192_CCM"), false},
            {CF_CIPHER("ARIA_192_CFB"), false},
            {CF_CIPHER("ARIA_192_CFB1"), false},
            {CF_CIPHER("ARIA_192_CFB128"), false},
            {CF_CIPHER("ARIA_192_CFB8"), false},
            {CF_CIPHER("ARIA_192_CTR"), false},
            {CF_CIPHER("ARIA_192_ECB"), false},
            {CF_CIPHER("ARIA_192_OFB"), false},
            {CF_CIPHER("ARIA_256_CBC"), false},
            {CF_CIPHER("ARIA_256_CCM"), false},
            {CF_CIPHER("ARIA_256_CFB"), false},
            {CF_CIPHER("ARIA_256_CFB1"), false},
            {CF_CIPHER("ARIA_256_CFB128"), false},
            {CF_CIPHER("ARIA_256_CFB8"), false},
            {CF_CIPHER("ARIA_256_CTR"), false},
            {CF_CIPHER("ARIA_256_ECB"), false},
            {CF_CIPHER("ARIA_256_OFB"), false},
            {CF_CIPHER("BF_CBC"), false},
            {CF_CIPHER("BF_CFB"), false},
            {CF_CIPHER("BF_ECB"), false},
            {CF_CIPHER("BF_OFB"), false},
            {CF_CIPHER("BLOWFISH_CBC"), false},
            {CF_CIPHER("BLOWFISH_CFB"), false},
            {CF_CIPHER("BLOWFISH_CFB64"), false},
            {CF_CIPHER("BLOWFISH_CTR"), false},
            {CF_CIPHER("BLOWFISH_ECB"), false},
            {CF_CIPHER("BLOWFISH_OFB"), false},
            {CF_CIPHER("CAMELLIA_128_CBC"), false},
            {CF_CIPHER("CAMELLIA_128_CFB"), false},
            {CF_CIPHER("CAMELLIA_128_CFB1"), false},
            {CF_CIPHER("CAMELLIA_128_CFB128"), false},
            {CF_CIPHER("CAMELLIA_128_CFB8"), false},
            {CF_CIPHER("CAMELLIA_128_CTR"), false},
            {CF_CIPHER("CAMELLIA_128_ECB"), false},
            {CF_CIPHER("CAMELLIA_128_OFB"), false},
            {CF_CIPHER("CAMELLIA_192_CBC"), false},
            {CF_CIPHER("CAMELLIA_192_CFB"), false},
            {CF_CIPHER("CAMELLIA_192_CFB1"), false},
            {CF_CIPHER("CAMELLIA_192_CFB128"), false},
            {CF_CIPHER("CAMELLIA_192_CFB8"), false},
            {CF_CIPHER("CAMELLIA_192_CTR"), false},
            {CF_CIPHER("CAMELLIA_192_ECB"), false},
            {CF_CIPHER("CAMELLIA_192_OFB"), false},
            {CF_CIPHER("CAMELLIA_256_CBC"), false},
            {CF_CIPHER("CAMELLIA_256_CFB"), false},
            {CF_CIPHER("CAMELLIA_256_CFB1"), false},
            {CF_CIPHER("CAMELLIA_256_CFB128"), false},
            {CF_CIPHER("CAMELLIA_256_CFB8"), false},
            {CF_CIPHER("CAMELLIA_256_CTR"), false},
            {CF_CIPHER("CAMELLIA_256_ECB"), false},
            {CF_CIPHER("CAMELLIA_256_OFB"), false},
            {CF_CIPHER("CAST5_CBC"), false},
            {CF_CIPHER("CAST5_CFB"), false},
            {CF_CIPHER("CAST5_CTR"), false},
            {CF_CIPHER("CAST5_ECB"), false},
            {CF_CIPHER("CAST5_OFB"), false},
            {CF_CIPHER("CHACHA20"), false},
            {CF_CIPHER("CHAM128_CBC"), false},
            {CF_CIPHER("CHAM128_CFB"), false},
            {CF_CIPHER("CHAM128_CTR"), false},
            {CF_CIPHER("CHAM128_ECB"), false},
            {CF_CIPHER("CHAM128_OFB"), false},
            {CF_CIPHER("CHAM64_CBC"), false},
            {CF_CIPHER("CHAM64_CFB"), false},
            {CF_CIPHER("CHAM64_CTR"), false},
            {CF_CIPHER("CHAM64_ECB"), false},
            {CF_CIPHER("CHAM64_OFB"), false},
            {CF_CIPHER("DES3_CBC"), false},
            {CF_CIPHER("DESX_A_CBC"), false},
            {CF_CIPHER("DESX_B_CBC"), false},
            {CF_CIPHER("DES_CBC"), false},
            {CF_CIPHER("DES_CFB"), false},
            {CF_CIPHER("DES_CFB1"), false},
            {CF_CIPHER("DES_CFB8"), false},
            {CF_CIPHER("DES_CTR"), false},
            {CF_CIPHER("DES_ECB"), false},
            {CF_CIPHER("DES_EDE"), false},
            {CF_CIPHER("DES_EDE3"), false},
            {CF_CIPHER("DES_EDE3_CBC"), false},
            {CF_CIPHER("DES_EDE3_CFB"), false},
            {CF_CIPHER("DES_EDE3_CFB1"), false},
            {CF_CIPHER("DES_EDE3_CFB8"), false},
            {CF_CIPHER("DES_EDE3_ECB"), false},
            {CF_CIPHER("DES_EDE3_OFB"), false},
            {CF_CIPHER("DES_EDE3_WRAP"), false},
            {CF_CIPHER("DES_EDE_CBC"), false},
            {CF_CIPHER("DES_EDE_CFB"), false},
            {CF_CIPHER("DES_EDE_ECB"), false},
            {CF_CIPHER("DES_EDE_OFB"), false},
            {CF_CIPHER("DES_OFB"), false},
            {CF_CIPHER("GMAC_128"), false},
            {CF_CIPHER("GMAC_192"), false},
            {CF_CIPHER("GMAC_256"), false},
            {CF_CIPHER("GOST-28147-89"), false},
            {CF_CIPHER("GOST-28147-89_CBC"), false},
            {CF_CIPHER("HC128"), false},
            {CF_CIPHER("HIGHT_CBC"), false},
            {CF_CIPHER("HIGHT_CFB"), false},
            {CF_CIPHER("HIGHT_CTR"), false},
            {CF_CIPHER("HIGHT_ECB"), false},
            {CF_CIPHER("HIGHT_OFB"), false},
            {CF_CIPHER("IDEA_CBC"), false},
            {CF_CIPHER("IDEA_CFB"), false},
            {CF_CIPHER("IDEA_CTR"), false},
            {CF_CIPHER("IDEA_ECB"), false},
            {CF_CIPHER("IDEA_OFB"), false},
            {CF_CIPHER("KALYNA128_CBC"), false},
            {CF_CIPHER("KALYNA128_CFB"), false},
            {CF_CIPHER("KALYNA128_CFB8"), false},
            {CF_CIPHER("KALYNA128_CTR"), false},
            {CF_CIPHER("KALYNA128_ECB"), false},
            {CF_CIPHER("KALYNA128_OFB"), false},
            {CF_CIPHER("KALYNA256_CBC"), false},
            {CF_CIPHER("KALYNA256_CFB"), false},
            {CF_CIPHER("KALYNA256_CFB8"), false},
            {CF_CIPHER("KALYNA256_CTR"), false},
            {CF_CIPHER("KALYNA256_ECB"), false},
            {CF_CIPHER("KALYNA256_OFB"), false},
            {CF_CIPHER("KALYNA512_CBC"), false},
            {CF_CIPHER("KALYNA512_CFB"), false},
            {CF_CIPHER("KALYNA512_CFB8"), false},
            {CF_CIPHER("KALYNA512_CTR"), false},
            {CF_CIPHER("KALYNA512_ECB"), false},
            {CF_CIPHER("KALYNA512_OFB"), false},
            {CF_CIPHER("KASUMI_CBC"), false},
            {CF_CIPHER("KASUMI_CFB"), false},
            {CF_CIPHER("KASUMI_CTR"), false},
            {CF_CIPHER("KASUMI_ECB"), false},
            {CF_CIPHER("KASUMI_OFB"), false},
            {CF_CIPHER("KASUMI_XTS"), false},
            {CF_CIPHER("KHAZAD_CBC"), false},
            {CF_CIPHER("KHAZAD_CFB"), false},
            {CF_CIPHER("KHAZAD_CTR"), false},
            {CF_CIPHER("KHAZAD_ECB"), false},
            {CF_CIPHER("KHAZAD_OFB"), false},
            {CF_CIPHER("KUZNYECHIK"), false},
            {CF_CIPHER("LEA_CBC"), false},
            {CF_CIPHER("LEA_CFB"), false},
            {CF_CIPHER("LEA_CTR"), false},
            {CF_CIPHER("LEA_ECB"), false},
            {CF_CIPHER("LEA_OFB"), false},
            {CF_CIPHER("MISTY1_CBC"), false},
            {CF_CIPHER("MISTY1_CTR"), false},
            {CF_CIPHER("MISTY1_OFB"), false},
            {CF_CIPHER("MISTY1_XTS"), false},
            {CF_CIPHER("NOEKEON_CBC"), false},
            {CF_CIPHER("NOEKEON_CFB"), false},
            {CF_CIPHER("NOEKEON_CTR"), false},
            {CF_CIPHER("NOEKEON_DIRECT_CBC"), false},
            {CF_CIPHER("NOEKEON_DIRECT_CFB"), false},
            {CF_CIPHER("NOEKEON_DIRECT_CTR"), false},
            {CF_CIPHER("NOEKEON_DIRECT_ECB"), false},
            {CF_CIPHER("NOEKEON_DIRECT_OFB"), false},
            {CF_CIPHER("NOEKEON_DIRECT_XTS"), false},
            {CF_CIPHER("NOEKEON_ECB"), false},
            {CF_CIPHER("NOEKEON_OFB"), false},
            {CF_CIPHER("NOEKEON_XTS"), false},
            {CF_CIPHER("RABBIT"), false},
            {CF_CIPHER("RC2_40_CBC"), false},
            {CF_CIPHER("RC2_64_CBC"), false},
            {CF_CIPHER("RC2_CBC"), false},
            {CF_CIPHER("RC2_CFB"), false},
            {CF_CIPHER("RC2_CTR"), false},
            {CF_CIPHER("RC2_ECB"), false},
            {CF_CIPHER("RC2_OFB"), false},
            {CF_CIPHER("RC4"), false},
            {CF_CIPHER("RC4_40"), false},
            {CF_CIPHER("RC4_HMAC_MD5"), false},
            {CF_CIPHER("RC5_32_12_16_CBC"), false},
            {CF_CIPHER("RC5_32_12_16_CFB"), false},
            {CF_CIPHER("RC5_32_12_16_ECB"), false},
            {CF_CIPHER("RC5_32_12_16_OFB"), false},
            {CF_CIPHER("RC5_CBC"), false},
            {CF_CIPHER("RC5_CFB"), false},
            {CF_CIPHER("RC5_CTR"), false},
            {CF_CIPHER("RC5_ECB"), false},
            {CF_CIPHER("RC5_OFB"), false},
            {CF_CIPHER("RC6_CBC"), false},
            {CF_CIPHER("RC6_CFB"), false},
            {CF_CIPHER("RC6_CTR"), false},
            {CF_CIPHER("RC6_ECB"), false},
            {CF_CIPHER("RC6_OFB"), false},
            {CF_CIPHER("SAFER_K_CBC"), false},
            {CF_CIPHER("SAFER_K_CFB"), false},
            {CF_CIPHER("SAFER_K_CTR"), false},
            {CF_CIPHER("SAFER_K_ECB"), false},
            {CF_CIPHER("SAFER_K_OFB"), false},
            {CF_CIPHER("SAFER_SK_CBC"), false},
            {CF_CIPHER("SAFER_SK_CFB"), false},
            {CF_CIPHER("SAFER_SK_CTR"), false},
            {CF_CIPHER("SAFER_SK_ECB"), false},
            {CF_CIPHER("SAFER_SK_OFB"), false},
            {CF_CIPHER("SALSA20_128"), false},
            {CF_CIPHER("SALSA20_12_128"), false},
            {CF_CIPHER("SALSA20_12_256"), false},
            {CF_CIPHER("SALSA20_256"), false},
            {CF_CIPHER("SEED_CBC"), false},
            {CF_CIPHER("SEED_CFB"), false},
            {CF_CIPHER("SEED_CTR"), false},
            {CF_CIPHER("SEED_ECB"), false},
            {CF_CIPHER("SEED_OFB"), false},
            {CF_CIPHER("SERPENT"), false},
            {CF_CIPHER("SERPENT_CBC"), false},
            {CF_CIPHER("SERPENT_CFB"), false},
            {CF_CIPHER("SERPENT_CTR"), false},
            {CF_CIPHER("SERPENT_ECB"), false},
            {CF_CIPHER("SERPENT_OFB"), false},
            {CF_CIPHER("SERPENT_XTS"), false},
            {CF_CIPHER("SHACAL2_CBC"), false},
            {CF_CIPHER("SHACAL2_CFB"), false},
            {CF_CIPHER("SHACAL2_CTR"), false},
            {CF_CIPHER("SHACAL2_OFB"), false},
            {CF_CIPHER("SHACAL2_XTS"), false},
            {CF_CIPHER("SHARK_CBC"), false},
            {CF_CIPHER("SHARK_CFB"), false},
            {CF_CIPHER("SHARK_CTR"), false},
            {CF_CIPHER("SHARK_ECB"), false},
            {CF_CIPHER("SHARK_OFB"), false},
            {CF_CIPHER("SIMECK32_CBC"), false},
            {CF_CIPHER("SIMECK32_CFB"), false},
            {CF_CIPHER("SIMECK32_CTR"), false},
            {CF_CIPHER("SIMECK32_ECB"), false},
            {CF_CIPHER("SIMECK32_OFB"), false},
            {CF_CIPHER("SIMECK64_CBC"), false},
            {CF_CIPHER("SIMECK64_CFB"), false},
            {CF_CIPHER("SIMECK64_CTR"), false},
            {CF_CIPHER("SIMECK64_ECB"), false},
            {CF_CIPHER("SIMECK64_OFB"), false},
            {CF_CIPHER("SIMON128_CBC"), false},
            {CF_CIPHER("SIMON128_CFB"), false},
            {CF_CIPHER("SIMON128_CTR"), false},
            {CF_CIPHER("SIMON128_ECB"), false},
            {CF_CIPHER("SIMON128_OFB"), false},
            {CF_CIPHER("SIMON64_CBC"), false},
            {CF_CIPHER("SIMON64_CFB"), false},
            {CF_CIPHER("SIMON64_CTR"), false},
            {CF_CIPHER("SIMON64_ECB"), false},
            {CF_CIPHER("SIMON64_OFB"), false},
            {CF_CIPHER("SKIPJACK_CBC"), false},
            {CF_CIPHER("SKIPJACK_CFB"), false},
            {CF_CIPHER("SKIPJACK_CTR"), false},
            {CF_CIPHER("SKIPJACK_ECB"), false},
            {CF_CIPHER("SKIPJACK_OFB"), false},
            {CF_CIPHER("SM4_CBC"), false},
            {CF_CIPHER("SM4_CFB"), false},
            {CF_CIPHER("SM4_CTR"), false},
            {CF_CIPHER("SM4_ECB"), false},
            {CF_CIPHER("SM4_OFB"), false},
            {CF_CIPHER("SOBER128"), false},
            {CF_CIPHER("SOSEMANUK"), false},
            {CF_CIPHER("SPECK128_CBC"), false},
            {CF_CIPHER("SPECK128_CFB"), false},
            {CF_CIPHER("SPECK128_CTR"), false},
            {CF_CIPHER("SPECK128_ECB"), false},
            {CF_CIPHER("SPECK128_OFB"), false},
            {CF_CIPHER("SPECK64_CBC"), false},
            {CF_CIPHER("SPECK64_CFB"), false},
            {CF_CIPHER("SPECK64_CTR"), false},
            {CF_CIPHER("SPECK64_ECB"), false},
            {CF_CIPHER("SPECK64_OFB"), false},
            {CF_CIPHER("SQUARE_CBC"), false},
            {CF_CIPHER("SQUARE_CFB"), false},
            {CF_CIPHER("SQUARE_CTR"), false},
            {CF_CIPHER("SQUARE_ECB"), false},
            {CF_CIPHER("SQUARE_OFB"), false},
            {CF_CIPHER("TEA_CBC"), false},
            {CF_CIPHER("TEA_CFB"), false},
            {CF_CIPHER("TEA_CTR"), false},
            {CF_CIPHER("TEA_ECB"), false},
            {CF_CIPHER("TEA_OFB"), false},
            {CF_CIPHER("THREEFISH_512_CBC"), false},
            {CF_CIPHER("THREEFISH_512_CFB"), false},
            {CF_CIPHER("THREEFISH_512_CTR"), false},
            {CF_CIPHER("THREEFISH_512_OFB"), false},
            {CF_CIPHER("THREEFISH_512_XTS"), false},
            {CF_CIPHER("TWOFISH"), false},
            {CF_CIPHER("TWOFISH_CBC"), false},
            {CF_CIPHER("TWOFISH_CFB"), false},
            {CF_CIPHER("TWOFISH_CTR"), false},
            {CF_CIPHER("TWOFISH_ECB"), false},
            {CF_CIPHER("TWOFISH_OFB"), false},
            {CF_CIPHER("TWOFISH_XTS"), false},
            {CF_CIPHER("XTEA_CBC"), false},
            {CF_CIPHER("XTEA_CFB"), false},
            {CF_CIPHER("XTEA_CTR"), false},
            {CF_CIPHER("XTEA_ECB"), false},
            {CF_CIPHER("XTEA_OFB"), false},
            {CF_CIPHER("XTEA_XTS"), false},
            {CF_CIPHER("AES_128_EAX"), false},
            {CF_CIPHER("AES_128_CBC_SHA1_TLS"), false},
            {CF_CIPHER("AES_128_CBC_SHA1_TLS_IMPLICIT_IV"), false},
            {CF_CIPHER("AES_128_CBC_SHA256_TLS"), false},
            {CF_CIPHER("AES_128_CCM_BLUETOOTH"), false},
            {CF_CIPHER("AES_128_CCM_BLUETOOTH_8"), false},
            {CF_CIPHER("AES_128_CTR_HMAC_SHA256"), false},
            {CF_CIPHER("AES_128_GCM"), false},
            {CF_CIPHER("AES_128_GCM_SIV"), false},
            {CF_CIPHER("AES_128_GCM_TLS12"), false},
            {CF_CIPHER("AES_128_GCM_TLS13"), false},
            {CF_CIPHER("AES_192_GCM"), false},
            {CF_CIPHER("AES_256_CBC_HMAC_SHA256"), false},
            {CF_CIPHER("AES_256_CBC_SHA1_TLS"), false},
            {CF_CIPHER("AES_256_CBC_SHA1_TLS_IMPLICIT_IV"), false},
            {CF_CIPHER("AES_256_CBC_SHA256_TLS"), false},
            {CF_CIPHER("AES_256_CBC_SHA384_TLS"), false},
            {CF_CIPHER("AES_256_CTR_HMAC_SHA256"), false},
            {CF_CIPHER("AES_256_GCM"), false},
            {CF_CIPHER("AES_256_GCM_SIV"), false},
            {CF_CIPHER("AES_256_GCM_TLS12"), false},
            {CF_CIPHER("AES_256_GCM_TLS13"), false},
            {CF_CIPHER("ARIA_128_GCM"), false},
            {CF_CIPHER("ARIA_192_GCM"), false},
            {CF_CIPHER("ARIA_256_GCM"), false},
            {CF_CIPHER("CAMELLIA_128_GCM"), false},
            {CF_CIPHER("CAMELLIA_192_GCM"), false},
            {CF_CIPHER("CAMELLIA_256_GCM"), false},
            {CF_CIPHER("CAMELLIA_128_CCM"), false},
            {CF_CIPHER("CAMELLIA_192_CCM"), false},
            {CF_CIPHER("CAMELLIA_256_CCM"), false},
            {CF_CIPHER("CHACHA20_POLY1305"), false},
            {CF_CIPHER("CHACHA20_POLY1305_LIBSODIUM"), false},
            {CF_CIPHER("DES_EDE3_CBC_SHA1_TLS"), false},
            {CF_CIPHER("DES_EDE3_CBC_SHA1_TLS_IMPLICIT_IV"), false},
            {CF_CIPHER("NULL_SHA1_TLS"), false},
            {CF_CIPHER("XCHACHA20_POLY1305"), false},
            
};

static uint64_t getCipherType(Datasource& ds){
    const auto origin_cipher = ds.Get<uint64_t>(0);
    auto new_cipher = CF_CIPHER("AES");
    if(Ciphers.count(origin_cipher) != 0){
        return origin_cipher;
    }
    return new_cipher;
}

namespace component {
/* SymmetricCipher */

SymmetricCipher::SymmetricCipher(Datasource& ds) :
    iv(ds),
    key(ds),
    cipherType(getCipherType(ds))
{ }

SymmetricCipher::SymmetricCipher(nlohmann::json json) :
    iv(json["iv"]),
    key(json["key"]),
    cipherType(json["cipherType"])
{ }

nlohmann::json SymmetricCipher::ToJSON(void) const {
    nlohmann::json j;
    j["iv"] = iv.ToJSON();
    j["key"] = key.ToJSON();
    j["cipherType"] = cipherType.ToJSON();
    return j;
}

bool SymmetricCipher::operator==(const SymmetricCipher& rhs) const {
    return
        (iv == rhs.iv) &&
        (key == rhs.key) &&
        (cipherType == rhs.cipherType);
}
void SymmetricCipher::Serialize(Datasource& ds) const {
    iv.Serialize(ds);
    key.Serialize(ds);
    cipherType.Serialize(ds);
}

/* Ciphertext */

Ciphertext::Ciphertext(Datasource& ds) :
    ciphertext(ds),
    tag( ds.Get<bool>() ? std::nullopt : std::make_optional<Tag>(ds) )
{ }

Ciphertext::Ciphertext(Buffer ciphertext, std::optional<Tag> tag) :
    ciphertext(ciphertext),
    tag(tag)
{ }

bool Ciphertext::operator==(const Ciphertext& rhs) const {
    return (ciphertext == rhs.ciphertext) && (tag == rhs.tag);
}

void Ciphertext::Serialize(Datasource& ds) const {
    ciphertext.Serialize(ds);
    if ( tag == std::nullopt ) {
        ds.Put<bool>(true);
    } else {
        ds.Put<bool>(false);
        tag->Serialize(ds);
    }
}

/* BignumPair */

BignumPair::BignumPair(Datasource& ds) :
    first(ds),
    second(ds)
{ }

BignumPair::BignumPair(const std::string first, const std::string second) :
    first(first),
    second(second)
{ }

BignumPair::BignumPair(nlohmann::json json) :
    first(json[0].get<std::string>()),
    second(json[1].get<std::string>())
{ }


bool BignumPair::operator==(const BignumPair& rhs) const {
    return
        (first == rhs.first) &&
        (second == rhs.second);
}

void BignumPair::Serialize(Datasource& ds) const {
    first.Serialize(ds);
    second.Serialize(ds);
}

nlohmann::json BignumPair::ToJSON(void) const {
    return std::vector<nlohmann::json>{first.ToJSON(), second.ToJSON()};
}

/* ECC_KeyPair */

ECC_KeyPair::ECC_KeyPair(Datasource& ds) :
    priv(ds),
    pub(ds)
{ }

ECC_KeyPair::ECC_KeyPair(ECC_PrivateKey priv, BignumPair pub) :
    priv(priv),
    pub(pub)
{ }

bool ECC_KeyPair::operator==(const ECC_KeyPair& rhs) const {
    return
        (priv == rhs.priv) &&
        (pub == rhs.pub);
}

void ECC_KeyPair::Serialize(Datasource& ds) const {
    priv.Serialize(ds);
    pub.Serialize(ds);
}

nlohmann::json ECC_KeyPair::ToJSON(void) const {
    return std::vector<nlohmann::json>{priv.ToJSON(), pub.ToJSON()};
}

/* ECDSA_Signature */
ECDSA_Signature::ECDSA_Signature(Datasource& ds) :
    signature(ds),
    pub(ds)
{ }

ECDSA_Signature::ECDSA_Signature(BignumPair signature, ECC_PublicKey pub) :
    signature(signature),
    pub(pub)
{ }

ECDSA_Signature::ECDSA_Signature(nlohmann::json json) :
    signature(json["signature"]),
    pub(json["pub"])
{ }

bool ECDSA_Signature::operator==(const ECDSA_Signature& rhs) const {
    return
        (signature == rhs.signature) &&
        (pub == rhs.pub);
}

void ECDSA_Signature::Serialize(Datasource& ds) const {
    signature.Serialize(ds);
    pub.Serialize(ds);
}

nlohmann::json ECDSA_Signature::ToJSON(void) const {
    return std::vector<nlohmann::json>{signature.ToJSON(), pub.ToJSON()};
}

/* MACType */

MACType::MACType(Datasource& ds) :
    mode(ds.Get<bool>()),
    type(ds)
{ }

MACType::MACType(nlohmann::json json) :
    mode(json["mode"].get<bool>()),
    type(json["type"])
{ }

nlohmann::json MACType::ToJSON(void) const {
    nlohmann::json j;
    j["mode"] = mode;
    j["type"] = type.ToJSON();
    return j;
}

bool MACType::operator==(const MACType& rhs) const {
    return
        (mode == rhs.mode) &&
        (type == rhs.type);
}

void MACType::Serialize(Datasource& ds) const {
    ds.Put<>(mode);
    type.Serialize(ds);
}

G2::G2(nlohmann::json json) :
    first(json[0]),
    second(json[1]) {
}

nlohmann::json G2::ToJSON(void) const {
    return std::vector<nlohmann::json>{
        first.first.ToJSON(), first.second.ToJSON(),
        second.first.ToJSON(), second.second.ToJSON()
    };
}

void G2::Serialize(Datasource& ds) const {
    first.Serialize(ds);
    second.Serialize(ds);
}

/* BLS_Signature */
BLS_Signature::BLS_Signature(Datasource& ds) :
    signature(ds),
    pub(ds)
{ }

BLS_Signature::BLS_Signature(G2 signature, ECC_PublicKey pub) :
    signature(signature),
    pub(pub)
{ }

BLS_Signature::BLS_Signature(nlohmann::json json) :
    signature(json["signature"]),
    pub(json["pub"])
{ }

bool BLS_Signature::operator==(const BLS_Signature& rhs) const {
    return
        (signature == rhs.signature) &&
        (pub == rhs.pub);
}

void BLS_Signature::Serialize(Datasource& ds) const {
    signature.Serialize(ds);
    pub.Serialize(ds);
}

nlohmann::json BLS_Signature::ToJSON(void) const {
    return std::vector<nlohmann::json>{signature.ToJSON(), pub.ToJSON()};
}

/* BLS_KeyPair */

BLS_KeyPair::BLS_KeyPair(Datasource& ds) :
    priv(ds),
    pub(ds)
{ }

BLS_KeyPair::BLS_KeyPair(BLS_PrivateKey priv, BignumPair pub) :
    priv(priv),
    pub(pub)
{ }

bool BLS_KeyPair::operator==(const BLS_KeyPair& rhs) const {
    return
        (priv == rhs.priv) &&
        (pub == rhs.pub);
}

void BLS_KeyPair::Serialize(Datasource& ds) const {
    priv.Serialize(ds);
    pub.Serialize(ds);
}

nlohmann::json BLS_KeyPair::ToJSON(void) const {
    return std::vector<nlohmann::json>{priv.ToJSON(), pub.ToJSON()};
}

/* BLS_PairingComponents */

BLS_PairingComponents::BLS_PairingComponents(Datasource& ds) {
    const auto num = ds.Get<uint32_t>(0);
    for (size_t i = 0; i < num; i++) {
        c.push_back( Component{{ds}, {ds}, {ds}, {ds}} );
    }
}

BLS_PairingComponents::BLS_PairingComponents(nlohmann::json json) {
    for (const auto& j : json) {
        c.push_back( Component{
                {j["sig_v"], j["sig_w"], j["sig_x"], j["sig_y"]},
                {j["pub_x"], j["pub_y"]},
                {j["msg"]},
                {j["aug"]}});
    }
}

void BLS_PairingComponents::Serialize(Datasource& ds) const {
    ds.Put<uint32_t>(c.size());
    for (const auto& component : c) {
        component.sig.Serialize(ds);
        component.pub.Serialize(ds);
        component.msg.Serialize(ds);
        component.aug.Serialize(ds);
    }
}

/* BLS_G1_Vector */

BLS_G1_Vector::BLS_G1_Vector(Datasource& ds) {
    const auto num = ds.Get<uint32_t>(0);
    for (size_t i = 0; i < num; i++) {
        points.push_back( component::G1(ds) );
    }
}

BLS_G1_Vector::BLS_G1_Vector(nlohmann::json json) {
    for (const auto& j : json) {
        points.push_back( component::G1{j["x"], j["y"]} );
    }
}

void BLS_G1_Vector::Serialize(Datasource& ds) const {
    ds.Put<uint32_t>(points.size());
    for (const auto& signature : points) {
        signature.Serialize(ds);
    }
}

/* BLS_G2_Vector */

BLS_G2_Vector::BLS_G2_Vector(Datasource& ds) {
    const auto num = ds.Get<uint32_t>(0);
    for (size_t i = 0; i < num; i++) {
        points.push_back( component::G2(ds) );
    }
}

BLS_G2_Vector::BLS_G2_Vector(nlohmann::json json) {
    for (const auto& j : json) {
        points.push_back( component::G2{j["v"], j["w"], j["x"], j["y"]} );
    }
}

void BLS_G2_Vector::Serialize(Datasource& ds) const {
    ds.Put<uint32_t>(points.size());
    for (const auto& signature : points) {
        signature.Serialize(ds);
    }
}

/* SR25519_Signature */
SR25519_Signature::SR25519_Signature(Datasource& ds) :
    signature(ds),
    pub(ds)
{ }

SR25519_Signature::SR25519_Signature(BignumPair signature, Bignum pub) :
    signature(signature),
    pub(pub)
{ }

SR25519_Signature::SR25519_Signature(nlohmann::json json) :
    signature(json["signature"]),
    pub(json["pub"])
{ }

bool SR25519_Signature::operator==(const SR25519_Signature& rhs) const {
    return
        (signature == rhs.signature) &&
        (pub == rhs.pub);
}

void SR25519_Signature::Serialize(Datasource& ds) const {
    signature.Serialize(ds);
    pub.Serialize(ds);
}

nlohmann::json SR25519_Signature::ToJSON(void) const {
    return std::vector<nlohmann::json>{signature.ToJSON(), pub.ToJSON()};
}

} /* namespace component */

} /* namespace cryptofuzz */
