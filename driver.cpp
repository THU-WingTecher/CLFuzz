#include "driver.h"
#include <fuzzing/datasource/id.hpp>
#include "tests.h"
#include "executor.h"
#include <cryptofuzz/util.h>
#include <set>
#include <algorithm>
#include <unistd.h>
#include "mutatorpool.h"

namespace cryptofuzz {

void Driver::LoadModule(std::shared_ptr<Module> module) {
    modules[module->ID] = module;
}

void Driver::Run(const uint8_t* data, const size_t size) const {
    using fuzzing::datasource::ID;
    /* Calculate the number of inputs */
    mt1.lock();
    FILE* fp = fopen("runningCount.txt", "a");
    fprintf(fp, "1");
    fclose(fp);
    mt1.unlock();

    static ExecutorDigest executorDigest(CF_OPERATION("Digest"), modules, options);
    static ExecutorHMAC executorHMAC(CF_OPERATION("HMAC"), modules, options);
    static ExecutorCMAC executorCMAC(CF_OPERATION("CMAC"), modules, options);
    static ExecutorSymmetricEncrypt executorSymmetricEncrypt(CF_OPERATION("SymmetricEncrypt"), modules, options);
    static ExecutorSymmetricDecrypt executorSymmetricDecrypt(CF_OPERATION("SymmetricDecrypt"), modules, options);
    static ExecutorKDF_SCRYPT executorKDF_SCRYPT(CF_OPERATION("KDF_SCRYPT"), modules, options);
    static ExecutorKDF_HKDF executorKDF_HKDF(CF_OPERATION("KDF_HKDF"), modules, options);
    static ExecutorKDF_TLS1_PRF executorKDF_TLS1_PRF(CF_OPERATION("KDF_TLS1_PRF"), modules, options);
    static ExecutorKDF_PBKDF executorKDF_PBKDF(CF_OPERATION("KDF_PBKDF"), modules, options);
    static ExecutorKDF_PBKDF1 executorKDF_PBKDF1(CF_OPERATION("KDF_PBKDF1"), modules, options);
    static ExecutorKDF_PBKDF2 executorKDF_PBKDF2(CF_OPERATION("KDF_PBKDF2"), modules, options);
    static ExecutorKDF_ARGON2 executorKDF_ARGON2(CF_OPERATION("KDF_ARGON2"), modules, options);
    static ExecutorKDF_SSH executorKDF_SSH(ID("Cryptofuzz/Operation/KDF_SSH"), modules, options);
    static ExecutorKDF_X963 executorKDF_X963(CF_OPERATION("KDF_X963"), modules, options);
    static ExecutorKDF_BCRYPT executorKDF_BCRYPT(CF_OPERATION("KDF_BCRYPT"), modules, options);
    static ExecutorKDF_SP_800_108 executorKDF_SP_800_108(CF_OPERATION("KDF_SP_800_108"), modules, options);
    static ExecutorECC_PrivateToPublic executorECC_PrivateToPublic(CF_OPERATION("ECC_PrivateToPublic"), modules, options);
    static ExecutorECC_ValidatePubkey executorECC_ValidatePubkey(CF_OPERATION("ECC_ValidatePubkey"), modules, options);
    static ExecutorECC_GenerateKeyPair executorECC_GenerateKeyPair(CF_OPERATION("ECC_GenerateKeyPair"), modules, options);
    static ExecutorECDSA_Sign executorECDSA_Sign(CF_OPERATION("ECDSA_Sign"), modules, options);
    static ExecutorECGDSA_Sign executorECGDSA_Sign(CF_OPERATION("ECGDSA_Sign"), modules, options);
    static ExecutorECRDSA_Sign executorECRDSA_Sign(CF_OPERATION("ECRDSA_Sign"), modules, options);
    static ExecutorSchnorr_Sign executorSchnorr_Sign(CF_OPERATION("Schnorr_Sign"), modules, options);
    static ExecutorECDSA_Verify executorECDSA_Verify(CF_OPERATION("ECDSA_Verify"), modules, options);
    static ExecutorECGDSA_Verify executorECGDSA_Verify(CF_OPERATION("ECGDSA_Verify"), modules, options);
    static ExecutorECRDSA_Verify executorECRDSA_Verify(CF_OPERATION("ECRDSA_Verify"), modules, options);
    static ExecutorSchnorr_Verify executorSchnorr_Verify(CF_OPERATION("Schnorr_Verify"), modules, options);
    static ExecutorECDSA_Recover executorECDSA_Recover(CF_OPERATION("ECDSA_Recover"), modules, options);
    static ExecutorECDH_Derive executorECDH_Derive(CF_OPERATION("ECDH_Derive"), modules, options);
    static ExecutorECIES_Encrypt executorECIES_Encrypt(CF_OPERATION("ECIES_Encrypt"), modules, options);
    static ExecutorECIES_Decrypt executorECIES_Decrypt(CF_OPERATION("ECIES_Decrypt"), modules, options);
    static ExecutorECC_Point_Add executorECC_Point_Add(CF_OPERATION("ECC_Point_Add"), modules, options);
    static ExecutorECC_Point_Mul executorECC_Point_Mul(CF_OPERATION("ECC_Point_Mul"), modules, options);
    static ExecutorDH_GenerateKeyPair executorDH_GenerateKeyPair(CF_OPERATION("DH_GenerateKeyPair"), modules, options);
    static ExecutorDH_Derive executorDH_Derive(CF_OPERATION("DH_Derive"), modules, options);
    static ExecutorBignumCalc executorBignumCalc(CF_OPERATION("BignumCalc"), modules, options);
    static ExecutorBignumCalc_Mod_BLS12_381_R executorBignumCalc_mod_bls12_381_r(CF_OPERATION("BignumCalc_Mod_BLS12_381_R"), modules, options);
    static ExecutorBignumCalc_Mod_BLS12_381_P executorBignumCalc_mod_bls12_381_p(CF_OPERATION("BignumCalc_Mod_BLS12_381_P"), modules, options);
    static ExecutorBignumCalc_Mod_2Exp256 executorBignumCalc_mod_2exp256(CF_OPERATION("BignumCalc_Mod_2Exp256"), modules, options);
    static ExecutorBignumCalc_Mod_SECP256K1 executorBignumCalc_mod_secp256k1(CF_OPERATION("BignumCalc_Mod_SECP256K1"), modules, options);
    static ExecutorBLS_PrivateToPublic executorBLS_PrivateToPublic(CF_OPERATION("BLS_PrivateToPublic"), modules, options);
    static ExecutorBLS_PrivateToPublic_G2 executorBLS_PrivateToPublic_G2(CF_OPERATION("BLS_PrivateToPublic_G2"), modules, options);
    static ExecutorBLS_Sign executorBLS_Sign(CF_OPERATION("BLS_Sign"), modules, options);
    static ExecutorBLS_Verify executorBLS_Verify(CF_OPERATION("BLS_Verify"), modules, options);
    static ExecutorBLS_Aggregate_G1 executorBLS_Aggregate_G1(CF_OPERATION("BLS_Aggregate_G1"), modules, options);
    static ExecutorBLS_Aggregate_G2 executorBLS_Aggregate_G2(CF_OPERATION("BLS_Aggregate_G2"), modules, options);
    static ExecutorBLS_Pairing executorBLS_Pairing(CF_OPERATION("BLS_Pairing"), modules, options);
    static ExecutorBLS_HashToG1 executorBLS_HashToG1(CF_OPERATION("BLS_HashToG1"), modules, options);
    static ExecutorBLS_HashToG2 executorBLS_HashToG2(CF_OPERATION("BLS_HashToG2"), modules, options);
    static ExecutorBLS_IsG1OnCurve executorBLS_IsG1OnCurve(CF_OPERATION("BLS_IsG1OnCurve"), modules, options);
    static ExecutorBLS_IsG2OnCurve executorBLS_IsG2OnCurve(CF_OPERATION("BLS_IsG2OnCurve"), modules, options);
    static ExecutorBLS_GenerateKeyPair executorBLS_GenerateKeyPair(CF_OPERATION("BLS_GenerateKeyPair"), modules, options);
    static ExecutorBLS_Decompress_G1 executorBLS_Decompress_G1(CF_OPERATION("BLS_Decompress_G1"), modules, options);
    static ExecutorBLS_Compress_G1 executorBLS_Compress_G1(CF_OPERATION("BLS_Compress_G1"), modules, options);
    static ExecutorBLS_Decompress_G2 executorBLS_Decompress_G2(CF_OPERATION("BLS_Decompress_G2"), modules, options);
    static ExecutorBLS_Compress_G2 executorBLS_Compress_G2(CF_OPERATION("BLS_Compress_G2"), modules, options);
    static ExecutorBLS_G1_Add executorBLS_G1_Add(CF_OPERATION("BLS_G1_Add"), modules, options);
    static ExecutorBLS_G1_Mul executorBLS_G1_Mul(CF_OPERATION("BLS_G1_Mul"), modules, options);
    static ExecutorBLS_G1_IsEq executorBLS_G1_IsEq(CF_OPERATION("BLS_G1_IsEq"), modules, options);
    static ExecutorBLS_G1_Neg executorBLS_G1_Neg(CF_OPERATION("BLS_G1_Neg"), modules, options);
    static ExecutorBLS_G2_Add executorBLS_G2_Add(CF_OPERATION("BLS_G2_Add"), modules, options);
    static ExecutorBLS_G2_Mul executorBLS_G2_Mul(CF_OPERATION("BLS_G2_Mul"), modules, options);
    static ExecutorBLS_G2_IsEq executorBLS_G2_IsEq(CF_OPERATION("BLS_G2_IsEq"), modules, options);
    static ExecutorBLS_G2_Neg executorBLS_G2_Neg(CF_OPERATION("BLS_G2_Neg"), modules, options);
    static ExecutorMisc executorMisc(CF_OPERATION("Misc"), modules, options);
    static ExecutorSR25519_Verify executorSR25519_Verify(CF_OPERATION("SR25519_Verify"), modules, options);

    try {

        Datasource ds(data, size);

        auto operation = ds.Get<uint64_t>();

        // auto operation =  CF_OPERATION("HMAC");

        /* Reset operation id */
        // switch ( origin_op % 66 ) {
        //     case 0:
        //         operation = CF_OPERATION("Digest");
        //         break;
        //     case 1:
        //         operation = CF_OPERATION("HMAC");
        //         break;
        //     case 2:
        //         operation = CF_OPERATION("CMAC");
        //         break;
        //     case 3:
        //         operation = CF_OPERATION("SymmetricEncrypt");
        //         break;
        //     case 4:
        //         operation = CF_OPERATION("SymmetricDecrypt");
        //         break;
        //     case 5:
        //         operation = CF_OPERATION("KDF_SCRYPT");
        //         break;
        //     case 6:
        //         operation = CF_OPERATION("KDF_HKDF");
        //         break;
        //     case 7:
        //         operation = CF_OPERATION("KDF_TLS1_PRF");
        //         break;
        //     case 8:
        //         operation = CF_OPERATION("KDF_PBKDF");
        //         break;
        //     case 9:
        //         operation = CF_OPERATION("KDF_PBKDF1");
        //         break;
        //     case 10:
        //         operation = CF_OPERATION("KDF_PBKDF2");
        //         break;
        //     case 11:
        //         operation = CF_OPERATION("KDF_ARGON2");
        //         break;
        //     case 12:
        //         operation = CF_OPERATION("KDF_SSH");
        //         break;
        //     case 13:
        //         operation = CF_OPERATION("KDF_X963");
        //         break;
        //     case 14:
        //         operation = CF_OPERATION("KDF_BCRYPT");
        //         break;
        //     case 15:
        //         operation = CF_OPERATION("KDF_SP_800_108");
        //         break;
        //     case 16:
        //         operation = CF_OPERATION("ECC_PrivateToPublic");
        //         break;
        //     case 17:
        //         operation = CF_OPERATION("ECC_ValidatePubkey");
        //         break;
        //     case 18:
        //         operation = CF_OPERATION("ECC_GenerateKeyPair");
        //         break;
        //     case 19:
        //         operation = CF_OPERATION("ECDSA_Sign");
        //         break;
        //     case 20:
        //         operation = CF_OPERATION("ECGDSA_Sign");
        //         break;
        //     case 21:
        //         operation = CF_OPERATION("ECRDSA_Sign");
        //         break;
        //     case 22:
        //         operation = CF_OPERATION("Schnorr_Sign");
        //         break;
        //     case 23:
        //         operation = CF_OPERATION("ECDSA_Verify");
        //         break;
        //     case 24:
        //         operation = CF_OPERATION("ECGDSA_Verify");
        //         break;
        //     case 25:
        //         operation = CF_OPERATION("ECRDSA_Verify");
        //         break;
        //     case 26:
        //         operation = CF_OPERATION("Schnorr_Verify");
        //         break;
        //     case 27:
        //         operation = CF_OPERATION("ECDSA_Recover");
        //         break;
        //     case 28:
        //         operation = CF_OPERATION("ECDH_Derive");
        //         break;
        //     case 29:
        //         operation = CF_OPERATION("ECIES_Encrypt");
        //         break;
        //     case 30:
        //         operation = CF_OPERATION("ECIES_Decrypt");
        //         break;
        //     case 31:
        //         operation = CF_OPERATION("ECC_Point_Add");
        //         break;
        //     case 32:
        //         operation = CF_OPERATION("ECC_Point_Mul");
        //         break;
        //     case 33:
        //         operation = CF_OPERATION("DH_GenerateKeyPair");
        //         break;
        //     case 34:
        //         operation = CF_OPERATION("DH_Derive");
        //         break;
        //     case 35:
        //         operation = CF_OPERATION("BignumCalc");
        //         break;
        //     case 36:
        //         operation = CF_OPERATION("BignumCalc_Mod_BLS12_381_R");
        //         break;
        //     case 37:
        //         operation = CF_OPERATION("BignumCalc_Mod_BLS12_381_P");
        //         break;
        //     case 38:
        //         operation = CF_OPERATION("BignumCalc_Mod_2Exp256");
        //         break;
        //     case 39:
        //         operation = CF_OPERATION("BignumCalc_Mod_SECP256K1");
        //         break;
        //     case 40:
        //         operation = CF_OPERATION("BLS_PrivateToPublic");
        //         break;
        //     case 41:
        //         operation = CF_OPERATION("BLS_PrivateToPublic_G2");
        //         break;
        //     case 42:
        //         operation = CF_OPERATION("BLS_Sign");
        //         break;
        //     case 43:
        //         operation = CF_OPERATION("BLS_Verify");
        //         break;
        //     case 44:
        //         operation = CF_OPERATION("BLS_Aggregate_G1");
        //         break;
        //     case 45:
        //         operation = CF_OPERATION("BLS_Aggregate_G2");
        //         break;
        //     case 46:
        //         operation = CF_OPERATION("BLS_Pairing");
        //         break;
        //     case 47:
        //         operation = CF_OPERATION("BLS_HashToG1");
        //         break;
        //     case 48:
        //         operation = CF_OPERATION("BLS_HashToG2");
        //         break;
        //     case 49:
        //         operation = CF_OPERATION("BLS_IsG1OnCurve");
        //         break;
        //     case 50:
        //         operation = CF_OPERATION("BLS_IsG2OnCurve");
        //         break;
        //     case 51:
        //         operation = CF_OPERATION("BLS_GenerateKeyPair");
        //         break;
        //     case 52:
        //         operation = CF_OPERATION("BLS_Decompress_G1");
        //         break;
        //     case 53:
        //         operation = CF_OPERATION("BLS_Compress_G1");
        //         break;
        //     case 54:
        //         operation = CF_OPERATION("BLS_Decompress_G2");
        //         break;
        //     case 55:
        //         operation = CF_OPERATION("BLS_Compress_G2");
        //         break;
        //     case 56:
        //         operation = CF_OPERATION("BLS_G1_Add");
        //         break;
        //     case 57:
        //         operation = CF_OPERATION("BLS_G1_Mul");
        //         break;
        //     case 58:
        //         operation = CF_OPERATION("BLS_G1_IsEq");
        //         break;
        //     case 59:
        //         operation = CF_OPERATION("BLS_G1_Neg");
        //         break;
        //     case 60:
        //         operation = CF_OPERATION("BLS_G2_Add");
        //         break;
        //     case 61:
        //         operation = CF_OPERATION("BLS_G2_Mul");
        //         break;
        //     case 62:
        //         operation = CF_OPERATION("BLS_G2_IsEq");
        //         break;
        //     case 63:
        //         operation = CF_OPERATION("BLS_G2_Neg");
        //         break;
        //     case 64:
        //         operation = CF_OPERATION("Misc");
        //         break;
        //     case 65:
        //         operation = CF_OPERATION("SR25519_Verify");
        //         break;
        // }
        /* end of operation reset */

        if ( !options.operations.Have(operation) ) {
            printf("------------None exists operation---------------\n");
            return;
        }

        const auto payload = ds.GetData(0, 1);

        switch ( operation ) {
            case CF_OPERATION("Digest"):
                executorDigest.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("HMAC"):
                executorHMAC.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("CMAC"):
                executorCMAC.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("SymmetricEncrypt"):
                executorSymmetricEncrypt.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("SymmetricDecrypt"):
                executorSymmetricDecrypt.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("KDF_SCRYPT"):
                executorKDF_SCRYPT.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("KDF_HKDF"):
                executorKDF_HKDF.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("KDF_TLS1_PRF"):
                executorKDF_TLS1_PRF.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("KDF_PBKDF"):
                executorKDF_PBKDF.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("KDF_PBKDF1"):
                executorKDF_PBKDF1.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("KDF_PBKDF2"):
                executorKDF_PBKDF2.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("KDF_ARGON2"):
                executorKDF_ARGON2.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("KDF_SSH"):
                executorKDF_SSH.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("KDF_X963"):
                executorKDF_X963.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("KDF_BCRYPT"):
                executorKDF_BCRYPT.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("KDF_SP_800_108"):
                executorKDF_SP_800_108.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("ECC_PrivateToPublic"):
                executorECC_PrivateToPublic.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("ECC_ValidatePubkey"):
                executorECC_ValidatePubkey.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("ECC_GenerateKeyPair"):
                executorECC_GenerateKeyPair.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("ECDSA_Sign"):
                executorECDSA_Sign.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("ECGDSA_Sign"):
                executorECGDSA_Sign.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("ECRDSA_Sign"):
                executorECRDSA_Sign.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("Schnorr_Sign"):
                executorSchnorr_Sign.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("ECDSA_Verify"):
                executorECDSA_Verify.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("ECGDSA_Verify"):
                executorECGDSA_Verify.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("ECRDSA_Verify"):
                executorECRDSA_Verify.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("Schnorr_Verify"):
                executorSchnorr_Verify.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("ECDSA_Recover"):
                executorECDSA_Recover.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("ECDH_Derive"):
                executorECDH_Derive.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("ECIES_Encrypt"):
                executorECIES_Encrypt.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("ECIES_Decrypt"):
                executorECIES_Decrypt.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("ECC_Point_Add"):
                executorECC_Point_Add.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("ECC_Point_Mul"):
                executorECC_Point_Mul.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("DH_GenerateKeyPair"):
                executorDH_GenerateKeyPair.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("DH_Derive"):
                executorDH_Derive.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("BignumCalc"):
                executorBignumCalc.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("BignumCalc_Mod_BLS12_381_R"):
                executorBignumCalc_mod_bls12_381_r.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("BignumCalc_Mod_BLS12_381_P"):
                executorBignumCalc_mod_bls12_381_p.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("BignumCalc_Mod_2Exp256"):
                executorBignumCalc_mod_2exp256.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("BignumCalc_Mod_SECP256K1"):
                executorBignumCalc_mod_secp256k1.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("BLS_PrivateToPublic"):
                executorBLS_PrivateToPublic.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("BLS_PrivateToPublic_G2"):
                executorBLS_PrivateToPublic_G2.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("BLS_Sign"):
                executorBLS_Sign.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("BLS_Verify"):
                executorBLS_Verify.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("BLS_Aggregate_G1"):
                executorBLS_Aggregate_G1.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("BLS_Aggregate_G2"):
                executorBLS_Aggregate_G2.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("BLS_Pairing"):
                executorBLS_Pairing.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("BLS_HashToG1"):
                executorBLS_HashToG1.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("BLS_HashToG2"):
                executorBLS_HashToG2.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("BLS_IsG1OnCurve"):
                executorBLS_IsG1OnCurve.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("BLS_IsG2OnCurve"):
                executorBLS_IsG2OnCurve.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("BLS_GenerateKeyPair"):
                executorBLS_GenerateKeyPair.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("BLS_Decompress_G1"):
                executorBLS_Decompress_G1.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("BLS_Compress_G1"):
                executorBLS_Compress_G1.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("BLS_Decompress_G2"):
                executorBLS_Decompress_G2.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("BLS_Compress_G2"):
                executorBLS_Compress_G2.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("BLS_G1_Add"):
                executorBLS_G1_Add.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("BLS_G1_Mul"):
                executorBLS_G1_Mul.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("BLS_G1_IsEq"):
                executorBLS_G1_IsEq.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("BLS_G1_Neg"):
                executorBLS_G1_Neg.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("BLS_G2_Add"):
                executorBLS_G2_Add.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("BLS_G2_Mul"):
                executorBLS_G2_Mul.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("BLS_G2_IsEq"):
                executorBLS_G2_IsEq.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("BLS_G2_Neg"):
                executorBLS_G2_Neg.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("Misc"):
                executorMisc.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("SR25519_Verify"):
                executorSR25519_Verify.Run(ds, payload.data(), payload.size());
                break;
            default:{
                /*reset op id*/
                switch ( operation % 66 ) {
                    case 0:
                        operation = CF_OPERATION("Digest");
                        break;
                    case 1:
                        operation = CF_OPERATION("HMAC");
                        break;
                    case 2:
                        operation = CF_OPERATION("CMAC");
                        break;
                    case 3:
                        operation = CF_OPERATION("SymmetricEncrypt");
                        break;
                    case 4:
                        operation = CF_OPERATION("SymmetricDecrypt");
                        break;
                    case 5:
                        operation = CF_OPERATION("KDF_SCRYPT");
                        break;
                    case 6:
                        operation = CF_OPERATION("KDF_HKDF");
                        break;
                    case 7:
                        operation = CF_OPERATION("KDF_TLS1_PRF");
                        break;
                    case 8:
                        operation = CF_OPERATION("KDF_PBKDF");
                        break;
                    case 9:
                        operation = CF_OPERATION("KDF_PBKDF1");
                        break;
                    case 10:
                        operation = CF_OPERATION("KDF_PBKDF2");
                        break;
                    case 11:
                        operation = CF_OPERATION("KDF_ARGON2");
                        break;
                    case 12:
                        operation = CF_OPERATION("KDF_SSH");
                        break;
                    case 13:
                        operation = CF_OPERATION("KDF_X963");
                        break;
                    case 14:
                        operation = CF_OPERATION("KDF_BCRYPT");
                        break;
                    case 15:
                        operation = CF_OPERATION("KDF_SP_800_108");
                        break;
                    case 16:
                        operation = CF_OPERATION("ECC_PrivateToPublic");
                        break;
                    case 17:
                        operation = CF_OPERATION("ECC_ValidatePubkey");
                        break;
                    case 18:
                        operation = CF_OPERATION("ECC_GenerateKeyPair");
                        break;
                    case 19:
                        operation = CF_OPERATION("ECDSA_Sign");
                        break;
                    case 20:
                        operation = CF_OPERATION("ECGDSA_Sign");
                        break;
                    case 21:
                        operation = CF_OPERATION("ECRDSA_Sign");
                        break;
                    case 22:
                        operation = CF_OPERATION("Schnorr_Sign");
                        break;
                    case 23:
                        operation = CF_OPERATION("ECDSA_Verify");
                        break;
                    case 24:
                        operation = CF_OPERATION("ECGDSA_Verify");
                        break;
                    case 25:
                        operation = CF_OPERATION("ECRDSA_Verify");
                        break;
                    case 26:
                        operation = CF_OPERATION("Schnorr_Verify");
                        break;
                    case 27:
                        operation = CF_OPERATION("ECDSA_Recover");
                        break;
                    case 28:
                        operation = CF_OPERATION("ECDH_Derive");
                        break;
                    case 29:
                        operation = CF_OPERATION("ECIES_Encrypt");
                        break;
                    case 30:
                        operation = CF_OPERATION("ECIES_Decrypt");
                        break;
                    case 31:
                        operation = CF_OPERATION("ECC_Point_Add");
                        break;
                    case 32:
                        operation = CF_OPERATION("ECC_Point_Mul");
                        break;
                    case 33:
                        operation = CF_OPERATION("DH_GenerateKeyPair");
                        break;
                    case 34:
                        operation = CF_OPERATION("DH_Derive");
                        break;
                    case 35:
                        operation = CF_OPERATION("BignumCalc");
                        break;
                    case 36:
                        operation = CF_OPERATION("BignumCalc_Mod_BLS12_381_R");
                        break;
                    case 37:
                        operation = CF_OPERATION("BignumCalc_Mod_BLS12_381_P");
                        break;
                    case 38:
                        operation = CF_OPERATION("BignumCalc_Mod_2Exp256");
                        break;
                    case 39:
                        operation = CF_OPERATION("BignumCalc_Mod_SECP256K1");
                        break;
                    case 40:
                        operation = CF_OPERATION("BLS_PrivateToPublic");
                        break;
                    case 41:
                        operation = CF_OPERATION("BLS_PrivateToPublic_G2");
                        break;
                    case 42:
                        operation = CF_OPERATION("BLS_Sign");
                        break;
                    case 43:
                        operation = CF_OPERATION("BLS_Verify");
                        break;
                    case 44:
                        operation = CF_OPERATION("BLS_Aggregate_G1");
                        break;
                    case 45:
                        operation = CF_OPERATION("BLS_Aggregate_G2");
                        break;
                    case 46:
                        operation = CF_OPERATION("BLS_Pairing");
                        break;
                    case 47:
                        operation = CF_OPERATION("BLS_HashToG1");
                        break;
                    case 48:
                        operation = CF_OPERATION("BLS_HashToG2");
                        break;
                    case 49:
                        operation = CF_OPERATION("BLS_IsG1OnCurve");
                        break;
                    case 50:
                        operation = CF_OPERATION("BLS_IsG2OnCurve");
                        break;
                    case 51:
                        operation = CF_OPERATION("BLS_GenerateKeyPair");
                        break;
                    case 52:
                        operation = CF_OPERATION("BLS_Decompress_G1");
                        break;
                    case 53:
                        operation = CF_OPERATION("BLS_Compress_G1");
                        break;
                    case 54:
                        operation = CF_OPERATION("BLS_Decompress_G2");
                        break;
                    case 55:
                        operation = CF_OPERATION("BLS_Compress_G2");
                        break;
                    case 56:
                        operation = CF_OPERATION("BLS_G1_Add");
                        break;
                    case 57:
                        operation = CF_OPERATION("BLS_G1_Mul");
                        break;
                    case 58:
                        operation = CF_OPERATION("BLS_G1_IsEq");
                        break;
                    case 59:
                        operation = CF_OPERATION("BLS_G1_Neg");
                        break;
                    case 60:
                        operation = CF_OPERATION("BLS_G2_Add");
                        break;
                    case 61:
                        operation = CF_OPERATION("BLS_G2_Mul");
                        break;
                    case 62:
                        operation = CF_OPERATION("BLS_G2_IsEq");
                        break;
                    case 63:
                        operation = CF_OPERATION("BLS_G2_Neg");
                        break;
                    case 64:
                        operation = CF_OPERATION("Misc");
                        break;
                    case 65:
                        operation = CF_OPERATION("SR25519_Verify");
                        break;
                }
            }break;
        }
    } catch ( Datasource::OutOfData ) {
    }
};

Driver::Driver(const Options options) :
    options(options)
{ }

const Options* Driver::GetOptionsPtr(void) const {
    return &options;
}

} /* namespace cryptofuzz */
