
#include "threaded_vm.hpp"


#ifndef ASGARD_BYTECODE_CHUNK_DEF
#define ASGARD_BYTECODE_CHUNK_DEF

#include <stdint.h>

#include <stddef.h>


#if defined(_MSC_VER) && !defined(__clang__)
#include <intrin.h>

#define ASG_CHUNK_BARRIER() MemoryBarrier()

#define ASG_CHUNK_TRAP() __debugbreak()
#else
#define ASG_CHUNK_BARRIER() __atomic_thread_fence(__ATOMIC_SEQ_CST)

#define ASG_CHUNK_TRAP() __builtin_trap()
#endif


#pragma pack(push, 1)

struct AsgardBytecodeChunk {
                                uint32_t chunk_id;
                                uint32_t next_chunk_id;
                                uint32_t word_offset;
                                uint32_t word_count;
                                uint32_t canary;
                                uint32_t entropy_seed;
                                uint64_t junk_pad[2];
                                const uint64_t* data;
                                
};

typedef struct AsgardBytecodeChunk AsgardBytecodeChunk;

#pragma pack(pop)
#endif


static const uint64_t embedded_bytecode_chk_0000[] = {
    0x9edada11f208c387ULL,
    0xf31a6a625c7a114aULL,
    0xdd3a84cce64ee376ULL,
    0x14108f9463e7627cULL,
    0xb73f32d3f6057919ULL,
    0x6211babef9132e69ULL,
    0x04c2abb46e77f017ULL,
    0x6122c2c65e07df81ULL,
    0x3b54b6a5fd4abb33ULL,
    0x040ba037281cbf96ULL,
    0x8ea607e8434e3e64ULL,
    0x6ba544c6fceb34abULL,
    0x3d97fc3e1a8ceaeaULL,
    0xebd7d9b235c18f80ULL,
    0x3e33224f88e4f46fULL,
    0x5c3cf60dfb4f5e3eULL,
    0x2f076b71ccc10b20ULL,
    0x922b50ca3cbc2349ULL,
    0xc25a79427ca78a17ULL,
    0xee27f77eacd87c14ULL,
    0x7839505867cc6ebbULL,
    0x2100bd8c68971910ULL,
    0xb3f17170201edb7aULL,
    0x0b77b528740ea8b8ULL,
    0x105ca5401168d6e9ULL,
    0xc0451b62dfd48d23ULL,
    0x33e06baa95747bc0ULL,
    0x0de1d36160bed517ULL,
    0x3d82fa53258877e5ULL,
    0x7c84a836bea68917ULL,
    0x095d92b5c668f5beULL,
    0x842bfba3bbe37ac4ULL,
    0xe12e7453a55f7d14ULL,
    0x7665a4d3b29cee23ULL,
    0x87e8204da9120ba1ULL,
    0xf249663ec1bce12eULL,
    0xb6de049c8f009544ULL,
    0xbf2b2a308041ecc9ULL,
    0x7b5b6f27dfd10394ULL,
    0x6d6aa881cae4c0d8ULL,
    0x11fe3a4e1bada4c4ULL,
    0x6d74c65e1d2c57bcULL,
    0xacf0890af6c57511ULL,
    0x0a7e2f0cfbc4aca5ULL,
    0x88cce66738cbc4e1ULL,
    0xc4068a2b9af4b663ULL,
    0xf7b1b00881f69177ULL,
    0xbe30e7ce68a205a8ULL,
    0xbeea5ca91b7c1cf0ULL,
    0x9277f85b18f7f14fULL,
    0x9a8923b749cf40edULL,
    0xa32a0f63ddf11ab3ULL,
    0x154b7f97eab3d502ULL,
    0x02ccbc2b4957ec38ULL,
    0x098ab32fef5d8cf8ULL,
    0x5076bc1294e96815ULL,
    0xf9d9d7ca189145b8ULL,
    0x1da42d0589eaf907ULL,
    0xc2055d6b3093bd66ULL,
    0x03f12ecc03306430ULL,
    0xa19282b48e444d04ULL,
    0x9a3409c5c0153b4eULL,
    0xb12146de59037711ULL,
    0x9883df8a90a5ca1dULL
};

static const uint64_t embedded_bytecode_chk_0001[] = {
    0x3b17810fe105a9b6ULL,
    0x4228607583a0b21eULL,
    0xb9c3cea3b8f19af1ULL,
    0xd27ce4e067afea0cULL,
    0x089f50cecd04ceeeULL,
    0x9004139878704dcbULL,
    0x3b1ef2a7d8a8acf3ULL,
    0xf59a7c10c8ff47f6ULL,
    0x74878c0380024507ULL,
    0x1cce19e5264704b9ULL,
    0x2466188c4430d600ULL,
    0xfef131425b6f7249ULL,
    0xf8ef9fde8fea9d2fULL,
    0xf367998b35abdab4ULL,
    0xdc8ffe390b9596cdULL,
    0xdb3923ab76a707f6ULL,
    0xcc161b90bbc5b337ULL,
    0xbe623c7bc034d472ULL,
    0x23915840634cc7a4ULL,
    0x25b15814198f00c7ULL,
    0x48ba7f4dbf9a0f22ULL,
    0x220fb282cefca47aULL,
    0xfbc993c925bcd260ULL,
    0x0a64338d2c2638bdULL,
    0x719800cd75caa1e3ULL,
    0xe1dc4d2ce0be742cULL,
    0x471cb15ec12e6163ULL,
    0xeb54982e315314a0ULL,
    0xda49cfd3c9d69ca8ULL,
    0x618e8a9a45877c7cULL,
    0xa8eab74e56ee049aULL,
    0x08ecf8fd4166e237ULL,
    0xabe80cbb6f957d73ULL,
    0x1fc5b151b53f6b69ULL,
    0x85377c40e0a52798ULL,
    0xd6cd6ee30a6764cfULL,
    0xd7aedb6d92dea1e0ULL,
    0x9254b85b9afd8fd4ULL,
    0x665fa63f7d6a058eULL,
    0xf1ff889722357686ULL,
    0xc3a555bf0c32394bULL,
    0x8261d2d20fe7ff62ULL,
    0x84f932327cf1e423ULL,
    0x389d558cb1b68a8aULL,
    0xd151a3ea01c3f6dcULL,
    0x97ca13fab9ba8564ULL,
    0xb15d413f47a2a21fULL,
    0x4c91c55c9f81df2cULL,
    0xcafaa53c92fb105dULL,
    0x808dc4b90cc1f133ULL,
    0x034d78ff9541f2b1ULL,
    0x4d570073816d05c9ULL,
    0xd0aa0dada906f977ULL,
    0x2ab5b21e16654a86ULL,
    0x3e044dde322b65a6ULL,
    0x2a023e9cbba838b3ULL,
    0xc510b9b9f0089c01ULL,
    0x1184a67bd4a95c6cULL,
    0x387bb4dc47ef8e6eULL,
    0x38e89f7f8bce3c68ULL,
    0xc97bf92c7a336be0ULL,
    0x48aec474f5c63c96ULL,
    0xe368012e63c1b00aULL,
    0xc35604f6481175ceULL
};

static const uint64_t embedded_bytecode_chk_0002[] = {
    0xec86218b1affafc4ULL,
    0x117001393dc778ffULL,
    0xf419f2a3342cf90bULL,
    0x572555019af3467aULL,
    0x0d56b43dac9ffb85ULL,
    0xf956043c39a3922aULL,
    0x030c1c38b2556c9bULL,
    0xd5d37abfdb12ff0cULL,
    0x471d73617d0bffc2ULL,
    0xc4279ce83300ea99ULL,
    0xf12825ef62a6045bULL,
    0xe2db61efd6cee301ULL,
    0x67747bea2aa0fee4ULL,
    0x22f2bb5a9ee02817ULL,
    0xef1b04a08c02482dULL,
    0xbd8fb3029956d1c7ULL,
    0x5a8b814f232c635aULL,
    0x51c0af23ae51f489ULL,
    0x2cc693bb25c6d87cULL,
    0x144b4779fee4796bULL,
    0x547fd3ba1743b4a8ULL,
    0x614b4c2dfe40ad5bULL,
    0xc699e833d90eaa54ULL,
    0x42c599548479ac4aULL,
    0x89048cf867031a0fULL,
    0xcb9c0ee11355ddd6ULL,
    0x7d632aae61f9d5beULL,
    0x6643a52363c7cd45ULL,
    0xedb7de040a0bd285ULL,
    0xae75775d231764f4ULL,
    0x39b4796f5e33a52bULL,
    0x8f77012d86df641aULL,
    0x38728f478e978dd6ULL,
    0x4983765936ab512aULL,
    0x89f394af895d3a75ULL,
    0xa3ee234c8f865838ULL,
    0x671f3a3eeb2e8737ULL,
    0x42bb49f9fce4c6a6ULL,
    0xe69d751114d2a065ULL,
    0x17282bf808377368ULL,
    0x5f387e9688a888baULL,
    0xe4aa4ae2e7e6a6ddULL,
    0x8929d48ebfc07262ULL,
    0xa59721f820fc9be4ULL,
    0x99c4d6059bad22e1ULL,
    0x9f0740330ce4fcf0ULL,
    0x2ce1f51076ef76c3ULL,
    0x11c5edee6cd80e6eULL,
    0x113bdcd12074e23fULL,
    0xbcc1feec292805a8ULL,
    0xf81d83649d976b82ULL,
    0x5c958cd9d66481c6ULL,
    0xcb54be42dcf006f7ULL,
    0x0230cb8992d53d1dULL,
    0x1261efa5dc99b08bULL,
    0xccca72c78ac8c622ULL,
    0x7bd4a283becce9d8ULL,
    0xeb3176f233135260ULL,
    0xd73c94380de9b693ULL,
    0x3de271b8d9ee700fULL,
    0x8c5bb49d884197a5ULL,
    0x9d09e7fc615fec7dULL,
    0xfbe2efda5c0801d0ULL,
    0xf91a52ba49348bdcULL
};

static const uint64_t embedded_bytecode_chk_0003[] = {
    0x589c2808a6aab6d1ULL,
    0x58af899b25223018ULL,
    0x2e5b0d05065e2211ULL,
    0x38fbfd837fb2f46dULL,
    0x016ecd8a5e136975ULL,
    0xe8e0d589489fb1d1ULL,
    0xf9721eae036cce99ULL,
    0x6a6c0cfacaad301cULL,
    0x979876fa26ece2f8ULL,
    0x6f2bc0903921f3b9ULL,
    0xe521a298466a5096ULL,
    0x81e56fe8f2beb06dULL,
    0x028fec67796083ceULL,
    0xdf21842ec39b32ebULL,
    0x6f4b3bb471485040ULL,
    0x43797ec2375780a9ULL,
    0x78257d1cffe4b576ULL,
    0x67959196adc605c3ULL,
    0xd2e794c3838a704dULL,
    0x43d61284396f924dULL,
    0x529e2031940afd58ULL,
    0xa7f4b992f3e4481aULL,
    0xb33c6fe32ea5f0fbULL,
    0x2b8f7d218a2ced51ULL,
    0x4ce2c6bb0678875eULL,
    0x994ada9efa862639ULL,
    0xf0f84e910003b770ULL,
    0x6b32cb8ee352f8d5ULL,
    0x0ac9615d348f2bcfULL,
    0x506d8a5b37773fb7ULL,
    0x3b2bd2413811bf07ULL,
    0xca85b5f35b285b83ULL,
    0x108d978abc217ce2ULL,
    0xe1baa02559055cbeULL,
    0xdcb83776f6d8aaffULL,
    0x88eba75e8186ac65ULL,
    0x55b917822d963befULL,
    0x2ca10aedf24954dcULL,
    0x7364a45dfd4cd756ULL,
    0xb013764155c37508ULL,
    0xc53a2b641f391ab0ULL,
    0x9e405c8fab2230d5ULL,
    0x1df661f2ac2e7e32ULL,
    0xff5111eba6030d4fULL,
    0xa26501d6a74fb704ULL,
    0xc63b03f78a54b87cULL,
    0xd07618669807707bULL,
    0xc46d8eb78e20f2e1ULL,
    0x7be4b8fbaac52bbcULL,
    0xda4a15943476876bULL,
    0x3566d92331f400c3ULL,
    0x950d25648f099875ULL,
    0xe42b9e5e09d91fb0ULL,
    0x1bc269d6b63e5ab7ULL,
    0x661225386e6bd1a4ULL,
    0x35c9dcd3a062ae8fULL,
    0x5f9971058da96f83ULL,
    0x660affff22e0a607ULL,
    0x29a317a586b19628ULL,
    0x8213584a8f2a0eabULL,
    0x366ae18a8e8e8972ULL,
    0x56b40f3ab8dffcb7ULL,
    0x390c8658eee4b3b6ULL,
    0xc471dc3f8f121e23ULL
};

static const uint64_t embedded_bytecode_chk_0004[] = {
    0x8d1a1aa8541995c1ULL,
    0x84cc663071c7e1d3ULL,
    0x69ed858f09b437c1ULL,
    0xf5e108b15d3a7f44ULL,
    0x8a7577f06ad26b5bULL,
    0xa2286ec6a9195e11ULL,
    0x578363af176cd35cULL,
    0xc8f391614bc8c562ULL,
    0x5e5aada84e2ef5bbULL,
    0xe4244da36c9e9428ULL,
    0xcc10daafc9c23526ULL,
    0xd2747a91d01206aeULL,
    0xbbf52584252dae9fULL,
    0x5e792ec61544d0d6ULL,
    0xcf135502cb4488b2ULL,
    0x74a508f4a79b0e78ULL,
    0x3c27af66ab3da069ULL,
    0x22394e2edb1a5ea6ULL,
    0x43b1a6a363e82e1aULL,
    0x5ceeb7f2cd77f87fULL,
    0x878d3400594c9c13ULL,
    0x64672323373620aeULL,
    0x763da834b648faedULL,
    0x76e299014c092006ULL,
    0x4141cedc9d04c1d0ULL,
    0x6c5debedc8b10496ULL,
    0x5b05b5b19dcab1f4ULL,
    0xcb09445c10015c3dULL,
    0xc3f01bd2620b87b5ULL,
    0x9050daf04c085a85ULL,
    0x8607064d7d2b5585ULL,
    0xb5ebc9770e2eb471ULL,
    0xcb0c80f5cd3b4045ULL,
    0x239f246ec3a5848fULL,
    0x1418430f7b668f20ULL,
    0x46bf3533dc199e2bULL,
    0x6a220ca29b1be376ULL,
    0x1ac8c23754858085ULL,
    0x8d7ee62fb244b363ULL,
    0x160ace4bdb950925ULL,
    0x95142523f92e35e1ULL,
    0xfca779f2ec7479edULL,
    0x7275efa23a8a147dULL,
    0xdef9597e78c846c0ULL,
    0xfe1d3df6706a3c85ULL,
    0xc144c0e456931cbdULL,
    0xa7162f6b0c3bbd30ULL,
    0x666783ce9c7562d0ULL,
    0x98fb85e226cd72d6ULL,
    0x60a6ee3bfaced8c3ULL,
    0xb264b27c48a10a12ULL,
    0xf2e179afa8474157ULL,
    0x2344642b99d72f3eULL,
    0x59e208abe707cfe2ULL,
    0x614f1014891c4829ULL,
    0x14cac65e4790fc2eULL,
    0xa3a743fe0edb8298ULL,
    0xe6b60a6f61176b0fULL,
    0x7a00fd6aa67a6265ULL,
    0xdf55111953106db0ULL,
    0xe68f4b21c4925a7bULL,
    0x35caf6a15f8d7c37ULL,
    0x2b5cbb6b5648fd23ULL,
    0x2ee4c142793f9826ULL
};

static const uint64_t embedded_bytecode_chk_0005[] = { 0x53c18c051085eccfULL, 0x7cd0f21478442d1cULL, 0xa836dd1abc49a4eaULL, 0x5451dd78aa413541ULL, 0x4006a13969480d9bULL, 0x2f8c292f40a008f4ULL, 0xddc1a98693da8ea3ULL, 0xfa1b2ae0cb396277ULL };

static const AsgardBytecodeChunk embedded_bytecode_chunks[6] = {
    {
        0x0000921cU,
        0x0000a553U,
        192,
        64,
        0x000000007f17cfeaULL,
        0x000000000001fd0aULL,
        { 0x82d1a7d26ee8cad0ULL, 0xceb21ab67b3c98f2ULL },
        embedded_bytecode_chk_0003
    },
    {
        0x0000b88aU,
        0xffffffffU,
        320,
        8,
        0x00000000a0852c40ULL,
        0x000000000002d11cULL,
        { 0x4f62aa616f43d286ULL, 0x46d1ae34450a76ecULL },
        embedded_bytecode_chk_0005
    },
    {
        0x0000a553U,
        0x0000b88aU,
        256,
        64,
        0x000000008fce7e15ULL,
        0x0000000000026713ULL,
        { 0x20aa2c1bee1e4ebbULL, 0x0ae064756a25cdf1ULL },
        embedded_bytecode_chk_0004
    },
    {
        0x00007ee5U,
        0x0000921cU,
        128,
        64,
        0x000000006e6121bfULL,
        0x0000000000019301ULL,
        { 0x6419398ceda346c5ULL, 0x955cd0f7085677f7ULL },
        embedded_bytecode_chk_0002
    },
    {
        0x00006baeU,
        0x00007ee5U,
        64,
        64,
        0x000000005daa7394ULL,
        0x00000000000128f8ULL,
        { 0xc640b3476c7dc2faULL, 0x596e89381971c2f8ULL },
        embedded_bytecode_chk_0001
    },
    {
        0x00005877U,
        0x00006baeU,
        0,
        64,
        0x000000004cf3c569ULL,
        0x000000000000beefULL,
        { 0x5877cafe1337beefULL, 0x1d38bf792e8899fdULL },
        embedded_bytecode_chk_0000
    }
};

static uint64_t embedded_bytecode[328];

static volatile int32_t embedded_bytecode_assembled = 0;

static inline void embedded_bytecode_ensure_assembled() {
                                                             if (!embedded_bytecode_assembled) {
                                                             
                                                                 for (size_t _idx = 0; _idx < 6; ++_idx) {
                                                                 
                                                                    const AsgardBytecodeChunk* c = (&embedded_bytecode_chunks[_idx]);
                                                                    if (c->canary != ((uint64_t)((((c->chunk_id * 0x0000deadU) + 0x0000cafeU) & 0xffffffffU)))) {
                                                                    
                                                                    ASG_CHUNK_TRAP();
                                                                    }
                                                                    uint64_t k_dyn = (0x5877a56a11223344ULL ^ (((uint64_t)(c->chunk_id)) * 0x9e3779b97f4a7c15ULL));
                                                                    for (size_t j = 0; j < ((int32_t)(c->word_count)); ++j) {
                                                                    
                                                                    uint64_t word_key = (k_dyn + (((uint64_t)(j)) * 0x00000100000001b3ULL));
                                                                    embedded_bytecode[(c->word_offset + j)] = (c->data[j] ^ word_key);
                                                                    }
                                                                 }
                                                                 ASG_CHUNK_BARRIER();
                                                                 embedded_bytecode_assembled = 1;
                                                             }
}

static __attribute__((constructor)) void embedded_bytecode_auto_init() {

    embedded_bytecode_ensure_assembled();
}

/**
 * Copyright (c) 2025 Kage Extension Enterprise Security
 */

#include "crypto.h"
#include "base64.h"
#include "kage_context.h"
#include "kage_config.h"
#include "bytecode_crypto.h"
#include "zend_compile.h"
#include "zend_execute.h"
#include "zend_smart_str.h"
#include "kage_memory.h"
#include "asgard_obf.h"
#include <sodium.h>

char* kage_compress_lzss(const char *i, size_t il, size_t *ol) {
    *ol = il;
    char *o = (char *)KAGE_ALLOC(il);
    if (!o) return NULL;
    memcpy(o, i, il);
    return o;
}

char* kage_decompress_lzss(const char *i, size_t il, size_t rl) {
    char *o = (char *)KAGE_ALLOC(rl + 1);
    if (!o) return NULL;
    size_t copy_len = il < rl ? il : rl;
    memcpy(o, i, copy_len);
    o[rl] = '\0';
    return o;
}

// Hash-KDF Key Derivation via libsodium BLAKE2b (crypto_generichash) - ASGARD Virtualized
static void kage_derive_effective_key_vm(unsigned char derived_key[32], const unsigned char master_key[32], const char *context_salt, size_t salt_len) {
    embedded_bytecode_ensure_assembled();
    vanguard_threaded_vm::asgard_vm_call(embedded_bytecode, sizeof(embedded_bytecode) / sizeof(embedded_bytecode[0]), (uint64_t)derived_key, (uint64_t)master_key, (uint64_t)(uintptr_t)context_salt, (uint64_t)salt_len);
    return;
}

static void kage_derive_effective_key(unsigned char derived_key[32], const unsigned char master_key[32], const char *hwid) {
    const char *context_salt = (hwid && strlen(hwid) > 0) ? hwid : "KAGE_GLOBAL_KEY_SALT_v2";
    kage_derive_effective_key_vm(derived_key, master_key, context_salt, strlen(context_salt));
}

int kage_raw_decrypt(zval *rv, const unsigned char *d, size_t dl, zend_string *k, uint32_t *os) {
    if (dl < sizeof(kage_header_t) + crypto_aead_chacha20poly1305_ietf_ABYTES) {
        return FAILURE;
    }
    kage_header_t *h = (kage_header_t*)d;
    if (memcmp(h->magic, KAGE_HEADER_MAGIC, 4) != 0) {
        return FAILURE;
    }
    if (os) *os = h->seed;

    unsigned char derived_key[32];
    if (h->flags & KAGE_FLAG_HWID) {
        char *mid = kage_get_machine_id();
        if (!mid) {
            return FAILURE;
        }
        kage_derive_effective_key(derived_key, (const unsigned char*)ZSTR_VAL(k), mid);
        efree(mid);
    } else {
        kage_derive_effective_key(derived_key, (const unsigned char*)ZSTR_VAL(k), NULL);
    }

    const unsigned char *ciphertext = d + sizeof(kage_header_t);
    size_t ciphertext_len = dl - sizeof(kage_header_t);

    size_t plaintext_len = ciphertext_len - crypto_aead_chacha20poly1305_ietf_ABYTES;
    unsigned char *p = (unsigned char *)KAGE_ALLOC(plaintext_len + 1);
    unsigned long long decrypted_len_out = 0;

    // ChaCha20-Poly1305 IETF AEAD Decryption with Header as Authenticated Data (AAD)
    if (crypto_aead_chacha20poly1305_ietf_decrypt(
            p, &decrypted_len_out,
            NULL,
            ciphertext, ciphertext_len,
            (const unsigned char*)h, sizeof(kage_header_t),
            h->nonce, derived_key) != 0) {
        sodium_memzero(derived_key, sizeof(derived_key));
        efree(p);
        return FAILURE;
    }

    p[decrypted_len_out] = '\0';
    ZVAL_STRINGL(rv, (char *)p, decrypted_len_out);

    // RAM Memory Zeroization
    sodium_memzero(p, decrypted_len_out);
    sodium_memzero(derived_key, sizeof(derived_key));
    efree(p);
    return SUCCESS;
}

PHP_FUNCTION(kage_encrypt_c) {
    zval *c; zend_string *k, *h_in = NULL, *d_in = NULL;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "zS|S!S!", &c, &k, &h_in, &d_in) == FAILURE) RETURN_FALSE;
    if (ZSTR_LEN(k) != 32) RETURN_FALSE;
    if (Z_TYPE_P(c) != IS_STRING) convert_to_string(c);
    
    kage_header_t h;
    memset(&h, 0, sizeof(h));
    memcpy(h.magic, KAGE_HEADER_MAGIC, 4);
    h.version = 2;
    randombytes_buf(&h.seed, sizeof(h.seed));
    randombytes_buf(h.nonce, sizeof(h.nonce)); // Unique random 12-byte AEAD Nonce per file

    unsigned char derived_key[32];
    if (h_in && ZSTR_LEN(h_in) > 0) {
        h.flags |= KAGE_FLAG_HWID;
        memcpy(h.hwid, ZSTR_VAL(h_in), ZSTR_LEN(h_in) < 31 ? ZSTR_LEN(h_in) : 31);
        kage_derive_effective_key(derived_key, (const unsigned char*)ZSTR_VAL(k), h.hwid);
    } else {
        kage_derive_effective_key(derived_key, (const unsigned char*)ZSTR_VAL(k), NULL);
    }

    if (d_in && ZSTR_LEN(d_in) > 0) {
        h.flags |= KAGE_FLAG_DOMAIN;
        memcpy(h.domain, ZSTR_VAL(d_in), ZSTR_LEN(d_in) < 31 ? ZSTR_LEN(d_in) : 31);
    }

    size_t plaintext_len = Z_STRLEN_P(c);
    h.payload_len = (uint32_t)(plaintext_len + crypto_aead_chacha20poly1305_ietf_ABYTES);
    h.crc32 = kage_crc32((const unsigned char*)Z_STRVAL_P(c), plaintext_len);

    size_t max_ciphertext_len = plaintext_len + crypto_aead_chacha20poly1305_ietf_ABYTES;
    unsigned char *cv = (unsigned char *)KAGE_ALLOC(max_ciphertext_len);
    unsigned long long ciphertext_len_out = 0;

    // ChaCha20-Poly1305 IETF AEAD Encryption with Header as Authenticated Data (AAD)
    crypto_aead_chacha20poly1305_ietf_encrypt(
        cv, &ciphertext_len_out,
        (const unsigned char*)Z_STRVAL_P(c), plaintext_len,
        (const unsigned char*)&h, sizeof(h),
        NULL, h.nonce, derived_key
    );
    sodium_memzero(derived_key, sizeof(derived_key));

    size_t tl = sizeof(h) + ciphertext_len_out;
    unsigned char *cb = (unsigned char *)KAGE_ALLOC(tl);
    memcpy(cb, &h, sizeof(h));
    memcpy(cb + sizeof(h), cv, ciphertext_len_out);
    
    size_t el; char *e = kage_base64_encode(cb, tl, &el);
    efree(cb); efree(cv); if (!e) RETURN_FALSE;
    ZVAL_STRINGL(return_value, e, el); efree(e);
}

PHP_FUNCTION(kage_decrypt_c) {
    zval *e; zend_string *k;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "zS", &e, &k) == FAILURE) RETURN_FALSE;
    if (ZSTR_LEN(k) != 32) RETURN_FALSE;
    if (Z_TYPE_P(e) != IS_STRING) convert_to_string(e);
    size_t dl; unsigned char *d = kage_base64_decode(Z_STRVAL_P(e), Z_STRLEN_P(e), &dl);
    if (!d) RETURN_FALSE;
    uint32_t s; if (kage_raw_decrypt(return_value, d, dl, k, &s) == SUCCESS) { efree(d); } else { efree(d); RETURN_FALSE; }
}

PHP_FUNCTION(kage_get_machine_id) {
    char *m = kage_get_machine_id();
    if (m) { RETVAL_STRING(m); efree(m); } else RETURN_FALSE;
}

int kage_internal_encrypt(zval *rv, zval *d, zend_string *k) { return FAILURE; }
int kage_internal_decrypt(zval *rv, zval *ed, zend_string *k) { return FAILURE; }
