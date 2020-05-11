#include <stdlib.h>
#include <CUnit/Basic.h>

#include "crystal.h"

static void base58_test(void)
{
    uint8_t pk[32] = {0};
    uint8_t sk[32] = {0};
    char base58[65] = {0};
    size_t len = sizeof(base58);
    char *p;
    int rc;
    ssize_t bytes;

#if defined(ENABLE_CRYPTO)
    rc = crypto_create_keypair(pk, sk);
    CU_ASSERT_EQUAL(rc, 0);
#else
    memset(pk, 0xFF, sizeof(pk));
#endif

    memset(sk, 0, sizeof(sk));

    p = base58_encode(pk, sizeof(pk), base58, &len);
    CU_ASSERT_PTR_EQUAL(p, base58);

    bytes = base58_decode(base58, sizeof(base58), sk, sizeof(sk));
    CU_ASSERT_EQUAL(bytes, sizeof(sk));
    CU_ASSERT_TRUE(memcmp(pk, sk, sizeof(pk)) == 0);
}

static void base58_test_length(void)
{
    uint8_t pk[80] = {0};
    uint8_t sk[80] = {0};
    char base58[256] = {0};
    size_t len = sizeof(base58);
    char *p;
    int rc;
    ssize_t bytes;

#if defined(ENABLE_CRYPTO)
    rc = crypto_create_keypair(pk, sk);
    CU_ASSERT_EQUAL(rc, 0);
    rc = crypto_create_keypair(pk + 32, sk + 32);
    CU_ASSERT_EQUAL(rc, 0);
#else
    memset(pk, 0xFF, sizeof(pk));
#endif

    memset(sk, 0, sizeof(sk));

    p = base58_encode(pk, sizeof(pk), base58, &len);
    CU_ASSERT_PTR_EQUAL(p, base58);

    bytes = base58_decode(base58, sizeof(base58), sk, sizeof(sk));
    CU_ASSERT_EQUAL(bytes, sizeof(sk));
    CU_ASSERT_TRUE(memcmp(pk, sk, sizeof(pk)) == 0);
}

static void base58_test_deprecated(void)
{
    uint8_t pk[32] = {0};
    uint8_t sk[32] = {0};
    char base58[65] = {0};
    size_t len = sizeof(base58);
    char base58_orig[65] = {0};
    //size_t len_orig=sizeof(base58_orig);
    size_t len_orig = 45;
    char *p;
    char *p_orig;
    int rc;
    ssize_t bytes;

#if defined(ENABLE_CRYPTO)
    rc = crypto_create_keypair(pk, sk);
    CU_ASSERT_EQUAL(rc, 0);
#else
    memset(pk, 0xFF, sizeof(pk));
#endif

    memset(sk, 0, sizeof(sk));

    p = base58_encode(pk, sizeof(pk), base58, &len);
    CU_ASSERT_PTR_EQUAL(p, base58);

    p_orig = base58_encode_deprecated(pk, sizeof(pk), base58_orig, &len_orig);
    //CU_ASSERT_EQUAL(p_orig, base58_orig);

    printf(" new: (%zu) %s\n", len, p);
    printf("orig: (%zu) %s\n", len_orig, base58_orig);
}

static int base58_test_suite_init(void)
{
    return 0;
}

static int base58_test_suite_cleanup(void)
{
    return 0;
}

static CU_TestInfo cases[] = {
    { "base58_test", base58_test },
    { "base58_test_length", base58_test_length },
    { "base58_test_deprecated", base58_test_deprecated},
    { NULL, NULL }
};

static CU_SuiteInfo suite[] = {
    {
        "base58 test",
        base58_test_suite_init,
        base58_test_suite_cleanup,
        NULL,
        NULL,
        cases
    },
    {
        NULL
    }
};

CU_SuiteInfo* base58_test_suite_info(void)
{
    return suite;
}
