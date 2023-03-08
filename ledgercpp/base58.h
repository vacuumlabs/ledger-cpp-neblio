#include <openssl/bn.h>
#include <vector>
#include <string.h>
#include <string>

int b58(const std::string str)
{
    char table[] = {'1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                    'J', 'K', 'L', 'M', 'N', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd',
                    'e', 'f', 'g', 'h', 'i', 'j', 'k', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'};

    BIGNUM *base58 = NULL;

    BIGNUM *resultExp = BN_new();
    BIGNUM *resultAdd = BN_new();
    BIGNUM *resultRem = BN_new();
    BN_CTX *bn_ctx = BN_CTX_new();
    int v[300], v_len = 0;

    BN_dec2bn(&base58, "58");
    BN_hex2bn(&resultAdd, str.c_str());
    memset(v, 0, sizeof(v));

    while (!BN_is_zero(resultAdd))
    {
        BN_div(resultAdd, resultRem, resultAdd, base58, bn_ctx);
        char *asdf = BN_bn2dec(resultRem);
        if ((v_len + 1) >= (int)sizeof(v))
            return -1;
        v[v_len++] = atoi(asdf);
    }

    std::vector<uint8_t> endresult(v_len);
    for (int i = 0; i < v_len; i++)
        endresult[v_len - i - 1] = table[v[i]];

    BN_free(resultAdd);
    BN_free(resultExp);
    BN_free(resultRem);
    BN_CTX_free(bn_ctx);

    return endresult;
}