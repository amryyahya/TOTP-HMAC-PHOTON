#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define D 7
#define S 4

#define N 40
//  160/S

#define R 9
// 36/S

int sbox[] = {0xc, 0x5, 0x6, 0xb, 0x9, 0x0, 0xa, 0xd, 0x3, 0xe, 0xf, 0x8, 0x4, 0x7, 0x1, 0x2};
int RC[] = {1, 3, 7, 14, 13, 11, 6, 12, 9, 2, 5, 10};
int IC[] = {0, 1, 2, 5, 3, 6, 4};
int M[D][D] = {
    {1, 4, 6, 1, 1, 6, 4},
    {4, 2, 15, 2, 5, 10, 5},
    {5, 3, 15, 10, 7, 8, 13},
    {13, 4, 11, 2, 7, 15, 9},
    {9, 15, 7, 2, 11, 4, 13},
    {13, 8, 7, 10, 15, 3, 5},
    {5, 10, 5, 2, 15, 2, 4}};
int FieldMult[16][16] = {
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {0, 2, 4, 6, 8, 10, 12, 14, 3, 1, 7, 5, 11, 9, 15, 13},
    {0, 3, 6, 5, 12, 15, 10, 9, 11, 8, 13, 14, 7, 4, 1, 2},
    {0, 4, 8, 12, 3, 7, 11, 15, 6, 2, 14, 10, 5, 1, 13, 9},
    {0, 5, 10, 15, 7, 2, 13, 8, 14, 11, 4, 1, 9, 12, 3, 6},
    {0, 6, 12, 10, 11, 13, 7, 1, 5, 3, 9, 15, 14, 8, 2, 4},
    {0, 7, 14, 9, 15, 8, 1, 6, 13, 10, 3, 4, 2, 5, 12, 11},
    {0, 8, 3, 11, 6, 14, 5, 13, 12, 4, 15, 7, 10, 2, 9, 1},
    {0, 9, 1, 8, 2, 11, 3, 10, 4, 13, 5, 12, 6, 15, 7, 14},
    {0, 10, 7, 13, 14, 4, 9, 3, 15, 5, 8, 2, 1, 11, 6, 12},
    {0, 11, 5, 14, 10, 1, 15, 4, 7, 12, 2, 9, 13, 6, 8, 3},
    {0, 12, 11, 7, 5, 9, 14, 2, 10, 6, 1, 13, 15, 3, 4, 8},
    {0, 13, 9, 4, 1, 12, 8, 5, 2, 15, 11, 6, 3, 14, 10, 7},
    {0, 14, 15, 1, 13, 3, 2, 12, 9, 7, 6, 8, 4, 10, 11, 5},
    {0, 15, 13, 2, 9, 6, 4, 11, 1, 14, 12, 3, 8, 7, 5, 10}};

void addConstant(int State[D][D], int k)
{
    for (int i = 0; i < D; i++)
    {
        State[i][0] = State[i][0] ^ RC[k] ^ IC[i];
    }
}

void subCells(int State[D][D])
{
    for (int i = 0; i < D; i++)
    {
        for (int j = 0; j < D; j++)
        {
            State[i][j] = sbox[State[i][j]];
        }
    }
}

void shiftRows(int State[D][D])
{
    int i, j;
    int tmp[D];
    for (i = 1; i < D; i++)
    {
        for (j = 0; j < D; j++)
            tmp[j] = State[i][j];
        for (j = 0; j < D; j++)
            State[i][j] = tmp[(j + i) % D];
    }
}

void MixColumnsSerial(int state[D][D])
{
    int tmp[D];
    for (int j = 0; j < D; j++)
    {
        for (int i = 0; i < D; i++)
        {
            int sum = 0;
            for (int k = 0; k < D; k++)
            {
                sum ^= FieldMult[M[i][k]][state[k][j]];
            }
            tmp[i] = sum;
        }
        for (int i = 0; i < D; i++)
        {
            state[i][j] = tmp[i];
        }
    }
}

void permutation(int State[D][D])
{
    for (int i = 0; i < 12; i++)
    {
        addConstant(State, i);
        subCells(State);
        shiftRows(State);
        MixColumnsSerial(State);
    }
}

int photon160(int *plainText, int plainLength, int *digest)
{
    int remains = R - (plainLength % R);
    int plainArray[plainLength + remains];
    for (int i = 0; i < plainLength; i++)
    {
        plainArray[i] = plainText[i];
    }

    if (remains != R)
    {
        plainArray[plainLength++] = 8;
        for (int i = 0; i < remains - 1; i++)
        {
            plainArray[plainLength++] = 0;
        }
    }
    int State[D][D] = {
        {0, 0, 0, 0, 0, 0, 0},
        {0, 0, 0, 0, 0, 0, 0},
        {0, 0, 0, 0, 0, 0, 0},
        {0, 0, 0, 0, 0, 0, 0},
        {0, 0, 0, 0, 0, 0, 0},
        {0, 0, 0, 0, 0, 0, 0},
        {0, 2, 8, 2, 4, 2, 4},
    };
    int k = 0;
    while (plainLength > 0)
    {
        for (int i = 0; i < D; i++)
        {
            State[0][i] = State[0][i] ^ plainArray[k++];
        }
        for (int i = 0; i < 2; i++)
        {
            State[1][i] = State[1][i] ^ plainArray[k++];
        }
        permutation(State);
        plainLength -= R;
    }
    for (int i = 0; i < N; i += R)
    {
        for (int j = i; j < i + R; j++)
        {
            if (j > N)
                return 0;
            if (j % 9 > D)
            {
                digest[j] = State[1][j % 9 - 7];
            }
            else
                digest[j] = State[0][j % 9];
        }
        permutation(State);
    }
}

int getTruncatedHMACPhoton(int *secretKey, int *time, int keyLengthBytes, int timeLengthBytes)
{
    int keyLength = keyLengthBytes * 2;
    int key[keyLength];
    for (int i = 0; i < keyLengthBytes; ++i)
    {
        for (int j = 0; j < 8; j += 4)
        {
            key[i * 2 + j / 4] = (secretKey[i] >> (4 - j)) & 0xF;
        }
    }
    int messageLength = timeLengthBytes * 2;
    int message[messageLength];
    for (int i = 0; i < timeLengthBytes; ++i)
    {
        for (int j = 0; j < 8; j += 4)
        {
            message[i * 2 + j / 4] = (time[i] >> (4 - j)) & 0xF;
        }
    }
    int hashedKey[N];
    photon160(key, keyLength, hashedKey);
    int outerPad[N], innerPad[N];
    for (int i = 0; i < N; i++)
    {
        if (i % 2 == 0)
        {
            outerPad[i] = hashedKey[i] ^ 0x5;
            innerPad[i] = hashedKey[i] ^ 0x3;
        }
        else
        {
            outerPad[i] = hashedKey[i] ^ 0xc;
            innerPad[i] = hashedKey[i] ^ 0x6;
        }
    }
    int innerMessage[N + messageLength];
    for (int i = 0; i < N; i++)
    {
        innerMessage[i] = hashedKey[i];
        if (i < messageLength)
            innerMessage[i + N] = message[i];
    }
    int hashedConcen[N];
    photon160(innerMessage, N + messageLength, hashedConcen);
    int outerMessage[2 * N];
    for (int i = 0; i < N; i++)
    {
        outerMessage[i] = outerPad[i];
        outerMessage[i + N] = hashedConcen[i];
    }
    int hmac_value[N];
    photon160(outerMessage, N * 2, hmac_value);
    __uint32_t truncated = 0;
    for (int i = hmac_value[N - 1]; i < hmac_value[N - 1] + 8; i++)
    {
        truncated = (truncated << 4) | hmac_value[i];
    }
    return truncated % 1000000;
}

int main()
{
    int message[] = {2, 3, 2, 1, 3, 5};
    int key[40];
        clock_t begin = clock();

    for (int i = 0; i < 40; i++)
    {
        key[i] = rand() % 16;
    }
    int totp = getTruncatedHMACPhoton(key, message, 40, 6);
    clock_t end = clock();
    
    printf("%d",totp);
    double time_spent = (double)(end - begin) / CLOCKS_PER_SEC;
    printf("execution time:%f seconds\n", time_spent);
    return 0;
}