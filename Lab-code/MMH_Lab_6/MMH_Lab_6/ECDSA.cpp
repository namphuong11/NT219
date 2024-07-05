#include <cryptopp/eccrypto.h>
#include <cryptopp/osrng.h>
#include <cryptopp/oids.h>
#include <cryptopp/integer.h>
#include <cryptopp/nbtheory.h>
#include <cryptopp/sha.h>
#include <cryptopp/base64.h>
#include <cryptopp/files.h>
#include <cryptopp/queue.h>
#include <cryptopp/hex.h>
#include <iostream>
#include <fstream>
#include <string>
#include <cryptopp/xed25519.h> // curve 25519

using namespace CryptoPP;

/*
Secure curves
https://safecurves.cr.yp.to/
https://datatracker.ietf.org/doc/html/rfc7748
https://datatracker.ietf.org/doc/html/rfc8410
https://datatracker.ietf.org/doc/html/rfc9295
Convert curves
https://crypto.stackexchange.com/questions/27842/edwards-montgomery-ecc-with-weierstrass-implementation
https://www-fourier.univ-grenoble-alpes.fr/mphell/doc-v5/conversion_weierstrass_edwards.html
https://neuromancer.sk/std/other/M-511
*/

// Any elliptic curve can be written in Weierstrass form
// Conversion Functions
using namespace CryptoPP;

// Convert Montgomery (A, B) to Weierstrass (a, b)
// a = (3 - A^2) / (3 * B^2) mod p
// b = (2 * A^3 - 9 * A) / (27 * B^3) mod p
// (x,y) -> ( x/B + A/(3*B), y/B )

void convertMontgomeryToWeierstrass(const Integer &p, const Integer &A, const Integer &B,
                                    Integer &a, Integer &b)
{
    Integer A_squared = (A * A) % p;
    Integer B_squared = (B * B) % p;
    Integer B_cubed = (B_squared * B) % p;
    ModularArithmetic ma(p);

    a = ma.Multiply(3 - A_squared, ma.MultiplicativeInverse(3 * B_squared)) % p;
    b = ma.Multiply(2 * A * A_squared - 9 * A, ma.MultiplicativeInverse(27 * B_cubed)) % p;
}

void convertBasePointMontgomeryToWeierstrass(const Integer &p, const Integer &A,
                                             Integer &B, const Integer &u,
                                             const Integer &v, Integer &x, Integer &y)
{
    Integer B_inv = B.InverseMod(p);
    x = (u + A / 3) * B_inv % p;
    y = v * B_inv % p;
}


int main()
{
}