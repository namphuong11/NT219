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

// Convert Montgomery (A, B) to Weierstrass (a, b)
// a = (3 - A^2) / (3 * B^2) mod p
// b = (2 * A^3 - 9 * A) / (27 * B^3) mod p
// (x,y) -> ( x/B + A/(3*B), y/B )

// Function to convert Montgomery curve parameters (A, B) to Weierstrass parameters (a, b)
void convertMontgomeryToWeierstrass(const Integer &p, const Integer &A, const Integer &B, Integer &a, Integer &b)
{
    Integer A_squared = (A * A) % p;
    Integer B_squared = (B * B) % p;
    Integer B_cubed = (B_squared * B) % p;
    ModularArithmetic ma(p); // Initialize modular arithmetic with modulus p

    a = ma.Multiply(3 - A_squared, ma.MultiplicativeInverse(3 * B_squared));
    b = ma.Multiply(2 * A * A_squared - 9 * A, ma.MultiplicativeInverse(27 * B_cubed));
}

// Function to convert a base point from Montgomery to Weierstrass form
void convertBasePointMontgomeryToWeierstrass(const Integer &p, const Integer &A, const Integer &B,
                                                const Integer &Gx, const Integer &Gy,
                                                Integer &x, Integer &y)
{
    Integer a, b;
    convertMontgomeryToWeierstrass(p, A, B, a, b);

    Integer X_over_B = Gx / B;
    Integer A_over_3B = A / (3 * B);

    ModularArithmetic ma(p);
    x = ma.Add(X_over_B, A_over_3B);
    y = ma.Add(Gy, A_over_3B);
}

// Function to save curve parameters as PEM file
void saveAsPEM(const char *outFileName, const Integer &p, const Integer &a, const Integer &b,
                const Integer &Gx, const Integer &Gy, const Integer &n, const Integer &h)
{
    std::ofstream outFile(outFileName);
    if (!outFile)
    {
        std::cerr << "Error opening output file." << std::endl;
        return;
    }

    // Encode parameters in DER format
    ByteQueue derQueue;
    p.DEREncode(derQueue);
    a.DEREncode(derQueue);
    b.DEREncode(derQueue);
    Gx.DEREncode(derQueue);
    Gy.DEREncode(derQueue);
    n.DEREncode(derQueue);
    h.DEREncode(derQueue);
    derQueue.MessageEnd();

    // Convert DER to Base64
    std::string encoded;
    Base64Encoder encoder(new StringSink(encoded), true, 64);
    derQueue.CopyTo(encoder);
    encoder.MessageEnd();

    // Write to PEM file
    outFile << "-----BEGIN EC PARAMETERS-----\n";
    outFile << encoded;
    outFile << "-----END EC PARAMETERS-----\n";
    outFile.close();
}

int main(int argc, char *argv[])
{
    // Curve M-383 parameters
    Integer p("0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF45");
    Integer A("0x1f82fe");
    Integer B("0x01");
    Integer Gx("0x0c");
    Integer Gy("0x1ec7ed04aaf834af310e304b2da0f328e7c165f0e8988abd3992861290f617aa1f1b2e7d0b6e332e969991b62555e77e");
    Integer n("0x10000000000000000000000000000000000000000000000006C79673AC36BA6E7A32576F7B1B249E46BBC225BE9071D7");
    Integer h("0x08");


    ECP curve(p, A, B); 

    ECP::Point G(Gx, Gy);            // Base point
    DL_GroupParameters_EC<ECP> M383; // Curve group
    M383.Initialize(curve, G, n, h); // Initialize ECC parameters

    // Print out parameters
    std::cout << "Prime p: " << std::hex << p << std::endl;
    std::cout << "Coefficient A: " << std::hex << A << std::endl;
    std::cout << "Coefficient B: " << std::hex << B << std::endl;
    std::cout << "Base point Gx: " << std::hex << Gx << std::endl;
    std::cout << "Base point Gy: " << std::hex << Gy << std::endl;
    std::cout << "Order n: " << std::hex << n << std::endl;
    std::cout << "Cofactor h: " << std::hex << h << std::endl;

    // Convert base point to Weierstrass form
    Integer x, y;
    convertBasePointMontgomeryToWeierstrass(p, A, B, Gx, Gy, x, y);
    std::cout << "Base point (Weierstrass form): (" << std::hex << x << ", " << y << ")" << std::endl;
    // Save as PEM
    saveAsPEM("curve-M-383.pem", p, A, B, x, y, n, h);

    return 0;
}
