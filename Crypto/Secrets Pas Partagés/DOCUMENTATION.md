# Section 3.1.1: DHutlock key exchange protocol

The modulus is the strong prime number (256 bits)

p = 0xff536875746c6f636b43544632303235bace001e54b565992d1483b7a59b8363

The curve and generator point G are specified in section 2.3.1

The key exchange protocol format is:

0. Client and server choose cryptographically secure random numbers a and b

1. The client sends a curve point P=aG in the following format

   0x40 (length of data, always 0x40)
   X coordinate (32 bytes, big-endian)
   Y coordinate (32 bytes, big-endian)

2. The server sends a curve point Q=bG in the following format

   0x40 (length of data, always 0x40)
   X coordinate (32 bytes, big-endian)
   Y coordinate (32 bytes, big-endian)

3. Both client and server compute a shared point S=abG using ordinary Diffie-Hellman

   The shared key is the SHA256 (32 bytes) of the 64 bytes:

   X coordinate of S (32 bytes, big-endian)
   Y coordinate of S (32 bytes, big-endian)

Example:

   Client sends point P:
   Px = 0x3fd30c050b6b2eb80ee49ea10afc275c7619d7e14e07d0e9ca086008de4f3c86
   Py = 0x688d8a0162f366891ccfcc36d7c0441a298c1df60a0ab60e2ad21ad3a2ad31ce

   Server sends point Q:
   Qx = 0xdfb60def45e447cdbb9e1643bbd09b32e5c8498de89e065b4196b547ae3d5209
   Qy = 0x71d66f8569df1688b0d9ce36feec7b0c13ac9c7dc6f917025c19bd6718c5dc44

   Client and server compute the shared secret S
   Sx = 0xe64dcf7477910072ff630d68ff11a7f5ba2080a1f1399e4119a49c55f609fecf
   Sy = 0xd90e966e860e4990da7a80ee89db76d4143c8c12d2e21a01b6321f27fffcc2d6

   The shared key is 32 bytes:

   a9098b435f3c738f787a2accb172c0398a385c86c17f00ed1039dd8fdac53594

The session data for a given direction is:

   IV (16 bytes)
   Data (encrypted using AES-CBC using shared key and IV)
