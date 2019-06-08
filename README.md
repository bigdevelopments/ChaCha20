# ChaCha
C# implementation of ChaCha20 stream cipher algorithm.

This is a fairly straight forward implementation of the ChaCha stream cipher algorithm as described on Wikipedia (https://en.wikipedia.org/wiki/Salsa20). The call is abstracted into an interface, and there are two implementations - the simple one which is just a straight code up, and the rapid one which ditches the state array in favour of member and local variables. It is very much quicker.

Worth noting that Wikipedia talks of an 8 byte nonce and 8 byte counter, but later specifications use a 12 byte nonce and 4 byte counter, which is the approach used here.

This hasn't been tested against an alternative reference implementation, but I'm using it for local file encryption.

Basics are:

* Create a 32 byte key (derived for a password most likely using some hashing technique).
* Create a 12 byte nonce - a random 12 bytes, this should be different every time an encryption is performed.
* Construct the RapidChaCha object using the above.
* Call one of the Transform overloads to encrypt or decrypt a buffer. If doing this repeatedly for streaming, make sure that the buffers presented are multiple of 64 bytes to prevent counter corruption.
