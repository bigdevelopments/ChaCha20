using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace BigDevelopments.ChaCha
{
	/// <summary>
	/// Simple little thing for encrypting/decrypting strings just for the purposes of demonstrating use
	/// </summary>
	public class ExampleStringEncryptor
	{
		// the ChaCha algorithm
		private readonly IStreamCipher _streamCipher;

		// the secret key
		private readonly byte[] _key;

		public ExampleStringEncryptor(string password, IStreamCipher encryptor = null)
		{
			// use the rapid implementation unless told otherwise
			_streamCipher = encryptor ?? new RapidChaCha();

			// we need to convert the password to a 32 byte key. Below is an unbrilliant way of doing that
			SHA1CryptoServiceProvider sha1 = new SHA1CryptoServiceProvider();
			_key = sha1.ComputeHash(Encoding.UTF8.GetBytes(password))
				.Concat(sha1.ComputeHash(Encoding.UTF8.GetBytes("XX" + password)))
				.Take(32).ToArray();
		}

		public byte[] Encrypt(string value)
		{
			// when encrypting, you need a 'nonce' - 'number once'. By changing this on each encryption, you end up with different output each time
			// without it you apply identical encryption for each key which would be a vulnerability. It's like seeding a random number generator.
			byte[] nonce = new byte[12];

			// shouldn't use this, not random enough, but its good enough for this demo
			new Random().NextBytes(nonce);

			// initialise the algorithm with the key (password) and nonce
			_streamCipher.SetState(_key, nonce);

			// convert our string to a byte array
			byte[] data = Encoding.UTF8.GetBytes(value);

			// encrypt it
			_streamCipher.Transform(data);

			// now return the nonce (first 12 bytes) and the encrypted data as one array
			return nonce.Concat(data).ToArray();
		}

		public string Decrypt(byte[] data)
		{
			// do decrypt we need the nonce again, the method above sticks it in the first 12 bytes of the data
			byte[] nonce = new byte[12];
			Array.Copy(data, 0, nonce, 0, 12);

			// initialise the algorithm with the key (password) and nonce from start of data
			_streamCipher.SetState(_key, nonce);

			// decrypt it
			_streamCipher.Transform(data, 12, data.Length - 12);

			// and turn it back into a string, stepping over the first 12 bytes
			return Encoding.UTF8.GetString(data, 12, data.Length - 12);
		}
	}
}
