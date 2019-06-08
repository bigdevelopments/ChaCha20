using System;

namespace BigDevelopments.ChaCha
{
	/// <summary>
	/// Simple implementation of ChaCha20, not very optimised. Based principally on the Wikipedia page https://en.wikipedia.org/wiki/Salsa20
	/// Actual specification is https://tools.ietf.org/html/rfc7539. Original version of ChaCha had 8 byte nonce and 8 byte counter, but this
	/// was change in later specification to a 4 byte counter and 12 byte nonce, which is what's used here
	/// </summary>
	/// <remarks>
	/// Here for reference, use RapidChaCha instead
	/// </remarks>
	public class SimpleChaCha : IStreamCipher
	{
		// the 4x4 state matrix of unsigned 32bit words as single dimension array
		private readonly uint[] _state;

		public SimpleChaCha()
		{
			// state consists of sixteen 32bit unsiged words
			_state = new uint[16];
		}

		public SimpleChaCha(byte[] key, byte[] nonce, uint counter = 0)
		{
			// state consists of sixteen 32bit unsiged words
			_state = new uint[16];

			// inititalise the state with the constant and the supplied key, nonce and counter
			SetState(key, nonce, counter);
		}

		public void SetState(byte[] key, byte[] nonce, uint counter = 0)
		{
			// keys and IVs must be correct size
			if (key == null || key.Length != 32) throw new ArgumentOutOfRangeException(nameof(key), "Must be a 32 byte (256 bit) array");
			if (nonce == null || nonce.Length != 12) throw new ArgumentOutOfRangeException(nameof(nonce), "Must be a 12 byte (96 bit) array");

			// set up the initial value of state according to constant, key, nonce and counter constituents..
			// first four words are the (arbitary although standardised) constants
			_state[0] = 0x61707865;
			_state[1] = 0x3320646e;
			_state[2] = 0x79622d32;
			_state[3] = 0x6b206574;

			// the next 8 words contain the key
			_state[4] = key[0] | (uint)key[1] << 8 | (uint)key[2] << 16 | (uint)key[3] << 24;
			_state[5] = key[4] | (uint)key[5] << 8 | (uint)key[6] << 16 | (uint)key[7] << 24;
			_state[6] = key[8] | (uint)key[9] << 8 | (uint)key[10] << 16 | (uint)key[11] << 24;
			_state[7] = key[12] | (uint)key[13] << 8 | (uint)key[14] << 16 | (uint)key[15] << 24;
			_state[8] = key[16] | (uint)key[17] << 8 | (uint)key[18] << 16 | (uint)key[19] << 24;
			_state[9] = key[20] | (uint)key[21] << 8 | (uint)key[22] << 16 | (uint)key[23] << 24;
			_state[10] = key[24] | (uint)key[25] << 8 | (uint)key[26] << 16 | (uint)key[27] << 24;
			_state[11] = key[28] | (uint)key[29] << 8 | (uint)key[30] << 16 | (uint)key[31] << 24;

			// the next one is the counter
			_state[12] = counter;

			// the final 3 words are the 'nonce'
			_state[13] = nonce[0] | (uint)nonce[1] << 8 | (uint)nonce[2] << 16 | (uint)nonce[3] << 24;
			_state[14] = nonce[4] | (uint)nonce[5] << 8 | (uint)nonce[6] << 16 | (uint)nonce[7] << 24;
			_state[15] = nonce[8] | (uint)nonce[9] << 8 | (uint)nonce[10] << 16 | (uint)nonce[11] << 24;
		}

		public uint Counter
		{
			get { return _state[12]; }
			set { _state[12] = value; }
		}

		/// <summary>
		/// Transforms (decrypts/encrypts) and copies the data in the source array to the destination array
		/// </summary>
		public void Transform(byte[] source, byte[] destination, int start, int length)
		{
			if (source == null) throw new ArgumentNullException(nameof(source));
			if (destination == null) throw new ArgumentNullException(nameof(destination));
			if (source.Length != destination.Length) throw new ArgumentNullException(nameof(destination), "Destination buffer differs in size from source buffer");
			source.CopyTo(destination, 0);
			Transform(destination, start, length);
		}

		/// <summary>
		/// Transforms (decrypts/encrypts) the data in place in the supplied buffer
		/// </summary>
		public void Transform(byte[] buffer)
		{
			Transform(buffer, 0, buffer.Length);
		}

		/// <summary>
		/// Transforms (decrypts/encrypts) the data in place in the supplied buffer
		/// </summary>
		public void Transform(byte[] buffer, int start, int length)
		{
			// state per 64 byte block
			uint[] blockState = new uint[16];

			// output
			byte[] output = new byte[64];

			// XORing cursor we'll move over the array
			int cursor = start;

			while (cursor < start + length)
			{
				// make a local copy of the state
				_state.CopyTo(blockState, 0);

				// go mental on it for 20 round (2 rounds per iteration)
				for (int index = 0; index < 10; index++)
				{
					// column rounds
					QR(ref blockState[0], ref blockState[4], ref blockState[8], ref blockState[12]);
					QR(ref blockState[1], ref blockState[5], ref blockState[9], ref blockState[13]);
					QR(ref blockState[2], ref blockState[6], ref blockState[10], ref blockState[14]);
					QR(ref blockState[3], ref blockState[7], ref blockState[11], ref blockState[15]);

					// diagnal rounds
					QR(ref blockState[0], ref blockState[5], ref blockState[10], ref blockState[15]);
					QR(ref blockState[1], ref blockState[6], ref blockState[11], ref blockState[12]);
					QR(ref blockState[2], ref blockState[7], ref blockState[8], ref blockState[13]);
					QR(ref blockState[3], ref blockState[4], ref blockState[9], ref blockState[14]);
				}

				// add local state and initial state and save as a 64 byte array
				for (int index = 0; index < 16; index++)
				{
					uint sum = blockState[index] + _state[index];

					output[index * 4] = (byte)(sum & 0xff);
					output[index * 4 + 1] = (byte)((sum >> 8) & 0xff);
					output[index * 4 + 2] = (byte)((sum >> 16) & 0xff);
					output[index * 4 + 3] = (byte)((sum >> 24) & 0xff);
				}

				for (int index = 0; index < 64; index++)
				{
					buffer[cursor] ^= output[index];
					if (++cursor == buffer.Length) break;
				}

				// increase counter, carry over into next word
				if (++_state[12] == 0) ++_state[13];
			}
		}

		private void QR(ref uint a, ref uint b, ref uint c, ref uint d)
		{
			a += b;
			d ^= a;
			d = d << 16 | d >> 16;
			c += d;
			b ^= c;
			b = b << 12 | b >> 20;
			a += b;
			d ^= a;
			d = d << 8 | d >> 24;
			c += d;
			b ^= c;
			b = b << 7 | b >> 25;
		}
	}
}
