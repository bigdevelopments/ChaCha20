using System;

namespace BigDevelopments.ChaCha
{
	/// Fast implementation of ChaCha20, using member variable and locals instead of arrays. Based principally on the Wikipedia
	/// page https://en.wikipedia.org/wiki/Salsa20. Actual specification is https://tools.ietf.org/html/rfc7539. Original version
	/// of ChaCha had 8 byte nonce and 8 byte counter, but this was change in later specification to a 4 byte counter and
	/// 12 byte nonce, which is what's used here
	public class RapidChaCha : IStreamCipher
	{
		// the 4x4 state matrix, represented as explicit members rather than an array
		private uint _s0, _s1, _s2, _s3, _s4, _s5, _s6, _s7, _s8, _s9, _s10, _s11, _s12, _s13, _s14, _s15;

		public RapidChaCha()
		{
			// no implementation
		}

		public RapidChaCha(byte[] key, byte[] nonce, uint counter = 0)
		{
			// inititalise the state with the constant and the supplied key, nonce and counter
			SetState(key, nonce, counter);
		}

		public void SetState(byte[] key, byte[] nonce, uint counter = 0)
		{
			// keys and nonces must be correct size
			if (key == null || key.Length != 32) throw new ArgumentOutOfRangeException(nameof(key), "Must be a 32 byte (256 bit) array");
			if (nonce == null || nonce.Length != 12) throw new ArgumentOutOfRangeException(nameof(nonce), "Must be a 12 byte (96 bit) array");

			// set up the initial value of state according to constant, key, nonce and counter constituents..
			// first four words are the (arbitary although standardised) constant
			_s0 = 0x61707865;
			_s1 = 0x3320646e;
			_s2 = 0x79622d32;
			_s3 = 0x6b206574;

			// the next 8 words contain the key
			_s4 = key[0] | (uint)key[1] << 8 | (uint)key[2] << 16 | (uint)key[3] << 24;
			_s5 = key[4] | (uint)key[5] << 8 | (uint)key[6] << 16 | (uint)key[7] << 24;
			_s6 = key[8] | (uint)key[9] << 8 | (uint)key[10] << 16 | (uint)key[11] << 24;
			_s7 = key[12] | (uint)key[13] << 8 | (uint)key[14] << 16 | (uint)key[15] << 24;
			_s8 = key[16] | (uint)key[17] << 8 | (uint)key[18] << 16 | (uint)key[19] << 24;
			_s9 = key[20] | (uint)key[21] << 8 | (uint)key[22] << 16 | (uint)key[23] << 24;
			_s10 = key[24] | (uint)key[25] << 8 | (uint)key[26] << 16 | (uint)key[27] << 24;
			_s11 = key[28] | (uint)key[29] << 8 | (uint)key[30] << 16 | (uint)key[31] << 24;

			// the next one is the counter
			_s12 = counter;

			// the final 3 words the 'nonce'
			_s13 = nonce[0] | (uint)nonce[1] << 8 | (uint)nonce[2] << 16 | (uint)nonce[3] << 24;
			_s14 = nonce[4] | (uint)nonce[5] << 8 | (uint)nonce[6] << 16 | (uint)nonce[7] << 24;
			_s15 = nonce[8] | (uint)nonce[9] << 8 | (uint)nonce[10] << 16 | (uint)nonce[11] << 24;
		}

		public uint Counter
		{
			get { return _s12; }
			set { _s12 = value; }
		}

		/// <summary>
		/// Transforms (decrypts/encrypts) and copies the data in the source array to the destination array
		/// </summary>
		public void Transform(byte[] source, byte[] destination, int start, int length)
		{
			// validate
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
			// XORing cursor we'll move over the array
			int cursor = start;

			while (cursor < start + length)
			{
				// make a local copy of the member variables - these can be manipulated much faster
				uint s0 = _s0, s1 = _s1, s2 = _s2, s3 = _s3, s4 = _s4, s5 = _s5, s6 = _s6, s7 = _s7,
				s8 = _s8, s9 = _s9, s10 = _s10, s11 = _s11, s12 = _s12, s13 = _s13, s14 = _s14, s15 = _s15;

				// go mental on it for 20 rounds (10 iterations of 2 rounds each)
				for (int index = 0; index < 10; index++)
				{
					s0 += s4; s12 ^= s0; s12 = s12 << 16 | s12 >> 16;
					s8 += s12; s4 ^= s8; s4 = s4 << 12 | s4 >> 20;
					s0 += s4; s12 ^= s0; s12 = s12 << 8 | s12 >> 24;
					s8 += s12; s4 ^= s8; s4 = s4 << 7 | s4 >> 25;
					s1 += s5; s13 ^= s1; s13 = s13 << 16 | s13 >> 16;
					s9 += s13; s5 ^= s9; s5 = s5 << 12 | s5 >> 20;
					s1 += s5; s13 ^= s1; s13 = s13 << 8 | s13 >> 24;
					s9 += s13; s5 ^= s9; s5 = s5 << 7 | s5 >> 25;
					s2 += s6; s14 ^= s2; s14 = s14 << 16 | s14 >> 16;
					s10 += s14; s6 ^= s10; s6 = s6 << 12 | s6 >> 20;
					s2 += s6; s14 ^= s2; s14 = s14 << 8 | s14 >> 24;
					s10 += s14; s6 ^= s10; s6 = s6 << 7 | s6 >> 25;
					s3 += s7; s15 ^= s3; s15 = s15 << 16 | s15 >> 16;
					s11 += s15; s7 ^= s11; s7 = s7 << 12 | s7 >> 20;
					s3 += s7; s15 ^= s3; s15 = s15 << 8 | s15 >> 24;
					s11 += s15; s7 ^= s11; s7 = s7 << 7 | s7 >> 25;
					s0 += s5; s15 ^= s0; s15 = s15 << 16 | s15 >> 16;
					s10 += s15; s5 ^= s10; s5 = s5 << 12 | s5 >> 20;
					s0 += s5; s15 ^= s0; s15 = s15 << 8 | s15 >> 24;
					s10 += s15; s5 ^= s10; s5 = s5 << 7 | s5 >> 25;
					s1 += s6; s12 ^= s1; s12 = s12 << 16 | s12 >> 16;
					s11 += s12; s6 ^= s11; s6 = s6 << 12 | s6 >> 20;
					s1 += s6; s12 ^= s1; s12 = s12 << 8 | s12 >> 24;
					s11 += s12; s6 ^= s11; s6 = s6 << 7 | s6 >> 25;
					s2 += s7; s13 ^= s2; s13 = s13 << 16 | s13 >> 16;
					s8 += s13; s7 ^= s8; s7 = s7 << 12 | s7 >> 20;
					s2 += s7; s13 ^= s2; s13 = s13 << 8 | s13 >> 24;
					s8 += s13; s7 ^= s8; s7 = s7 << 7 | s7 >> 25;
					s3 += s4; s14 ^= s3; s14 = s14 << 16 | s14 >> 16;
					s9 += s14; s4 ^= s9; s4 = s4 << 12 | s4 >> 20;
					s3 += s4; s14 ^= s3; s14 = s14 << 8 | s14 >> 24;
					s9 += s14; s4 ^= s9; s4 = s4 << 7 | s4 >> 25;
				}

				s0 += _s0; s1 += _s1; s2 += _s2; s3 += _s3; s4 += _s4; s5 += _s5; s6 += _s6; s7 += _s7;
				s8 += _s8; s9 += _s9; s10 += _s10; s11 += _s11; s12 += _s12; s13 += _s13; s14 += _s14; s15 += _s15;

				// increase counter, carry over into next word
				if (++_s12 == 0) ++_s13;

				// ugly copy
				buffer[cursor++] ^= (byte)(s0 & 0xff); if (cursor == buffer.Length) return;
				buffer[cursor++] ^= (byte)((s0 >> 8) & 0xff); if (cursor == buffer.Length) return;
				buffer[cursor++] ^= (byte)((s0 >> 16) & 0xff); if (cursor == buffer.Length) return;
				buffer[cursor++] ^= (byte)((s0 >> 24) & 0xff); if (cursor == buffer.Length) return;
				buffer[cursor++] ^= (byte)(s1 & 0xff); if (cursor == buffer.Length) return;
				buffer[cursor++] ^= (byte)((s1 >> 8) & 0xff); if (cursor == buffer.Length) return;
				buffer[cursor++] ^= (byte)((s1 >> 16) & 0xff); if (cursor == buffer.Length) return;
				buffer[cursor++] ^= (byte)((s1 >> 24) & 0xff); if (cursor == buffer.Length) return;
				buffer[cursor++] ^= (byte)(s2 & 0xff); if (cursor == buffer.Length) return;
				buffer[cursor++] ^= (byte)((s2 >> 8) & 0xff); if (cursor == buffer.Length) return;
				buffer[cursor++] ^= (byte)((s2 >> 16) & 0xff); if (cursor == buffer.Length) return;
				buffer[cursor++] ^= (byte)((s2 >> 24) & 0xff); if (cursor == buffer.Length) return;
				buffer[cursor++] ^= (byte)(s3 & 0xff); if (cursor == buffer.Length) return;
				buffer[cursor++] ^= (byte)((s3 >> 8) & 0xff); if (cursor == buffer.Length) return;
				buffer[cursor++] ^= (byte)((s3 >> 16) & 0xff); if (cursor == buffer.Length) return;
				buffer[cursor++] ^= (byte)((s3 >> 24) & 0xff); if (cursor == buffer.Length) return;
				buffer[cursor++] ^= (byte)(s4 & 0xff); if (cursor == buffer.Length) return;
				buffer[cursor++] ^= (byte)((s4 >> 8) & 0xff); if (cursor == buffer.Length) return;
				buffer[cursor++] ^= (byte)((s4 >> 16) & 0xff); if (cursor == buffer.Length) return;
				buffer[cursor++] ^= (byte)((s4 >> 24) & 0xff); if (cursor == buffer.Length) return;
				buffer[cursor++] ^= (byte)(s5 & 0xff); if (cursor == buffer.Length) return;
				buffer[cursor++] ^= (byte)((s5 >> 8) & 0xff); if (cursor == buffer.Length) return;
				buffer[cursor++] ^= (byte)((s5 >> 16) & 0xff); if (cursor == buffer.Length) return;
				buffer[cursor++] ^= (byte)((s5 >> 24) & 0xff); if (cursor == buffer.Length) return;
				buffer[cursor++] ^= (byte)(s6 & 0xff); if (cursor == buffer.Length) return;
				buffer[cursor++] ^= (byte)((s6 >> 8) & 0xff); if (cursor == buffer.Length) return;
				buffer[cursor++] ^= (byte)((s6 >> 16) & 0xff); if (cursor == buffer.Length) return;
				buffer[cursor++] ^= (byte)((s6 >> 24) & 0xff); if (cursor == buffer.Length) return;
				buffer[cursor++] ^= (byte)(s7 & 0xff); if (cursor == buffer.Length) return;
				buffer[cursor++] ^= (byte)((s7 >> 8) & 0xff); if (cursor == buffer.Length) return;
				buffer[cursor++] ^= (byte)((s7 >> 16) & 0xff); if (cursor == buffer.Length) return;
				buffer[cursor++] ^= (byte)((s7 >> 24) & 0xff); if (cursor == buffer.Length) return;
				buffer[cursor++] ^= (byte)(s8 & 0xff); if (cursor == buffer.Length) return;
				buffer[cursor++] ^= (byte)((s8 >> 8) & 0xff); if (cursor == buffer.Length) return;
				buffer[cursor++] ^= (byte)((s8 >> 16) & 0xff); if (cursor == buffer.Length) return;
				buffer[cursor++] ^= (byte)((s8 >> 24) & 0xff); if (cursor == buffer.Length) return;
				buffer[cursor++] ^= (byte)(s9 & 0xff); if (cursor == buffer.Length) return;
				buffer[cursor++] ^= (byte)((s9 >> 8) & 0xff); if (cursor == buffer.Length) return;
				buffer[cursor++] ^= (byte)((s9 >> 16) & 0xff); if (cursor == buffer.Length) return;
				buffer[cursor++] ^= (byte)((s9 >> 24) & 0xff); if (cursor == buffer.Length) return;
				buffer[cursor++] ^= (byte)(s10 & 0xff); if (cursor == buffer.Length) return;
				buffer[cursor++] ^= (byte)((s10 >> 8) & 0xff); if (cursor == buffer.Length) return;
				buffer[cursor++] ^= (byte)((s10 >> 16) & 0xff); if (cursor == buffer.Length) return;
				buffer[cursor++] ^= (byte)((s10 >> 24) & 0xff); if (cursor == buffer.Length) return;
				buffer[cursor++] ^= (byte)(s11 & 0xff); if (cursor == buffer.Length) return;
				buffer[cursor++] ^= (byte)((s11 >> 8) & 0xff); if (cursor == buffer.Length) return;
				buffer[cursor++] ^= (byte)((s11 >> 16) & 0xff); if (cursor == buffer.Length) return;
				buffer[cursor++] ^= (byte)((s11 >> 24) & 0xff); if (cursor == buffer.Length) return;
				buffer[cursor++] ^= (byte)(s12 & 0xff); if (cursor == buffer.Length) return;
				buffer[cursor++] ^= (byte)((s12 >> 8) & 0xff); if (cursor == buffer.Length) return;
				buffer[cursor++] ^= (byte)((s12 >> 16) & 0xff); if (cursor == buffer.Length) return;
				buffer[cursor++] ^= (byte)((s12 >> 24) & 0xff); if (cursor == buffer.Length) return;
				buffer[cursor++] ^= (byte)(s13 & 0xff); if (cursor == buffer.Length) return;
				buffer[cursor++] ^= (byte)((s13 >> 8) & 0xff); if (cursor == buffer.Length) return;
				buffer[cursor++] ^= (byte)((s13 >> 16) & 0xff); if (cursor == buffer.Length) return;
				buffer[cursor++] ^= (byte)((s13 >> 24) & 0xff); if (cursor == buffer.Length) return;
				buffer[cursor++] ^= (byte)(s14 & 0xff); if (cursor == buffer.Length) return;
				buffer[cursor++] ^= (byte)((s14 >> 8) & 0xff); if (cursor == buffer.Length) return;
				buffer[cursor++] ^= (byte)((s14 >> 16) & 0xff); if (cursor == buffer.Length) return;
				buffer[cursor++] ^= (byte)((s14 >> 24) & 0xff); if (cursor == buffer.Length) return;
				buffer[cursor++] ^= (byte)(s15 & 0xff); if (cursor == buffer.Length) return;
				buffer[cursor++] ^= (byte)((s15 >> 8) & 0xff); if (cursor == buffer.Length) return;
				buffer[cursor++] ^= (byte)((s15 >> 16) & 0xff); if (cursor == buffer.Length) return;
				buffer[cursor++] ^= (byte)((s15 >> 24) & 0xff); if (cursor == buffer.Length) return;
			}
		}
	}
}

