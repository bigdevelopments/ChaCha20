namespace BigDevelopments.ChaCha
{
	/// <summary>
	/// Abstraction for symmetric encryption using a key, nonce and optional counter 
	/// </summary>
	public interface IStreamCipher
	{
		/// <summary>
		/// Sets they key, nonce and optionally a counter for future transforms
		/// </summary>
		void SetState(byte[] key, byte[] nonce, uint counter = 0);

		/// <summary>
		/// Set the counter, whilst leaving the key and the nonce untouched
		/// </summary>
		uint Counter { get; set; }

		/// <summary>
		/// Transforms (decrypts/encrypts) and copies the data in the source array to the destination array
		/// </summary>
		void Transform(byte[] source, byte[] destination, int start, int length);

		/// <summary>
		/// Transforms (decrypts/encrypts) the data in place in the supplied buffer
		/// </summary>
		void Transform(byte[] buffer);

		/// <summary>
		/// Transforms (decrypts/encrypts) the data in place in the supplied buffer
		/// </summary>
		void Transform(byte[] buffer, int start, int length);
	}
}
