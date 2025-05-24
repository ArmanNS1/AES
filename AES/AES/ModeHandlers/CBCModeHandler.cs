namespace AES.ModeHandlers
{
    public class CBCModeHandler : OperationModeHandler
    {
        private readonly AESAlgorithm _aes;
        private readonly byte[] _iv;

        public override string ModeName => "CBC";

        public CBCModeHandler(byte[] key, byte[] iv)
        {
            if (key.Length != 16)
                throw new ArgumentException("AES-128 key must be 16 bytes");
            if (iv.Length != 16)
                throw new ArgumentException("IV must be 16 bytes");

            _aes = new AESAlgorithm(key);  // expands the key internally
            _iv = iv;
        }

        public override byte[] Encrypt(byte[] plaintext)
        {
            int blockSize = 16;
            var ciphertext = new byte[plaintext.Length];
            var previous = (byte[])_iv.Clone();

            for (int i = 0; i < plaintext.Length; i += blockSize)
            {
                var block = new byte[blockSize];
                Array.Copy(plaintext, i, block, 0, blockSize);

                // 1) XOR with previous (or IV)
                for (int j = 0; j < blockSize; j++)
                    block[j] ^= previous[j];

                // 2) AES encrypt
                var cipherBlock = AESAlgorithm.Encrypt(block);

                // 3) copy out & update feedback
                Array.Copy(cipherBlock, 0, ciphertext, i, blockSize);
                Array.Copy(cipherBlock, 0, previous, 0, blockSize);
            }

            return ciphertext;
        }

        public override byte[] Decrypt(byte[] ciphertext)
        {
            int blockSize = 16;
            var plaintext = new byte[ciphertext.Length];
            var previous = (byte[])_iv.Clone();

            for (int i = 0; i < ciphertext.Length; i += blockSize)
            {
                var block = new byte[blockSize];
                Array.Copy(ciphertext, i, block, 0, blockSize);

                // 1) AES decrypt
                byte[] decrypted = AESAlgorithm.Decrypt(block);

                // 2) XOR with previous (or IV)
                for (int j = 0; j < blockSize; j++)
                    decrypted[j] ^= previous[j];

                // 3) copy out & update feedback
                Array.Copy(decrypted, 0, plaintext, i, blockSize);
                Array.Copy(block, 0, previous, 0, blockSize);
            }

            return plaintext;
        }
    }
}
