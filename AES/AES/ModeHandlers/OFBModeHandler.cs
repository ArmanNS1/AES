using System;

namespace AES.ModeHandlers
{
    public class OFBModeHandler : OperationModeHandler
    {
        private const int BlockSize = 16;
        private readonly AESAlgorithm _aes;
        private readonly byte[] _iv;

        public override string ModeName => "CFB";

        /// <summary>
        /// iv must be 16 bytes for CFB mode.
        /// </summary>
        public OFBModeHandler(byte[] key, byte[] iv)
        {
            if (key.Length != 16)
                throw new ArgumentException("AES-128 key must be 16 bytes", nameof(key));
            if (iv.Length != BlockSize)
                throw new ArgumentException($"IV must be {BlockSize} bytes", nameof(iv));

            _aes = new AESAlgorithm(key);
            _iv = (byte[])iv.Clone();
        }

        public override byte[] Encrypt(byte[] plaintext)
        {
            int blocks = plaintext.Length / BlockSize;
            var output = new byte[plaintext.Length];
            var feedback = (byte[])_iv.Clone();

            for (int i = 0; i < blocks; i++)
            {
                int offset = i * BlockSize;
                byte[] plainBlock = new byte[BlockSize];
                Array.Copy(plaintext, offset, plainBlock, 0, BlockSize);

                byte[] encryptedFeedback = AESAlgorithm.Encrypt(feedback);

                byte[] cipherBlock = new byte[BlockSize];
                for (int j = 0; j < BlockSize; j++)
                    cipherBlock[j] = (byte)(plainBlock[j] ^ encryptedFeedback[j]);

                Array.Copy(cipherBlock, 0, output, offset, BlockSize);
                feedback = cipherBlock; 
            }

            return output;
        }

        public override byte[] Decrypt(byte[] ciphertext)
        {
            int blocks = ciphertext.Length / BlockSize;
            var output = new byte[ciphertext.Length];
            var feedback = (byte[])_iv.Clone();

            for (int i = 0; i < blocks; i++)
            {
                int offset = i * BlockSize;
                byte[] cipherBlock = new byte[BlockSize];
                Array.Copy(ciphertext, offset, cipherBlock, 0, BlockSize);

                byte[] encryptedFeedback = AESAlgorithm.Encrypt(feedback);

                byte[] plainBlock = new byte[BlockSize];
                for (int j = 0; j < BlockSize; j++)
                    plainBlock[j] = (byte)(cipherBlock[j] ^ encryptedFeedback[j]);

                Array.Copy(plainBlock, 0, output, offset, BlockSize);
                feedback = cipherBlock;
            }

            return output;
        }
    }
}
