using System;

namespace AES.ModeHandlers
{
    public class CTRModeHandler : OperationModeHandler
    {
        private const int BlockSize = 16;
        private readonly AESAlgorithm _aes;
        private readonly byte[] _noncePrefix;

        public override string ModeName => "CTR";

        /// <summary>
        /// nonceOrIv should be 16 bytes; the first 12 bytes are used as the nonce prefix,
        /// and the last 4 bytes are replaced by the block counter (big-endian).
        /// </summary>
        public CTRModeHandler(byte[] key, byte[] nonceOrIv)
        {
            if (key.Length != 16)
                throw new ArgumentException("AES-128 key must be 16 bytes", nameof(key));
            if (nonceOrIv.Length != BlockSize)
                throw new ArgumentException($"IV/Nonce must be {BlockSize} bytes", nameof(nonceOrIv));

            _aes = new AESAlgorithm(key);
            _noncePrefix = new byte[12];
            Array.Copy(nonceOrIv, 0, _noncePrefix, 0, 12);
        }

        public override byte[] Encrypt(byte[] plaintext)
        {
            int blocks = plaintext.Length / BlockSize;
            var output = new byte[plaintext.Length];

            for (int i = 0; i < blocks; i++)
            {
                byte[] counterBlock = BuildCounterBlock(i);
                byte[] keystream = AESAlgorithm.Encrypt(counterBlock);

                int offset = i * BlockSize;
                for (int j = 0; j < BlockSize; j++)
                    output[offset + j] = (byte)(plaintext[offset + j] ^ keystream[j]);
            }

            return output;
        }

        public override byte[] Decrypt(byte[] ciphertext)
        {
            return Encrypt(ciphertext);
        }

        private byte[] BuildCounterBlock(int counter)
        {
            var block = new byte[BlockSize];

            Array.Copy(_noncePrefix, 0, block, 0, _noncePrefix.Length);

            // encode counter as 4-byte big endian in the last 4 bytes
            byte[] cnt = BitConverter.GetBytes(counter);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(cnt);
            Array.Copy(cnt, 0, block, BlockSize - 4, 4);

            return block;
        }
    }
}
