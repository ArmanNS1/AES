namespace AES.ModeHandlers
{
    public class ECBModeHandler : OperationModeHandler
    {
        private readonly AESAlgorithm _aes;

        public override string ModeName => "ECB";

        // ← This is the constructor that takes exactly one byte[] key
        public ECBModeHandler(byte[] key)
        {
            if (key.Length != 16)
                throw new ArgumentException("AES-128 key must be 16 bytes", nameof(key));

            _aes = new AESAlgorithm(key);
        }

        public override byte[] Encrypt(byte[] data)
        {
            int blockSize = 16;
            var output = new byte[data.Length];

            for (int i = 0; i < data.Length; i += blockSize)
            {
                var block = new byte[blockSize];
                Array.Copy(data, i, block, 0, blockSize);

                var cipher = AESAlgorithm.Encrypt(block);
                Array.Copy(cipher, 0, output, i, blockSize);
            }

            return output;
        }

        public override byte[] Decrypt(byte[] data)
        {
            int blockSize = 16;
            var output = new byte[data.Length];

            for (int i = 0; i < data.Length; i += blockSize)
            {
                var block = new byte[blockSize];
                Array.Copy(data, i, block, 0, blockSize);

                var plain = AESAlgorithm.Decrypt(block);
                Array.Copy(plain, 0, output, i, blockSize);
            }

            return output;
        }
    }
}
