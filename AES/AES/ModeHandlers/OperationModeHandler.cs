namespace AES.ModeHandlers
{
    public abstract class OperationModeHandler
    {
        /// <summary>
        /// Friendly name of the mode (e.g. "ECB", "CBC", etc.)
        /// </summary>
        public abstract string ModeName { get; }

        /// <summary>
        /// Encrypts a full buffer (must be a multiple of 16 bytes).
        /// </summary>
        public abstract byte[] Encrypt(byte[] data);

        /// <summary>
        /// Decrypts a full buffer (must be a multiple of 16 bytes).
        /// </summary>
        public abstract byte[] Decrypt(byte[] data);

        /// <summary>
        /// Factory: creates the correct handler based on a mode enum or integer.
        /// </summary>
        public static OperationModeHandler Create(
            int mode,    // 1=ECB, 2=CBC, 3=CFB, 4=OFB, 5=CTR
            byte[] key,
            byte[] ivOrNonce = null
        )
        {
            return mode switch
            {
                1 => new ECBModeHandler(key),
                2 => new CBCModeHandler(key, ivOrNonce ?? throw new ArgumentNullException(nameof(ivOrNonce))),
                3 => new CFBModeHandler(key, ivOrNonce ?? throw new ArgumentNullException(nameof(ivOrNonce))),
                4 => new OFBModeHandler(key, ivOrNonce ?? throw new ArgumentNullException(nameof(ivOrNonce))),
                5 => new CTRModeHandler(key, ivOrNonce ?? throw new ArgumentNullException(nameof(ivOrNonce))),
                _ => throw new ArgumentOutOfRangeException(nameof(mode), "Mode must be 1–5")
            };
        }
    }
}