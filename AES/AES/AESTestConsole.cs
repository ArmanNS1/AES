using AES.ModeHandlers;
using System;
using System.Text;

namespace AES
{
    public static class AESTestConsole
    {
        public static void Main()
        {
            Console.OutputEncoding = Encoding.UTF8;
            Console.InputEncoding = Encoding.UTF8;

            Console.WriteLine("AES Algorithm Test Program");
            Console.WriteLine("========================\n");

            while (true)
            {
                // دریافت متن از کاربر
                Console.WriteLine("Please enter the text to encrypt (or type 'exit' to quit):");
                string plaintext = Console.ReadLine() ?? "";
                if (plaintext.Equals("exit", StringComparison.OrdinalIgnoreCase))
                    break;

                // دریافت کلید از کاربر (16 کاراکتر)
                Console.WriteLine("\nPlease enter the encryption key (16 characters):");
                string keyInput = Console.ReadLine() ?? "";
                if (keyInput.Equals("exit", StringComparison.OrdinalIgnoreCase))
                    break;
                byte[] key = Encoding.UTF8.GetBytes(keyInput.PadRight(16).Substring(0, 16));

                // دریافت بردار اولیه / نانس
                Console.WriteLine(
                    "\nPlease enter the IV/Nonce (16 characters) or leave blank for default (type 'exit' to quit):"
                );
                string ivInput = Console.ReadLine() ?? "";
                if (ivInput.Equals("exit", StringComparison.OrdinalIgnoreCase))
                    break;
                byte[] iv = Encoding.UTF8.GetBytes(
                    string.IsNullOrEmpty(ivInput)
                        ? "DefaultInitVector"
                        : ivInput.PadRight(16).Substring(0, 16)
                );

                // انتخاب حالت رمزنگاری
                Console.WriteLine("\nPlease select the encryption mode:");
                Console.WriteLine("1. ECB");
                Console.WriteLine("2. CBC");
                Console.WriteLine("3. CFB");
                Console.WriteLine("4. OFB");
                Console.WriteLine("5. CTR");
                Console.WriteLine("6. Exit");

                string modeInput = Console.ReadLine() ?? "";
                if (modeInput.Equals("exit", StringComparison.OrdinalIgnoreCase) || modeInput == "6")
                    break;

                if (!int.TryParse(modeInput, out int mode) || mode < 1 || mode > 6)
                {
                    Console.WriteLine("Invalid mode. Using ECB mode.");
                    mode = 1;
                }

                // تبدیل متن به بایت و پدینگ PKCS7
                byte[] plainBytes = Encoding.UTF8.GetBytes(plaintext);
                plainBytes = PadPkcs7(plainBytes, 16);

                // ایجاد هندلر مناسب
                OperationModeHandler handler = mode switch
                {
                    2 => new CBCModeHandler(key, iv),
                    3 => new CFBModeHandler(key, iv),
                    4 => new OFBModeHandler(key, iv),
                    5 => new CTRModeHandler(key, iv),
                    _ => new ECBModeHandler(key),
                };
                Console.WriteLine($"\nUsing {handler.ModeName} mode\n");

                try
                {
                    // رمزنگاری
                    Console.WriteLine("Encrypting...");
                    byte[] ciphertext = handler.Encrypt(plainBytes);
                    string base64Cipher = Convert.ToBase64String(ciphertext);
                    Console.WriteLine($"Ciphertext (Base64): {base64Cipher}\n");

                    // رمزگشایی
                    Console.WriteLine("Decrypting...");
                    byte[] decryptedPadded = handler.Decrypt(ciphertext);
                    byte[] decrypted = UnpadPkcs7(decryptedPadded);
                    string decryptedText = Encoding.UTF8.GetString(decrypted);
                    Console.WriteLine($"Decrypted text: {decryptedText}\n");

                    // اعتبارسنجی
                    if (decryptedText == plaintext)
                        Console.WriteLine("✓ Success! Decrypted matches original.");
                    else
                        Console.WriteLine("✗ Failure! Output does not match input.");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"\nError: {ex.Message}");
                }

                Console.WriteLine("\n------------------------\n");
            }

            Console.WriteLine("Exiting program. Goodbye!");
        }

        private static byte[] PadPkcs7(byte[] data, int blockSize)
        {
            int pad = blockSize - (data.Length % blockSize);
            var padded = new byte[data.Length + pad];
            Array.Copy(data, padded, data.Length);
            for (int i = data.Length; i < padded.Length; i++)
                padded[i] = (byte)pad;
            return padded;
        }

        private static byte[] UnpadPkcs7(byte[] data)
        {
            int pad = data[^1];
            if (pad <= 0 || pad > data.Length)
                throw new ArgumentException("Invalid padding");
            for (int i = data.Length - pad; i < data.Length; i++)
                if (data[i] != pad)
                    throw new ArgumentException("Invalid padding");
            var output = new byte[data.Length - pad];
            Array.Copy(data, output, output.Length);
            return output;
        }
    }
}
