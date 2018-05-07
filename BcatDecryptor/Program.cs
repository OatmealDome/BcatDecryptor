using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Syroot.BinaryData;
using System;
using System.IO;
using System.Text;

namespace BcatDecryptor
{
    class Program
    {
        // Taken from 5.0.1 bcat sysmodule
        static string[] secretData =
        {
            "a3e20c5c1cd7b720",
            "7f4c637432c8d420",
            "188d087d92a0c087",
            "8e7d23fa7fafe60f",
            "5252ae57c026d3cb",
            "2650f5e53554f01d",
            "b213a1e986307c9f",
            "875d8b01e3df5d7c",
            "c1b9a5ce866e00b1",
            "6a48ae69161e0138",
            "3f7b0401928b1f46",
            "0e9db55903a10f0e",
            "a8914bcbe7b888f9",
            "b15ef3ed6ce0e4cc",
            "f3b9d9f43dedf569",
            "bda4f7a0508c7462",
            "f5dc3586b1b2a8af",
            "7f6828b6f33dd118",
            "860de88547dcbf70",
            "ccbacacb70d11fb5",
            "b1475e5ea18151b9",
            "5f857ca15cf3374c",
            "cfa747c1d09d4f05",
            "30e7d70cb6f98101",
            "c8b3c78772bdcf43",
            "533dfc0702ed9874",
            "a29301cac5219e5c",
            "5776f5bec1b0df06",
            "1d4ab85a07ac4251",
            "7c1bd512b1cf5092",
            "2691cb8b3f76b411",
            "4400abee651c9eb9"
        };

        // BcatDecryptor.exe <titleid> <passphrase> <file path>
        static void Main(string[] args)
        {
            // Print header
            Console.WriteLine("BcatDecryptor by OatmealDome\n");

            // Check arguments length
            if (args.Length != 3)
            {
                // Print out usage
                Console.WriteLine("BcatDecryptor.exe <title ID> <BCAT passphrase> <file path>");

                return;
            }

            // Check that the file exists
            if (!File.Exists(args[2]))
            {
                // Print error
                Console.WriteLine("The file doesn't exist.");

                return;
            }

            // Check title ID length
            if (args[0].Length != 16)
            {
                // Print error
                Console.WriteLine("Invalid title ID.");

                return;
            }

            // Declare BCAT container fields
            byte unk;
            byte cryptoType;
            byte rsaHashType;
            byte secretDataIdx;
            ulong unk2;
            byte[] encryptionIv;
            byte[] signature;
            byte[] encryptedData;

            // Open a reader on the file
            using (FileStream fileStream = new FileStream(args[2], FileMode.Open))
            using (BinaryDataReader reader = new BinaryDataReader(fileStream, Encoding.ASCII))
            {
                // Read as big endian
                reader.ByteOrder = ByteOrder.BigEndian;

                // Check magic numbers
                if (reader.ReadUInt32() != 0x62636174) // "bcat"
                {
                    Console.WriteLine("This file isn't a BCAT container file.");

                    return;
                }

                // Read fields
                unk = reader.ReadByte();
                cryptoType = reader.ReadByte();
                rsaHashType = reader.ReadByte();
                secretDataIdx = reader.ReadByte();
                unk2 = reader.ReadUInt64();
                encryptionIv = reader.ReadBytes(0x10);
                signature = reader.ReadBytes(0x100);
                encryptedData = reader.ReadBytes((int)(reader.Length - 0x120));
            }
            
            // Check the secret data index
            if (secretData.Length < secretDataIdx)
            {
                // Print error
                Console.WriteLine("This BCAT file is not supported by this version (err: secret data).");

                return;
            }

            // Create the salt from the title ID and secret data
            string salt = args[0].ToLower() + secretData[secretDataIdx];

            // Get the key size
            int keySize;
            switch (cryptoType)
            {
                case 1:
                    keySize = 128;
                    break;
                case 2:
                    keySize = 192;
                    break;
                case 3:
                    keySize = 256;
                    break;
                default:
                    Console.WriteLine("This BCAT file is not supported by this version (err: crypto).");
                    return;
            }

            // Create a new Pkcs5S2ParametersGenerator and initialize it
            Pkcs5S2ParametersGenerator generator = new Pkcs5S2ParametersGenerator(new Sha256Digest());
            generator.Init(Encoding.ASCII.GetBytes(args[1].ToLower()), Encoding.ASCII.GetBytes(salt), 4096);

            // Generate the key parameter
            KeyParameter parameter = (KeyParameter)generator.GenerateDerivedParameters("aes" + keySize, keySize);

            // Initialize a cipher in AES-CTR mode
            IBufferedCipher cipher = CipherUtilities.GetCipher("AES/CTR/NoPadding");
            cipher.Init(false, new ParametersWithIV(parameter, encryptionIv));

            // Get the decrypted bytes
            byte[] decryptedBytes = cipher.DoFinal(encryptedData);

            // Get the output file name and path, then combine them
            string fileName = Path.GetFileName(args[2]) + ".decrypted";
            string filePath = Path.GetDirectoryName(args[2]);
            string outputPath = filePath + Path.DirectorySeparatorChar + fileName;

            // Remove the output file if it already exists
            if (File.Exists(outputPath))
            {
                File.Delete(outputPath);
            }

            // Write out the file
            File.WriteAllBytes(outputPath, decryptedBytes);

            // Print out that we're done
            Console.WriteLine("Wrote file successfully.");
        }
    }

}
