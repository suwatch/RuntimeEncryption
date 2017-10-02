using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace RuntimeEncryption
{
    class Program
    {
        static void Main(string[] args)
        {
            try
            {
                var exp = DateTime.UtcNow.AddHours(1);

                // data is SimpleWebToken.  &-separated key=value pair.
                var swt = new StringBuilder();
                swt.AppendFormat("exp={0}", exp.Ticks);

                // base64-encoded 32-byte key is flowed as WEBSITE_ENCRYPTION_KEY env
                var key = GenerateKey();

                // encrypt
                var cipher = Encrypt(key, swt.ToString());

                // decrypt
                var plain = Decrypt(key, cipher);

                // decode SWT
                var pair = plain.Split('&')
                    .ToDictionary(p => p.Split('=')[0], p => p.Split('=')[1]);

                var dt = new DateTime(Int64.Parse(pair["exp"]), DateTimeKind.Utc);
                if (dt == exp)
                {
                    Console.WriteLine("Verified");
                }
                else
                {
                    throw new InvalidOperationException("Expiration mismatch!");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
            }
        }

        private static string GenerateKey()
        {
            using (var aes = new AesManaged())
            {
                aes.GenerateKey();
                return Convert.ToBase64String(aes.Key);
            }
        }

        // https://stackoverflow.com/q/8041451/3234163
        private static string Encrypt(string key, string data)
        {
            using (var aes = new AesManaged { Key = Convert.FromBase64String(key) })
            {
                aes.GenerateIV();
                var input = Encoding.UTF8.GetBytes(data);
                var iv = Convert.ToBase64String(aes.IV);

                using (var encrypter = aes.CreateEncryptor(aes.Key, aes.IV))
                using (var cipherStream = new MemoryStream())
                {
                    using (var tCryptoStream = new CryptoStream(cipherStream, encrypter, CryptoStreamMode.Write))
                    using (var tBinaryWriter = new BinaryWriter(tCryptoStream))
                    {
                        tBinaryWriter.Write(input);
                        tCryptoStream.FlushFinalBlock();
                    }

                    return string.Format("{0}.{1}", iv, Convert.ToBase64String(cipherStream.ToArray()));
                }
            }
        }

        private static string Decrypt(string key, string data)
        {
            var parts = data.Split(new[] { '.' }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length != 2)
            {
                throw new ArgumentException("Malform encrypted data.");
            }

            var iv = Convert.FromBase64String(parts[0]);
            var dataArray = Convert.FromBase64String(parts[1]);
            using (var aes = new AesManaged { Key = Convert.FromBase64String(key) })
            {
                using (var ms = new MemoryStream())
                {
                    using (var cs = new CryptoStream(ms, aes.CreateDecryptor(aes.Key, iv), CryptoStreamMode.Write))
                    using (var binaryWriter = new BinaryWriter(cs))
                    {
                        //Decrypt Cipher Text from Message
                        binaryWriter.Write(dataArray, 0, dataArray.Length);
                    }

                    return Encoding.Default.GetString(ms.ToArray());
                }
            }
        }
    }
}
