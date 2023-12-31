using SecurityTool.Shared;
using System.Security.Cryptography;
using System.Text;
using System.Collections.Generic;
using static System.Net.Mime.MediaTypeNames;
using System.Runtime.Intrinsics.Arm;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.AspNetCore.Identity;

namespace SecurityTool.Data
{
    public class CryptographyServices
    {
        static readonly string secretKey = "CybersecurityBootCamp"; //key used to encrypt data
        
        public string TDESEncryption(string TextToEncrypt)
        {
            byte[] myEncryptedArray = UTF8Encoding.UTF8.GetBytes(TextToEncrypt);

            //Generate HashKey
            MD5 hashMD5 = MD5.Create();
            byte[] securityKeyArray = hashMD5.ComputeHash(UTF8Encoding.UTF8.GetBytes(secretKey));
            hashMD5.Clear();

            //3dCryptoServices
            TripleDES tDES = TripleDES.Create();
            tDES.Key = securityKeyArray;
            tDES.Mode = CipherMode.CBC;
            tDES.Padding = PaddingMode.PKCS7;
            
            ICryptoTransform cTransform = tDES.CreateEncryptor();
            byte[] resultArray = cTransform.TransformFinalBlock(myEncryptedArray, 0, myEncryptedArray.Length);
            tDES.Clear();

            return Convert.ToBase64String(resultArray, 0, resultArray.Length);
        }
        public string MD5HashEncryption(string inputValue)
        {
            byte[] keyArray;

            //Generate HashKey
            MD5 hashMD5 = MD5.Create();
            keyArray = hashMD5.ComputeHash(UTF8Encoding.UTF8.GetBytes(inputValue));
            hashMD5.Clear();

            return Convert.ToHexString(keyArray);
        }

        public string SHA256HashEncryption(string inputValue)
        {
            byte[] hashValue;

            //Genetate hashKey
            SHA256 sha256 = SHA256.Create();            
            UTF8Encoding objUtf8 = new UTF8Encoding();
            hashValue = sha256.ComputeHash(objUtf8.GetBytes(inputValue));
                        
            return Convert.ToHexString(hashValue);
        }

        public string SHA1HashEncryption(string inputValue)
        {
            using var sha1 = SHA1.Create();
            {
                return Convert.ToHexString(sha1.ComputeHash(Encoding.UTF8.GetBytes(inputValue)));
            }
        }

        public PasswordResponse CheckPasswordStrength(string password)
        {
            if (password.Length < 8)
            {
                return new PasswordResponse(false, "Password should not be less than 8 characters");
            }

            var letters = 0;
            var digits = 0;
            var uppers = 0;
            var lowers = 0;
            var symbols = 0;
            foreach (var ch in password)
            {
                if (char.IsLetter(ch)) letters++;
                if (char.IsDigit(ch)) digits++;
                if (char.IsUpper(ch)) uppers++;
                if (char.IsLower(ch)) lowers++;
                if (!char.IsLetterOrDigit(ch)) symbols++;
            }

            if (letters < 2) {
                return new PasswordResponse(false, "Your password should not have less than 2 characters");
            }
            else if (digits < 2) {
                return new PasswordResponse(false, "Your password should not have less than 2 digits");
            }
            else if (uppers < 1) {
                return new PasswordResponse(false, "Your password should contain at least one upper case letter");
            }
            else if (lowers < 1) {
                return new PasswordResponse(false, "Your password should contain at least one lower case letter");
            }
            else if (symbols < 1) {
                return new PasswordResponse(false, "Your password should contain at least one special character");
            }
            else  return new PasswordResponse(true, "Your password is VERY strong");
        }

        public string GenerateNewStrongPassword(PasswordOptions? opts = null)
        {
            if (opts == null) opts = new PasswordOptions()
            {
                RequiredLength = 8,
                RequiredUniqueChars = 4,
                RequireDigit = true,
                RequireLowercase = true,
                RequireNonAlphanumeric = true,
                RequireUppercase = true
            };

            string[] randomChars = new[] {
            "ABCDEFGHJKLMNOPQRSTUVWXYZ",    // uppercase 
            "abcdefghijkmnopqrstuvwxyz",    // lowercase
            "0123456789",                   // digits
            "!@$?_-"                        // non-alphanumeric
        };

            Random rand = new Random(Environment.TickCount);
            List<char> chars = new List<char>();

            if (opts.RequireUppercase)
                chars.Insert(rand.Next(0, chars.Count),
                    randomChars[0][rand.Next(0, randomChars[0].Length)]);

            if (opts.RequireLowercase)
                chars.Insert(rand.Next(0, chars.Count),
                    randomChars[1][rand.Next(0, randomChars[1].Length)]);

            if (opts.RequireDigit)
                chars.Insert(rand.Next(0, chars.Count),
                    randomChars[2][rand.Next(0, randomChars[3].Length)]);

            if (opts.RequireNonAlphanumeric)
                chars.Insert(rand.Next(0, chars.Count),
                    randomChars[3][rand.Next(0, randomChars[3].Length)]);

            for (int i = chars.Count; i < opts.RequiredLength
                || chars.Distinct().Count() < opts.RequiredUniqueChars; i++)
            {
                string rcs = randomChars[rand.Next(0, randomChars.Length)];
                chars.Insert(rand.Next(0, chars.Count),
                    rcs[rand.Next(0, rcs.Length)]);
            }

            return new string(chars.ToArray());
        }
    }
}
