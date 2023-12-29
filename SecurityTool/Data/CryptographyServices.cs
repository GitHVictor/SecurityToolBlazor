using SecurityTool.Shared;
using System.Security.Cryptography;
using System.Text;
using System.Collections.Generic;
using static System.Net.Mime.MediaTypeNames;
using System.Runtime.Intrinsics.Arm;

namespace SecurityTool.Data
{
    public class CryptographyServices
    {
        static readonly string mySecretKey = "CybersecurityBootCamp"; //key used to encrypt data
        
        public string TDESEncryption(string inputValue)
        {
            byte[] keyArray;
            byte[] toEncryptArray = UTF8Encoding.UTF8.GetBytes(inputValue);

            //Generate HashKey
            MD5 hashMD5 = MD5.Create();
            keyArray = hashMD5.ComputeHash(UTF8Encoding.UTF8.GetBytes(mySecretKey));
            hashMD5.Clear();

            //3dCryptoServices
            TripleDES tDES = TripleDES.Create();
            tDES.Key = keyArray;
            tDES.Mode = CipherMode.ECB;
            tDES.Padding = PaddingMode.PKCS7;

            ICryptoTransform cTransform = tDES.CreateEncryptor();
            byte[] resultArray = cTransform.TransformFinalBlock(toEncryptArray, 0, toEncryptArray.Length);
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
                return new PasswordResponse(false, "Password should not be less than 2 characters");
            }
            else if (digits < 2) {
                return new PasswordResponse(false, "Password should not be less than 2 digits");
            }
            else if (uppers < 1) {
                return new PasswordResponse(false, "Password should contain at least one upper case letter");
            }
            else if (lowers < 1) {
                return new PasswordResponse(false, "Password should contain at least one lower case letter");
            }
            else if (symbols < 1) {
                return new PasswordResponse(false, "Password should contain at least one special character");
            }
            else  return new PasswordResponse(true, "Your password is very strong");
        }

        public string GenerateNewStrongPassword(string inputValue)
        {
            byte[] keyArray;

            //Generate HashKey
            MD5 hashMD5 = MD5.Create();
            keyArray = hashMD5.ComputeHash(UTF8Encoding.UTF8.GetBytes(inputValue));
            hashMD5.Clear();

            return Convert.ToHexString(keyArray);
        }
    }
}
