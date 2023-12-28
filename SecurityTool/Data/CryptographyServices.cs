using System.Security.Cryptography;
using System.Text;

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
    }
}
