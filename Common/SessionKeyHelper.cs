using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Manage
{
    public class SessionKeyHelper
    {
        public static byte[] CreateSessionKey()
        {
            SymmetricAlgorithm symetricObject = AesCryptoServiceProvider.Create();
            byte[] sessionKey = symetricObject.Key;

            return sessionKey;
        }

        public static byte[] EncryptSessionKey(X509Certificate2 certificate, byte[] sessionKey)
        {
            /// Looks for the certificate's public key to encrypt a message with RSA
            RSACryptoServiceProvider csp = (RSACryptoServiceProvider)certificate.PublicKey.Key;

            if (csp == null)
            {
                throw new Exception("Valid certificate was not found.");
            }

            //enkripcija sessionKey sa javnim kljucem servera
            byte[] encryptedSessionKey = csp.Encrypt(sessionKey, false);

            return encryptedSessionKey;
        }

        public static byte[] DecryptSessionKey(X509Certificate2 certificate, byte[] encryptedSessionKey)
        {
            /// Looks for the certificate's public key to encrypt a message with RSA
            RSACryptoServiceProvider csp = (RSACryptoServiceProvider)certificate.PrivateKey;

            if (csp == null)
            {
                throw new Exception("Valid certificate was not found.");
            }

            //dekripcija encrypredSessionKey sa privatnim kljucem servera
            byte[] sessionKey = csp.Decrypt(encryptedSessionKey, false);

            return sessionKey;
        }

        public static void PrintSessionKey(byte[] sessionKey)
        {
            Console.WriteLine(Encoding.Default.GetString(sessionKey));
        }
    }
}
