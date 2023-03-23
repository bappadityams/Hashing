using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Hashing.Services
{
    public class HashingService
    {
        public string GenerateSSHAHash(string value, string existingHash)
        {
            using SHA1 sha = new SHA1Managed();
            var passwordBytes = Encoding.ASCII.GetBytes(value);
            var storedBytes = Convert.FromBase64String(existingHash);

            // Skip the first 64 bytes because that is the hashed password + salt. What remains is the salt
            var saltBytes = storedBytes.Skip(20).ToArray();

            // Join the password bytes and salt bytes together to get the hash
            var hash = sha.ComputeHash(JoinArray(passwordBytes, saltBytes));
            // Join the salt again to the end of the hash to get the "hashSalt"
            var hashSalt = JoinArray(hash, saltBytes);
            // Now Base64 encode the array since that's how the old code stores the hashSalt value
            return Convert.ToBase64String(hashSalt);
        }

        public string GenerateSSHA512Hash(string value, string existingHash)
        {
            using SHA512 shaM = new SHA512Managed();
            var passwordBytes = Encoding.ASCII.GetBytes(value);
            var storedBytes = Convert.FromBase64String(existingHash);

            // Skip the first 64 bytes because that is the hashed password + salt. What remains is the salt
            var saltBytes = storedBytes.Skip(64).ToArray();

            // Join the password bytes and salt bytes together to get the hash
            var hash = shaM.ComputeHash(JoinArray(passwordBytes, saltBytes));
            // Join the salt again to the end of the hash to get the "hashSalt"
            var hashSalt = JoinArray(hash, saltBytes);
            // Now Base64 encode the array since that's how the old code stores the hashSalt value
            return Convert.ToBase64String(hashSalt);
        }

        private static byte[] JoinArray(byte[] b1, byte[] b2)
        {
            byte[] b = new byte[b1.Length + b2.Length];
            Buffer.BlockCopy(b1, 0, b, 0, b1.Length);
            Buffer.BlockCopy(b2, 0, b, b1.Length, b2.Length);
            return b;
        }
    }
}