using System;
using System.Security.Cryptography;

namespace CypAssimetrica
{
    public class RFC2898
    {
        private readonly int cicles;

        /// <summary>
        ///  Construtor
        /// </summary>
        /// <param name="cicles">A contagem de iteração deve ser maior que zero. O número mínimo recomendado de iterações é 1000</param>
        public RFC2898(int cicles)
        {
            this.cicles = cicles;
        }
         
        /// <summary>
        /// Gera salt aleatório
        /// </summary>
        /// <returns></returns>
        private byte[] CreateSalt()
        {
            /*O tamanho de Salt deve ser de 8 bytes ou maior*/
            byte[] salt1 = new byte[256];
            using (RNGCryptoServiceProvider rngCsp = new RNGCryptoServiceProvider())
            {
                // Fill the array with a random value.
                rngCsp.GetBytes(salt1);
            }

            return salt1;
        }

        /// <summary>
        /// Implementa funcionalidade de derivação de chave
        /// </summary>
        /// <param name="text"></param>
        /// <param name="salt"></param>
        /// <returns></returns>
        private Rfc2898DeriveBytes GerarBytes(string text, byte[] salt)
        {
            Rfc2898DeriveBytes k1 = new Rfc2898DeriveBytes(text, salt, cicles);
            return k1;
        }

        /// <summary>
        /// Gera o hash da string informada,
        /// caso não informe um salt o método criará um automáticamente
        /// </summary>
        /// <param name="text"></param>
        /// <param name="salt"></param>
        /// <returns></returns>
        public string GerarHash(string text, byte[] salt = null)
        {
            salt = salt == null ? CreateSalt() : salt;
            var k1 = GerarBytes(text, salt);

            byte[] key = k1.GetBytes(64);

            var hash = Convert.ToBase64String(salt) + "|" + Convert.ToBase64String(key);

            return hash;
        }

        /// <summary>
        /// Verifica se a string informada corresponde ao hash informado
        /// </summary>
        /// <param name="input">string decriptada</param>
        /// <param name="hash">hash correspondente</param>
        /// <returns></returns>
        public bool ValidaHash(string input, string hash)
        {
            var salt = hash.Split('|');
            var origSalt = Convert.FromBase64String(salt[0]);
            var pwd = GerarHash(input, origSalt);

            return hash.Equals(pwd);
        }

        /// <summary>
        /// Obtem o Salt do hash informado
        /// </summary>
        /// <param name="input">hash a verificar</param>
        /// <returns></returns>
        public byte[] RetornaSaltFromHash(string input)
        {
            var salt = input.Split('|');
            var origSalt = Convert.FromBase64String(salt[0]);

            return origSalt;
        }
         
    }
}
