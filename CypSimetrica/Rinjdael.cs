using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace CypSimetrica
{
    public class Rinjdael
    {

        private readonly byte[] key;
        private readonly byte[] vetor;

        /// <summary>
        /// Construtor
        /// </summary>
        /// <param name="key">Representa a chave secreta para o algoritmo simétrico.</param>
        /// <param name="iv">Representa o vetor de inicialização (IV) do algoritmo simétrico.</param>
        public Rinjdael(byte[] key, byte[] iv)
        {
            this.key = key;
            this.vetor = iv;
        }

        /// <summary>
        /// Criptografa texto informado
        /// </summary>
        /// <param name="text">texto a ser criptografado</param>
        /// <returns>
        /// valor criptografado
        /// </returns>
        public string Encrypt(string text)
        {
            try
            {
                if (!string.IsNullOrEmpty(text) && IsEncrypt(text) == false)
                {
                    byte[] bytes = new UTF8Encoding().GetBytes(text);
                    Rijndael rijndael = (Rijndael)new RijndaelManaged();
                    rijndael.KeySize = 256;
                    var cypText = "";

                    using (MemoryStream memoryStream = new MemoryStream())
                    {
                        using (CryptoStream cryptoStream = new CryptoStream((Stream)memoryStream,
                        rijndael.CreateEncryptor(this.key, this.vetor), CryptoStreamMode.Write))
                        {
                            cryptoStream.Write(bytes, 0, bytes.Length);
                            cryptoStream.FlushFinalBlock();
                            cypText = Convert.ToBase64String(memoryStream.ToArray());
                        }
                    }

                    return GetSubstringKey() + cypText;
                }
                else
                {
                    return text;
                }
            }
            catch (Exception ex)
            {
                throw new ApplicationException("Erro ao criptografar", ex);
            }
        }

        /// <summary>
        /// Descriptografa o texto informado
        /// </summary>
        /// <param name="text">texto criptografado</param>
        /// <returns>
        /// texto original
        /// </returns>
        public string Decrypt(string text)
        {
            try
            {
                if (IsEncrypt(text))
                {
                    text = text.Replace(GetSubstringKey(), "");
                    if (string.IsNullOrEmpty(text))
                        return (string)null;

                    byte[] buffer = Convert.FromBase64String(text);
                    Rijndael rijndael = (Rijndael)new RijndaelManaged();
                    rijndael.KeySize = 256;
                    byte[] result = null;

                    using (MemoryStream memoryStream = new MemoryStream())
                    {
                        using (CryptoStream cryptoStream = new CryptoStream((Stream)memoryStream,
                            rijndael.CreateDecryptor(this.key, this.vetor), CryptoStreamMode.Write))
                        {

                            cryptoStream.Write(buffer, 0, buffer.Length);
                            cryptoStream.FlushFinalBlock();
                            result = memoryStream.ToArray();
                        }
                    }

                    return new UTF8Encoding().GetString(result);
                }
                else
                    return text;

            }
            catch (Exception ex)
            {
                throw new ApplicationException("Erro ao descriptografar", ex);
            }
        }


        public bool IsEncrypt(string text)
        {
            var isCyp = false;
            if (!string.IsNullOrEmpty(text) && text.Length > 6)
            {
                var sub = GetSubstringKey();
                var tam = sub.Length;

                if (tam > text.Length) return false;

                isCyp = sub == text.Substring(0, tam);
            }

            return isCyp;
        }

        /// <summary>
        /// Retorna texto para identificar criptografia
        /// desse modo é menos custoso para identificar se uma string foi
        /// criptografada ou não
        /// </summary>
        /// <returns>
        /// Substring Key
        /// </returns>

        public string GetSubstringKey()
        {
            var subIv = Convert.ToBase64String(this.vetor);

            if (subIv.Length > 10)
            {
                return subIv.Substring(subIv.Length - 6, 6);
            }

            return "";
        }
    }
}
