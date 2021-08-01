using NUnit.Framework;
using System.Security.Cryptography;

namespace Test
{
    [TestFixture]
    public class Test
    {
        [Test]
        public void TestRinjdael()
        {
            var texto = "Palmeiras não tem mundial";

            using (RijndaelManaged generator = new RijndaelManaged())
            {
                //gera chave e vetor de inicialização aleatorios
                generator.GenerateKey();
                generator.GenerateIV();

                var cyp = new CypSimetrica.Rinjdael(generator.Key, generator.IV);
                var cyped = cyp.Encrypt(texto);

                Assert.AreEqual(texto, cyp.Decrypt(cyped));
            }
        }

        [Test]
        public void TestRFC2898()
        {
            var texto = "Palmeiras não tem mundial";


            var cyp = new CypAssimetrica.RFC2898(1100);

            var cyped = cyp.GerarHash(texto);
            var salt = cyp.RetornaSaltFromHash(cyped);
           

            Assert.IsTrue(cyp.ValidaHash(texto,cyped));
            Assert.AreEqual(cyped, cyp.GerarHash(texto, salt));
        }

    }
}
