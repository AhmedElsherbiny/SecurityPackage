using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Numerics;
namespace SecurityLibrary.RSA
{
    public class RSA
    {
        public int Encrypt(int p, int q, int M, int e)
        {
            int n = p * q;
            BigInteger res = BigInteger.ModPow(BigInteger.Parse(M.ToString()), BigInteger.Parse(e.ToString()), BigInteger.Parse(n.ToString()));
            return int.Parse(res.ToString()) ;
        }

        public int Decrypt(int p, int q, int C, int e)
        {
            //throw new NotImplementedException();
            int n = p * q;
            int Totient = ((p - 1) * (q - 1));
            int d = 1;
            while (((d * e) % Totient) != 1)
            {
                d++;
            }
            BigInteger res = BigInteger.ModPow(BigInteger.Parse(C.ToString()), BigInteger.Parse(d.ToString()), BigInteger.Parse(n.ToString()));
            return int.Parse(res.ToString());
        }
    }
}
