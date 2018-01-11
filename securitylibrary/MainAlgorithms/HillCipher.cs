using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SecurityLibrary.MatrixOperation;
using Accord.Math;
using SecurityLibrary.AES;
namespace SecurityLibrary
{
    /// <summary>
    /// The List<int> is row based. Which means
    /// </summary>
    public class HillCipher : ICryptographicTechnique<string, string>, ICryptographicTechnique<List<int>, List<int>>
    {
        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
            MatrixOP r = new MatrixOP();
            //throw new NotImplementedException();
            Dictionary<char, int> DT = new Dictionary<char, int>();
            Dictionary<int, char> CT = new Dictionary<int, char>();
            int cnt = 0;
            for (char c = 'a'; c <= 'z'; c++)
            {
                DT[c] = cnt;
                CT[cnt] = c;
                cnt++;
            }
            string plaintext = "";
            string ciphertext = "";
            for (int i = 0; i < plainText.Count; i++)
            {
                plaintext += CT[plainText[i]];
                ciphertext += CT[cipherText[i]];
            }
            string[] split = new string[plaintext.Length / 2 + (plaintext.Length % 2 == 0 ? 0 : 1)];
            for (int i = 0; i < split.Length; i++)
            {
                split[i] = plaintext.Substring(i * 2, i * 2 + 2 > plaintext.Length ? 1 : 2);
            }
            string[] splitc = new string[ciphertext.Length / 2 + (ciphertext.Length % 2 == 0 ? 0 : 1)];
            for (int i = 0; i < splitc.Length; i++)
            {
                splitc[i] = ciphertext.Substring(i * 2, i * 2 + 2 > ciphertext.Length ? 1 : 2);
            }
            List<string> PermKey = new List<string>();
            List<string> ciph = new List<string>();
            for (int i = 0; i < split.Length; i++)
            {
                string perm = "";
                string ch = "";
                for (int j = i + 1; j < split.Length; j++)
                {
                    perm += split[i] + split[j];
                    ch += splitc[i] + splitc[j];
                    PermKey.Add(perm);
                    ciph.Add(ch);
                    perm = "";
                    ch = "";
                }
            }
            List<int> CalInverse = new List<int>();
            for (int i = 0; i < PermKey.Count; i++)
            {
                CalInverse.Add(r.calculateInverse(PermKey[i]));
            }
            int cnterr = 0;
            for (int i = 0; i < CalInverse.Count; i++)
            {
                if(CalInverse[i] < 0) cnterr++;
            }
            if (cnterr == CalInverse.Count)
            {
                throw new InvalidAnlysisException();
            }
            int invMul = 0;
            string pl = "";
            string ct = "";
            for (int i = 0; i < CalInverse.Count; i++)
            {
                if (CalInverse[i] > 0)
                {
                    invMul = CalInverse[i];
                    pl = PermKey[i];
                    ct = ciph[i];
                    break;
                }
            }
            ////////////////////plaintext/////////////////////
            int[,] keymat = new int[2, 2];
            int idx = 0;
            for (int i = 0; i < 2; i++)
            {
                int cc = idx;
                for (int j = 0; j < 2; j++)
                {
                    keymat[i, j] = DT[pl[idx]];
                    idx++;
                    cc++;
                }
                cc = idx;
            }
            ////////////////////ciphertext//////////////////
            int[,] cimat = new int[2, 2];
            idx = 0;
            for (int i = 0; i < 2; i++)
            {
                int cc = idx;
                for (int j = 0; j < 2; j++)
                {
                    cimat[j, i] = DT[ct[idx]];
                    idx++;
                    cc++;
                }
                cc = idx;
            }
            ///////////////////cofactors//////////////////
            int A = keymat[0, 0];
            int B = keymat[0, 1];
            int C = keymat[1, 0];
            int D = keymat[1, 1];
            keymat[0, 0] = invMul * D;
            keymat[1, 1] = invMul * A;
            keymat[1, 0] = invMul * (B * -1);
            keymat[0, 1] = invMul * (C * -1);
            for (int i = 0; i < 2; i++)
            {
                for (int j = 0; j < 2; j++)
                {
                    while (keymat[i, j] < 0)
                    {
                        keymat[i, j] += 26;
                    }
                    while (keymat[i, j] > 26)
                    {
                        keymat[i, j] -= 26;
                    }
                }
            }
            int[,] Mulapp = new int[2, 2];
            for (int i = 0; i < 2; i++)
            {
                for (int j = 0; j < 2; j++)
                {
                    int sum = 0;
                    for (int k = 0; k < 2; k++)
                    {
                        sum += cimat[i, k] * keymat[k, j];
                    }
                    Mulapp[i, j] = sum % 26;
                }
            }
            List<int> key = new List<int>();
            for (int i = 0; i < 2; i++)
            {
                for (int j = 0; j < 2; j++)
                {
                    key.Add(Mulapp[i, j]);
                }
            }
            return key;
        }

        public string Analyse(string plainText, string cipherText)
        {
            MatrixOP r = new MatrixOP();
            //throw new NotImplementedException();
            Dictionary<char, int> DT = new Dictionary<char, int>();
            Dictionary<int, char> CT = new Dictionary<int, char>();
            int cnt = 0;
            for (char c = 'a'; c <= 'z'; c++)
            {
                DT[c] = cnt;
                CT[cnt] = c;
                cnt++;
            }
            string[] split = new string[plainText.Length / 2 + (plainText.Length % 2 == 0 ? 0 : 1)];
            for (int i = 0; i < split.Length; i++)
            {
                split[i] = plainText.Substring(i * 2, i * 2 + 2 > plainText.Length ? 1 : 2);
            }
            string[] splitc = new string[cipherText.Length / 2 + (cipherText.Length % 2 == 0 ? 0 : 1)];
            for (int i = 0; i < splitc.Length; i++)
            {
                splitc[i] = cipherText.ToLower().Substring(i * 2, i * 2 + 2 > cipherText.Length ? 1 : 2);
            }
            List<string> PermKey = new List<string>();
            List<string> ciph = new List<string>();
            for (int i = 0; i < split.Length; i++)
            {
                string perm = "";
                string ch = "";
                for (int j = i + 1; j < split.Length; j++)
                {
                    perm += split[i] + split[j];
                    ch += splitc[i] + splitc[j];
                    PermKey.Add(perm);
                    ciph.Add(ch);
                    perm = "";
                    ch = "";
                }
            }
            List<int> CalInverse = new List<int>();
            for (int i = 0; i < PermKey.Count; i++)
            {
                CalInverse.Add(r.calculateInverse(PermKey[i]));
            }
            int cnterr = 0;
            for (int i = 0; i < CalInverse.Count; i++)
            {
                if(CalInverse[i] < 0) cnterr++;
            }
            if (cnterr == CalInverse.Count)
            {
                throw new InvalidAnlysisException();
            }
            int invMul = 0;
            string pl = "";
            string ct = "";
            for (int i = 0; i < CalInverse.Count; i++)
            {
                if (CalInverse[i] > 0)
                {
                    invMul = CalInverse[i];
                    pl = PermKey[i];
                    ct = ciph[i];
                    break;
                }
            }
            ////////////////////plaintext/////////////////////
            int[,] keymat = new int[2, 2];
            int idx = 0;
            for (int i = 0; i < 2; i++)
            {
                int cc = idx;
                for (int j = 0; j < 2; j++)
                {
                    keymat[i, j] = DT[pl[idx]];
                    idx++;
                    cc++;
                }
                cc = idx;
            }
            ////////////////////ciphertext//////////////////
            int[,] cimat = new int[2, 2];
            idx = 0;
            for (int i = 0; i < 2; i++)
            {
                int cc = idx;
                for (int j = 0; j < 2; j++)
                {
                    cimat[j, i] = DT[ct[idx]];
                    idx++;
                    cc++;
                }
                cc = idx;
            }
            ///////////////////cofactors//////////////////
            int A = keymat[0, 0];
            int B = keymat[0, 1];
            int C = keymat[1, 0];
            int D = keymat[1, 1];
            keymat[0, 0] = invMul * D;
            keymat[1, 1] = invMul * A;
            keymat[1, 0] = invMul * (B * -1);
            keymat[0, 1] = invMul * (C * -1);
            for (int i = 0; i < 2; i++)
            {
                for (int j = 0; j < 2; j++)
                {
                    while (keymat[i, j] < 0)
                    {
                        keymat[i, j] += 26;
                    }
                    while (keymat[i, j] > 26)
                    {
                        keymat[i, j] -= 26;
                    }
                }
            }
            int[,] Mulapp = new int[2, 2];
            for (int i = 0; i < 2; i++)
            {
                for (int j = 0; j < 2; j++)
                {
                    int sum = 0;
                    for (int k = 0; k < 2; k++)
                    {
                        sum += cimat[i, k] * keymat[k, j];
                    }
                    Mulapp[i, j] = sum % 26;
                }
            }
            string key = "";
            for (int i = 0; i < 2; i++)
            {
                for (int j = 0; j < 2; j++)
                {
                    key += CT[Mulapp[i, j]];
                }
            }
            return key;
        }

        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            //throw new NotImplementedException();
            MatrixOP mp = new MatrixOP();
            int n = key.Count;
            if (key.Count % 2 == 0)
                n = n / 2;
            else
                n = (n / 2) - 1;
            int m = (cipherText.Count / n);
            double[,] matKey = new double[n, n];
            int[,] matPlain = new int[n, m];
            int[,] matRes = new int[n, m];
            int rp = 0;
            for (int i = 0; i < n; i++)
            {
                int cc = rp;
                for (int j = 0; j < n; j++)
                {
                    matKey[i, j] = key[cc];
                    rp++;
                    cc++;
                }
                cc = rp;
            }
            rp = 0;
            for (int i = 0; i < m; i++)
            {
                int cc = rp;
                for (int j = 0; j < n; j++)
                {
                    matPlain[j, i] = cipherText[cc];
                    rp++;
                    cc++;
                }
                cc = rp;
            }

            int mat = int.Parse(Matrix.Determinant(matKey).ToString());
            //Console.WriteLine(mat);
            while (mat < 0)
            {
                mat += 26;
            }
            while (mat > 26)
            {
                mat -= 26;
            }
            ////////////////checking valid///////////////
            ExtendedEuclid e = new ExtendedEuclid();
            int mulinv = e.GetMultiplicativeInverse(mat, 26);
            if (mulinv == -1)
            {
                throw new InvalidAnlysisException();
            }
            int[,] matl = new int[n, n];
            for (int i = 0; i < n; i++)
            {
                for (int j = 0; j < n; j++)
                {
                    matl[i, j] = int.Parse(Math.Floor((Math.Pow(-1, i + j) * (int.Parse(Matrix.Determinant(mp.CreateSmallerMatrix(matKey, i, j)).ToString()))) % 26).ToString());
                    if (matl[i, j] % 26 < 0)
                    {
                        matl[i, j] += 26;
                    }
                }
            }

            /////////////////////////////////
            int[,] matKeyinverse = new int[n, n];
            for (int i = 0; i < n; i++)
            {
                for (int j = 0; j < n; j++)
                {
                    matKeyinverse[i, j] = matl[j, i];
                    matKeyinverse[i, j] = (mulinv * matKeyinverse[i, j]) % 26;
                }
            }
            for (int i = 0; i < n; i++)
            {
                for (int j = 0; j < m; j++)
                {
                    int sum = 0;
                    for (int k = 0; k < n; k++)
                    {
                        sum += matKeyinverse[i, k] * matPlain[k, j];
                    }
                    matRes[i, j] = sum % 26;
                }
            }
            List<int> PlaintText = new List<int>();
            for (int i = 0; i < m; i++)
            {
                for (int j = 0; j < n; j++)
                {
                    PlaintText.Add(matRes[j, i]);
                }
            }
            return PlaintText;            
        }

        public string Decrypt(string cipherText, string key)
        {
            MatrixOP mp = new MatrixOP();
            Dictionary<char, int> DT = new Dictionary<char, int>();
            Dictionary<int, char> CT = new Dictionary<int, char>();
            int cnt = 0;
            for (char c = 'a'; c <= 'z'; c++)
            {
                DT[c] = cnt;
                CT[cnt] = c;
                cnt++;
            }
            int n = key.Length;
            if (key.Length % 2 == 0)
                n = n / 2;
            else
                n = (n / 2) - 1;
            int m = (cipherText.Length / n);
            double[,] matKey = new double[n, n];
            int[,] matPlain = new int[n, m];
            int[,] matRes = new int[n, m];
            int rp = 0;
            for (int i = 0; i < n; i++)
            {
                int cc = rp;
                for (int j = 0; j < n; j++)
                {
                    matKey[i, j] = DT[key[cc]];
                    rp++;
                    cc++;
                }
                cc = rp;
            }
            rp = 0;
            for (int i = 0; i < m; i++)
            {
                int cc = rp;
                for (int j = 0; j < n; j++)
                {
                    matPlain[j, i] = DT[cipherText.ToLower()[cc]];
                    rp++;
                    cc++;
                }
                cc = rp;
            }

            int mat = int.Parse(Matrix.Determinant(matKey).ToString()) % 26;
            //Console.WriteLine(mat);
            while (mat < 0)
            {
                mat += 26;
            }
            int x = 0;
            for (int b = 0; b < 26; b++)
            {
                if ((b * mat) % 26 == 1)
                {
                    x = b;
                    break;
                }
            }
            //Console.WriteLine(x);
            int[,] matl = new int[n, n];
            for (int i = 0; i < n; i++)
            {
                for (int j = 0; j < n; j++)
                {
                    matl[i, j] = int.Parse(Math.Floor((Math.Pow(-1, i + j) * (int.Parse(Matrix.Determinant(mp.CreateSmallerMatrix(matKey, i, j)).ToString()))) % 26).ToString());
                    if (matl[i, j] % 26 < 0)
                    {
                        matl[i, j] += 26;
                    }
                }
            }

            /////////////////////////////////
            int[,] matKeyinverse = new int[n, n];
            for (int i = 0; i < n; i++)
            {
                for (int j = 0; j < n; j++)
                {
                    matKeyinverse[i, j] = matl[j, i];
                    matKeyinverse[i, j] = (x * matKeyinverse[i, j]) % 26;
                }
            }
            for (int i = 0; i < n; i++)
            {
                for (int j = 0; j < m; j++)
                {
                    int sum = 0;
                    for (int k = 0; k < n; k++)
                    {
                        sum += matKeyinverse[i, k] * matPlain[k, j];
                    }
                    matRes[i, j] = sum % 26;
                }
            }
            string PlaintText = "";
            for (int i = 0; i < m; i++)
            {
                for (int j = 0; j < n; j++)
                {
                    PlaintText += CT[matRes[j, i]];
                }
            }
            return PlaintText.ToLower();            
        }

        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            
            //throw new NotImplementedException();
            List<int> CipherText = new List<int>();
            int n = key.Count;
            if (key.Count % 2 == 0)
                n = n / 2;
            else
                n = (n / 2) - 1;
            int m = (plainText.Count / n);
            int[,] matKey = new int[n, n];
            int[,] matPlain = new int[n, m];
            int[,] matRes = new int[n, m];
            int rp = 0;
            for (int i = 0; i < n; i++)
            {
                int cc = rp;
                for (int j = 0; j < n; j++)
                {
                    matKey[i, j] = key[cc];
                    rp++;
                    cc++;
                }
                cc = rp;
            }
            rp = 0;
            for (int i = 0; i < m; i++)
            {
                int cc = rp;
                for (int j = 0; j < n; j++)
                {
                    matPlain[j, i] = plainText[cc];
                    rp++;
                    cc++;
                }
                cc = rp;
            }
            for (int i = 0; i < n; i++)
            {
                for (int j = 0; j < m; j++)
                {
                    int sum = 0;
                    for (int k = 0; k < n; k++)
                    {
                        sum += matKey[i, k] * matPlain[k, j];
                    }
                    matRes[i, j] = sum % 26;
                }
            }
            for (int i = 0; i < m; i++)
            {
                for (int j = 0; j < n; j++)
                {
                    CipherText.Add(matRes[j, i]);
                }
            }
            return CipherText;
        }

        public string Encrypt(string plainText, string key)
        {
            //throw new NotImplementedException();
            Dictionary<char, int> DT = new Dictionary<char, int>();
            Dictionary<int, char> CT = new Dictionary<int, char>();
            int cnt = 0;
            for (char c = 'a'; c <= 'z'; c++)
            {
                DT[c] = cnt;
                CT[cnt] = c;
                cnt++;
            }
            int n = key.Length;
            if (key.Length % 2 == 0)
                n = n / 2;
            else
                n = (n / 2) - 1;
            int m = (plainText.Length / n);
            int[,] matKey = new int[n, n];
            int[,] matPlain = new int[n, m];
            int[,] matRes = new int[n, m];
            int rp = 0;
            for (int i = 0; i < n; i++)
            {
                int cc = rp;
                for (int j = 0; j < n; j++)
                {
                    matKey[i, j] = DT[key[cc]];
                    rp++;
                    cc++;
                }
                cc = rp;
            }
            rp = 0;
            for (int i = 0; i < m; i++)
            {
                int cc = rp;
                for (int j = 0; j < n; j++)
                {
                    matPlain[j, i] = DT[plainText[cc]];
                    rp++;
                    cc++;
                }
                cc = rp;
            }
            for (int i = 0; i < n; i++)
            {
                for (int j = 0; j < m; j++)
                {
                    int sum = 0;
                    for (int k = 0; k < n; k++)
                    {
                        sum += matKey[i, k] * matPlain[k, j];
                    }
                    matRes[i, j] = sum % 26;
                }
            }
            string CipherText = "";
            for (int i = 0; i < m; i++)
            {
                for (int j = 0; j < n; j++)
                {
                    CipherText += CT[matRes[j, i]];
                }
            }
            return CipherText.ToUpper();
        }
        public List<int> Analyse3By3Key(List<int> plainText, List<int> cipherText)
        {
            //throw new NotImplementedException();
            MatrixOP r = new MatrixOP();
            Dictionary<char, int> DT = new Dictionary<char, int>();
            Dictionary<int, char> CT = new Dictionary<int, char>();
            int cnt = 0;
            for (char c = 'a'; c <= 'z'; c++)
            {
                DT[c] = cnt;
                CT[cnt] = c;
                cnt++;
            }
            string plaintext = "";
            string ciphertext = "";
            for (int i = 0; i < plainText.Count; i++)
            {
                plaintext += CT[plainText[i]];
                ciphertext += CT[cipherText[i]];
            }
            string[] split = new string[plaintext.Length / 3 + (plaintext.Length % 3 == 0 ? 0 : 1)];
            for (int i = 0; i < split.Length; i++)
            {
                split[i] = plaintext.Substring(i * 3, i * 3 + 3 > plaintext.Length ? 1 : 3);
            }
            string[] splitc = new string[ciphertext.Length / 3 + (ciphertext.Length % 3 == 0 ? 0 : 1)];
            for (int i = 0; i < splitc.Length; i++)
            {
                splitc[i] = ciphertext.ToLower().Substring(i * 3, i * 3 + 3 > ciphertext.Length ? 1 : 3);
            }
            List<string> PermKey = new List<string>();
            List<string> ciph = new List<string>();
            for (int i = 0; i < split.Length; i++)
            {
                string perm = "";
                string ch = "";
                for (int j = i + 2; j < split.Length; j++)
                {
                    perm += split[i] + split[j - 1] + split[j];
                    ch += splitc[i] + splitc[j - 1] + splitc[j];
                    PermKey.Add(perm);
                    ciph.Add(ch);
                    perm = "";
                    ch = "";
                }
            }
            List<int> In = new List<int>();
            for (int i = 0; i < PermKey.Count; i++)
            {
                In.Add(r.Inversekey(PermKey[i]));
            }
            int cnterr = 0;
            for (int i = 0; i < In.Count; i++)
            {
                if(In[i] < 0) cnterr++;
            }
            if (cnterr == In.Count)
            {
                throw new InvalidAnlysisException();
            }
            int invMul = 0;
            string pl = "";
            string ct = "";
            for (int i = 0; i < In.Count; i++)
            {
                if (In[i] > 0)
                {
                    invMul = In[i];
                    pl = PermKey[i];
                    ct = ciph[i];
                    break;
                }
            }
            double[,] keymat = new double[3, 3];
            int[,] Ciphermat = new int[3, 3];
            int rp = 0;
            for (int i = 0; i < 3; i++)
            {
                int cc = rp;
                for (int j = 0; j < 3; j++)
                {
                    keymat[i, j] = DT[pl[cc]];
                    rp++;
                    cc++;
                }
                cc = rp;
            }
            rp = 0;
            for (int i = 0; i < 3; i++)
            {
                int cc = rp;
                for (int j = 0; j < 3; j++)
                {
                    Ciphermat[i, j] = DT[ct[cc]];
                    rp++;
                    cc++;
                }
                cc = rp;
            }
            /////////////////////////cofactors///////////////////////////////
            int[,] matl = new int[3, 3];
            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    matl[i, j] = int.Parse(Math.Floor((Math.Pow(-1, i + j) * (int.Parse(Matrix.Determinant(r.CreateSmallerMatrix(keymat, i, j)).ToString())))).ToString());
                    while (matl[i, j] < 0)
                    {
                        matl[i, j] += 26;
                    }
                    while (matl[i, j] > 26)
                    {
                        matl[i, j] -= 26;
                    }
                }
            }
            //////////////////////////////////////////////////////////////////
            //////////////////////////////////////////////////////////////////
            int[,] matKeyinverse = new int[3, 3];
            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    matKeyinverse[i, j] = matl[j, i];
                    matKeyinverse[i, j] = (invMul * matKeyinverse[i, j]) % 26;
                }
            }
            //////////////////////////////////inverse///////////////////////////////////
            int[,] matRes = new int[3, 3];
            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    int sum = 0;
                    for (int k = 0; k < 3; k++)
                    {
                        sum += matKeyinverse[i, k] * Ciphermat[k, j];
                    }
                    matRes[i, j] = sum % 26;
                }
            }
            List<int>key = new List<int>();
            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    key.Add(matRes[j, i]);
                }
            }
            return key;
        }

        public string Analyse3By3Key(string plainText, string cipherText)
        {
            //throw new NotImplementedException();
            MatrixOP r = new MatrixOP();
            Dictionary<char, int> DT = new Dictionary<char, int>();
            Dictionary<int, char> CT = new Dictionary<int, char>();
            int cnt = 0;
            for (char c = 'a'; c <= 'z'; c++)
            {
                DT[c] = cnt;
                CT[cnt] = c;
                cnt++;
            }
            string[] split = new string[plainText.Length / 3 + (plainText.Length % 3 == 0 ? 0 : 1)];
            for (int i = 0; i < split.Length; i++)
            {
                split[i] = plainText.Substring(i * 3, i * 3 + 3 > plainText.Length ? 1 : 3);
            }
            string[] splitc = new string[cipherText.Length / 3 + (cipherText.Length % 3 == 0 ? 0 : 1)];
            for (int i = 0; i < splitc.Length; i++)
            {
                splitc[i] = cipherText.ToLower().Substring(i * 3, i * 3 + 3 > cipherText.Length ? 1 : 3);
            }
            List<string> PermKey = new List<string>();
            List<string> ciph = new List<string>();
            for (int i = 0; i < split.Length; i++)
            {
                string perm = "";
                string ch = "";
                for (int j = i + 2; j < split.Length; j++)
                {
                    perm += split[i] + split[j - 1] + split[j];
                    ch += splitc[i] + splitc[j - 1] + splitc[j];
                    PermKey.Add(perm);
                    ciph.Add(ch);
                    perm = "";
                    ch = "";
                }
            }
            List<int> In = new List<int>();
            for (int i = 0; i < PermKey.Count; i++)
            {
                In.Add(r.Inversekey(PermKey[i]));
            }
            int cnterr = 0;
            for (int i = 0; i < In.Count; i++)
            {
                if (In[i] < 0) cnterr++;
            }
            if (cnterr == In.Count)
            {
                throw new InvalidAnlysisException();
            }
            int invMul = 0;
            string pl = "";
            string ct = "";
            for (int i = 0; i < In.Count; i++)
            {
                if (In[i] > 0)
                {
                    invMul = In[i];
                    pl = PermKey[i];
                    ct = ciph[i];
                    break;
                }
            }
            double[,] keymat = new double[3, 3];
            int[,] Ciphermat = new int[3, 3];
            int rp = 0;
            for (int i = 0; i < 3; i++)
            {
                int cc = rp;
                for (int j = 0; j < 3; j++)
                {
                    keymat[i, j] = DT[pl[cc]];
                    rp++;
                    cc++;
                }
                cc = rp;
            }
            rp = 0;
            for (int i = 0; i < 3; i++)
            {
                int cc = rp;
                for (int j = 0; j < 3; j++)
                {
                    Ciphermat[i, j] = DT[ct[cc]];
                    rp++;
                    cc++;
                }
                cc = rp;
            }
            /////////////////////////cofactors///////////////////////////////
            int[,] matl = new int[3, 3];
            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    matl[i, j] = int.Parse(Math.Floor((Math.Pow(-1, i + j) * (int.Parse(Matrix.Determinant(r.CreateSmallerMatrix(keymat, i, j)).ToString())))).ToString());
                    while (matl[i, j] < 0)
                    {
                        matl[i, j] += 26;
                    }
                    while (matl[i, j] > 26)
                    {
                        matl[i, j] -= 26;
                    }
                }
            }
            //////////////////////////////////////////////////////////////////
            //////////////////////////////////////////////////////////////////
            int[,] matKeyinverse = new int[3, 3];
            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    matKeyinverse[i, j] = matl[j, i];
                    matKeyinverse[i, j] = (invMul * matKeyinverse[i, j]) % 26;
                }
            }
            //////////////////////////////////inverse///////////////////////////////////
            int[,] matRes = new int[3, 3];
            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    int sum = 0;
                    for (int k = 0; k < 3; k++)
                    {
                        sum += matKeyinverse[i, k] * Ciphermat[k, j];
                    }
                    matRes[i, j] = sum % 26;
                }
            }
            string key = "";
            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    key += CT[matRes[j, i]];
                }
            }
            return key;
        }
    }
}
