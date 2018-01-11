using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {
        public string Encrypt(string plainText, int key)
        {
            Dictionary<char, int> P = new Dictionary<char, int>();
            Dictionary<int, char> d = new Dictionary<int, char>();
            int cnt = 0;
            for (char c = 'a'; c <= 'z'; c++)
            {
                P[c] = cnt;
                d[cnt] = c;
                cnt++;
            }
            string CipherText = "";
            foreach (char pt in plainText)
            {
                CipherText += d[((P[pt] + key) % 26)];
            }
            return CipherText.ToUpper();
        }

        public string Decrypt(string cipherText, int key)
        {
            Dictionary<char, int> P = new Dictionary<char, int>();
            Dictionary<int, char> d = new Dictionary<int, char>();
            int cnt = 0;
            for (char c = 'a'; c <= 'z'; c++)
            {
                P[c] = cnt;
                d[cnt] = c;
                cnt++;
            }
            string PlaintText = "";
            foreach(char c in cipherText.ToLower())
            {
                int ch = ((P[c] - key)%26);
                if (ch < 0)
                {
                    ch += 26;
                    PlaintText += d[ch];
                }
                else {
                    PlaintText += d[ch];
                }
            }
            return PlaintText;
        }

        public int Analyse(string plainText, string cipherText)
        {
            Dictionary<char, int> P = new Dictionary<char, int>();
            Dictionary<int, char> d = new Dictionary<int, char>();
            int cnt = 0;
            for (char c = 'a'; c <= 'z'; c++)
            {
                P[c] = cnt;
                d[cnt] = c;
                cnt++;
            }
            int key = 0;
            for(int k = 0 ; k < 26 ; k++)
            {
                 string Hack = "";
                for (int i = 0; i < plainText.Length; i++)
                {
                    if(P[cipherText.ToLower()[i]] == ((P[plainText[i]] + k) % 26))
                    {
                        Hack += d[((P[plainText[i]] + k) % 26)];
                    }
                }
                if (Hack == cipherText.ToLower())
                {
                    key = k; 
                    break;
                }
            }
            return key;
        }
    }
}
