using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        public string AnalyseUsingCharFrequency(string cipher)
        {
            throw new NotImplementedException();
        }
        public string Analyse(string plainText, string cipherText)
        {
            //throw new NotImplementedException();
            Dictionary<char, char> K = new Dictionary<char, char>();
                for (char c = 'a'; c <= 'z'; c++)
                {
                    for (int i = 0; i < plainText.Length; i++)
                    {
                        if (plainText[i] != c)
                        {
                            K[c] = '.';
                        }
                    }
            }
                for (char c = 'a'; c <= 'z'; c++)
                {
                    for (int i = 0; i < plainText.Length; i++)
                    {
                        if (plainText[i] == c)
                        {
                            K[c] = cipherText.ToLower()[i];
                        }
                    }
                }
                string s = "";
            foreach (KeyValuePair<char, char> pair in K)
            {
                s += pair.Value;
            }
          
               string final = "";
               
               for (int i = 0; i < s.Length; i++)
               {
                   if(char.IsLetter(s[i]))
                   {
                       final += s[i];
                   }
                   else
                   {
                       char c = ((char)(final[final.Length - 1]));
                       while(s.Contains(c) || final.Contains(c))
                       {
                           if (c == 'z') c = 'a';
                           else
                           {
                               c++;
                           }
                       }
                       final += c;
                   }
               }

               return final;
        }

        public string Decrypt(string cipherText, string key)
        {
            Dictionary<char, char> k = new Dictionary<char, char>();
            //throw new NotImplementedException();
            int i = 0;
            for (char c = 'a'; c <= 'z'; c++)
            {
                k[key[i]] = c;
                i++;
            }
            string PlaintText = "";
            for (int a = 0; a < cipherText.Length; a++)
            {
                PlaintText += k[cipherText.ToLower()[a]];
            }
            return PlaintText;
        }

        public string Encrypt(string plainText, string key)
        {
            Dictionary<char, char> k = new Dictionary<char, char>();
            //throw new NotImplementedException();
            int i = 0;
            for (char c = 'a'; c <= 'z'; c++)
            {
                k[c] = key[i];
                i++;
            }
            string CipherText = "";
            for (int a = 0; a < plainText.Length; a++)
            {
                CipherText += k[plainText[a]];
            }
            return CipherText.ToUpper();
        }
    }
}
