using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographicTechnique<string, string>
    {
        static string RemoveDuplicateChars(string key)
        {
            // --- Removes duplicate chars using string concats. ---
            // Store encountered letters in this string.
            string table = "";

            // Store the result in this string.
            string result = "";

            // Loop over each character.
            foreach (char value in key)
            {
                // See if character is in the table.
                if (table.IndexOf(value) == -1)
                {
                    // Append to the table and the result.
                    table += value;
                    result += value;
                }
            }
            return result;
        }
        public string RemoveXfromPlainText(string plainText)
        {
            if (plainText[plainText.Length - 1] == 'x')
            {
                string val = "";
                for (int i = 0; i < plainText.Length - 1; i++)
                {
                    val += plainText[i];
                }
                plainText = val;
            }
            string x = "";
            string d = "";
            for (int i = 2; i < plainText.Length; )
            {
                char a = plainText[i - 2];
                char b = plainText[i];
                char c = plainText[i - 1];
                x += a;
                if (a == b && c == 'x')
                {
                    x += b;
                    i += 3;
                }
                else
                {
                    i++;
                }
            }
            x += plainText[plainText.Length - 2].ToString() + plainText[plainText.Length - 1].ToString();
            return x;
        }
        public string Analyse(string plainText, string cipherText)
        {
            throw new NotImplementedException();
        }
        public string Analyse(string plainText)
        {
            throw new NotImplementedException();
        }
        public string Decrypt(string cipherText, string key)
        {
            //int k;
            string[,] pf = new string[5, 5];
            //remove RemoveDuplicateChars 
            string x = RemoveDuplicateChars(key);
            for (char d = 'a'; d <= 'z'; d++)
            {
                if (x.Contains(d) || d == 'j')
                {
                    continue;
                }
                else
                {
                    x += d;
                }
            }
            string e = "";
            int z = 0;
            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    if (x[z] == 'i')
                    {
                        e = x[z] + "/" + "j";
                        pf[i, j] = e;
                    }
                    else
                    {
                        pf[i, j] = x[z].ToString();

                    }
                    z++;
                }
            }
            ////////////////////////////////////////////
         
            ////////////////////////////////////////////
            string[] split = new string[cipherText.Length / 2 + (cipherText.Length % 2 == 0 ? 0 : 1)];
            for (int i = 0; i < split.Length; i++)
            {

                split[i] = cipherText.ToLower().Substring(i * 2, i * 2 + 2 > cipherText.Length ? 1 : 2);
            }
            string PlaintText = "";
            for (int k = 0; k < split.Length; k++)
            {
                string d = "";
                for (int i = 0; i < 5; i++)
                {
                    for (int j = 0; j < 5; j++)
                    {
                        if (pf[i, j] == split[k][0].ToString() || (pf[i, j].Length == 3 && pf[i, j][0].ToString() == split[k][0].ToString()) || (pf[i, j].Length == 3 && pf[i, j][2].ToString() == split[k][0].ToString()))
                        {
                            d += i.ToString() + j.ToString();
                        }
                    }
                }
                for (int i = 0; i < 5; i++)
                {
                    for (int j = 0; j < 5; j++)
                    {
                        if (pf[i, j] == split[k][1].ToString() || (pf[i, j].Length == 3 && pf[i, j][0].ToString() == split[k][1].ToString()) || (pf[i, j].Length == 3 && pf[i, j][2].ToString() == split[k][1].ToString()))
                        {
                            d += i.ToString() + j.ToString();
                        }
                    }
                }
               //Console.WriteLine(d);
                int x1 = Int32.Parse(d[0].ToString());
                int x2 = Int32.Parse(d[2].ToString());
                int y1 = Int32.Parse(d[1].ToString());
                int y2 = Int32.Parse(d[3].ToString());
                ///////////////////////////////////////
                if (y1 == y2)
                {
                    if (x1 == 0) { x1 = 4; x2--; }
                    else if (x2 == 0) { x2 = 4; x1--; }
                    else { x1--; x2--; }
                }
                else if (x1 == x2)
                {
                    if (y1 == 0) { y1 = 4; y2--; }
                    else if (y2 == 0) { y2 = 4; y1--; }
                    else { y1--; y2--; }
                }
                else
                {
                    int t = y1;
                    y1 = y2;
                    y2 = t;
                }
                //////////////////////////////////////
                if (pf[x1, y1] == "i/j")
                {
                    if (pf[x1, y1][0] == 'i')
                    {
                        PlaintText += pf[x1, y1][0].ToString() + pf[x2, y2];
                    }
                    else if (pf[x1, y1][2] == 'j')
                    {
                        PlaintText += pf[x1, y1][2].ToString() + pf[x2, y2];
                    }
                }
                else if (pf[x2, y2] == "i/j")
                {
                    if (pf[x2, y2][0] == 'i')
                    {
                        PlaintText += pf[x1, y1] + pf[x2, y2][0].ToString();
                    }
                    else if (pf[x2, y2][2] == 'j')
                    {
                        PlaintText += pf[x1, y1] + pf[x2, y2][2].ToString();
                    }
                }
                else
                {
                    PlaintText += pf[x1, y1] + pf[x2, y2];
                }
            }
            string PlaintTextAfterRemoveX = RemoveXfromPlainText(PlaintText);
            return PlaintTextAfterRemoveX.ToLower();
        }

        public string Encrypt(string plainText, string key)
        {
            //throw new NotImplementedException();
            string[,] pf = new string[5, 5];
            //remove RemoveDuplicateChars 
            string x = RemoveDuplicateChars(key);
            for (char d = 'a'; d <= 'z'; d++)
            {
                if (x.Contains(d) || d == 'j')
                {
                    continue;
                }
                else
                {
                    x += d;
                }
            }
            string e = "";
            int z = 0;
            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    if (x[z] == 'i')
                    {
                        e = x[z] + "/" + "j";
                        pf[i, j] = e;
                    }
                    else
                    {
                        pf[i, j] = x[z].ToString();

                    }
                    z++;
                }
            }
            StringBuilder sb = new StringBuilder(plainText);

            for (int i = 0; i < sb.Length; i += 2)
            {

                if (i == sb.Length - 1)
                    sb.Append(sb.Length % 2 == 1 ? "x" : "");

                else if (sb[i] == sb[i + 1])
                    sb.Insert(i + 1, 'x');
            }
            plainText = sb.ToString();
            string[] split = new string[plainText.Length / 2 + (plainText.Length % 2 == 0 ? 0 : 1)];
            for (int i = 0; i < split.Length; i++)
            {
                split[i] = plainText.Substring(i * 2, i * 2 + 2 > plainText.Length ? 1 : 2);
            }
            ///////////////////////////////////////////////////////////////////////////////////////
            //////////////////////////////////////////////////////////////////////////////////////
            string ciphertext = "";
            for (int k = 0; k < split.Length; k++)
            {
                string d = "";
                for (int i = 0; i < 5; i++)
                {
                    for (int j = 0; j < 5; j++)
                    {
                        if (pf[i, j] == split[k][0].ToString() || (pf[i, j].Length == 3 && pf[i, j][0].ToString() == split[k][0].ToString()) || (pf[i, j].Length == 3 && pf[i, j][2].ToString() == split[k][0].ToString()))
                        {
                            d += i.ToString() + j.ToString();
                        }
                    }
                }
                for (int i = 0; i < 5; i++)
                {
                    for (int j = 0; j < 5; j++)
                    {
                        if (pf[i, j] == split[k][1].ToString() || (pf[i, j].Length == 3 && pf[i, j][0].ToString() == split[k][1].ToString()) || (pf[i, j].Length == 3 && pf[i, j][2].ToString() == split[k][1].ToString()))
                        {
                            d += i.ToString() + j.ToString();
                        }
                    }
                }
                int x1 = Int32.Parse(d[0].ToString());
                int x2 = Int32.Parse(d[2].ToString());
                int y1 = Int32.Parse(d[1].ToString());
                int y2 = Int32.Parse(d[3].ToString());
                ///////////////////////////////////////
                if (y1 == y2)
                {
                    if (x1 == 4) { x1 = 0; x2++; }
                    else if (x2 == 4) { x2 = 0; x1++; }
                    else { x1++; x2++; }
                }
                else if (x1 == x2)
                {
                    if (y1 == 4) { y1 = 0; y2++; }
                    else if (y2 == 4) { y2 = 0; y1++; }
                    else { y1++; y2++; }
                }
                else
                {
                    int t = y1;
                    y1 = y2;
                    y2 = t;
                }
                if (pf[x1, y1] == "i/j")
                {
                    if (pf[x1, y1][0] == 'i')
                    {
                        ciphertext += pf[x1, y1][0].ToString() + pf[x2, y2];
                    }
                    else if (pf[x1, y1][2] == 'j')
                    {
                        ciphertext += pf[x1, y1][2].ToString() + pf[x2, y2];
                    }
                }
                else if (pf[x2, y2] == "i/j")
                {
                    if (pf[x2, y2][0] == 'i')
                    {
                        ciphertext += pf[x1, y1] + pf[x2, y2][0].ToString();
                    }
                    else if (pf[x2, y2][2] == 'j')
                    {
                        ciphertext += pf[x1, y1] + pf[x2, y2][2].ToString();
                    }
                }
                else
                {
                    ciphertext += pf[x1, y1] + pf[x2, y2];
                }
            }
            return ciphertext.ToUpper();
        }
    }
}
