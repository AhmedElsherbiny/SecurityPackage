using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SecurityLibrary.MatrixOperation;
namespace SecurityLibrary.AES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class AES : CryptographicTechnique
    {
        public override string Decrypt(string cipherText, string key)
        {
            AESHelpers r = new AESHelpers();
            //throw new NotImplementedException();
            byte[,] CipherTextMat = new byte[4, 4];
            byte[,] KeyMat = new byte[4, 4];
            byte[,] AddRoundKey10 = new byte[4, 4];
            byte[,] AddRoundKey = new byte[4, 4];
            byte[,] B = new byte[4, 4];
            string[,] SubBytes = new string[4, 4];
            string[,] shiftRows = new string[4, 4];
            string[,] MIX = new string[4, 4];
            byte[,] MixColumn = new byte[4, 4];
            int len1 = (cipherText.Length / 2 + (cipherText.Length % 2 == 0 ? 0 : 1));
            int len2 = (key.Length / 2 + (key.Length % 2 == 0 ? 0 : 1));
            List<string> KeyWithoutX = new List<string>();
            List<string> plainWithoutX = new List<string>();
            ///////////////////////////////////////////////////////////
            for (int i = 0; i < len1; i++)
            {
                string ch = cipherText.Substring(i * 2, i * 2 + 2 > cipherText.Length ? 1 : 2).ToLower();
                if (ch == "0x") continue;
                else
                {
                    plainWithoutX.Add(ch);
                }
            }
            for (int i = 0; i < len2; i++)
            {
                string ch = key.Substring(i * 2, i * 2 + 2 > key.Length ? 1 : 2).ToLower();
                if (ch == "0x") continue;
                else
                {
                    KeyWithoutX.Add(ch);
                }
            }
            //////////////////////////////////////////////
            int cn = 0;
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    CipherTextMat[j, i] = byte.Parse(plainWithoutX[cn], System.Globalization.NumberStyles.HexNumber);
                    cn++;
                }
            }
            byte[] key1 = new byte[KeyWithoutX.Count];
            for (int i = 0; i < KeyWithoutX.Count; i++)
            {
                key1[i] = byte.Parse(KeyWithoutX[i], System.Globalization.NumberStyles.HexNumber);
            }
            byte[,] KEXpansion = r.KeyExpansion(key1);
            //round10
            AddRoundKey = r.AddRound(10, CipherTextMat, KEXpansion);
            AddRoundKey10 = AddRoundKey;
            //round from 9 to 1
            for (int round = 9; round >= 1; round--)
            {
                SubBytes = r.invSubBytes(AddRoundKey10);
                shiftRows = r.invShiftRows(SubBytes);
                B = r.FromStringTObyte(shiftRows);
                AddRoundKey = r.AddRound(round, B, KEXpansion);
                MIX = r.FromByteToString(AddRoundKey);
                MixColumn = r.InvMixColumns(MIX);
                AddRoundKey10 = MixColumn;
            }
            SubBytes = r.invSubBytes(AddRoundKey10);
            shiftRows = r.invShiftRows(SubBytes);
            B = r.FromStringTObyte(shiftRows);
            AddRoundKey = r.AddRound(0, B, KEXpansion);
            string PlaintText = "";
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    PlaintText += AddRoundKey[j, i].ToString("x2");
                }
            }
            return ("0x" + PlaintText);
        }

        public override string Encrypt(string plainText, string key)
        {
            MatrixOP mp = new MatrixOP();
            string[,] S_Box = new string[,]
            {
                 {"63","7c","77","7b","f2","6b","6f","c5","30","01","67","2b","fe","d7","ab","76"},
                 {"ca","82","c9","7d","fa","59","47","f0","ad","d4","a2","af","9c","a4","72","c0"},
                 {"b7","fd","93","26","36","3f","f7","cc","34","a5","e5","f1","71","d8","31","15"},
                 {"04","c7","23","c3","18","96","05","9a","07","12","80","e2","eb","27","b2","75"},
                 {"09","83","2c","1a","1b","6e","5a","a0","52","3b","d6","b3","29","e3","2f","84"},
                 {"53","d1","00","ed","20","fc","b1","5b","6a","cb","be","39","4a","4c","58","cf"},
                 {"d0","ef","aa","fb","43","4d","33","85","45","f9","02","7f","50","3c","9f","a8"},
                 {"51","a3","40","8f","92","9d","38","f5","bc","b6","da","21","10","ff","f3","d2"},
                 {"cd","0c","13","ec","5f","97","44","17","c4","a7","7e","3d","64","5d","19","73"},
                 {"60","81","4f","dc","22","2a","90","88","46","ee","b8","14","de","5e","0b","db"},
                 {"e0","32","3a","0a","49","06","24","5c","c2","d3","ac","62","91","95","e4","79"},
                 {"e7","c8","37","6d","8d","d5","4e","a9","6c","56","f4","ea","65","7a","ae","08"},
                 {"ba","78","25","2e","1c","a6","b4","c6","e8","dd","74","1f","4b","bd","8b","8a"},
                 {"70","3e","b5","66","48","03","f6","0e","61","35","57","b9","86","c1","1d","9e"},
                 {"e1","f8","98","11","69","d9","8e","94","9b","1e","87","e9","ce","55","28","df"},
                 {"8c","a1","89","0d","bf","e6","42","68","41","99","2d","0f","b0","54","bb","16"}
            };
            string[] Bin = new string[] {"0000" , "0001" , "0010" ,"0011","0100","0101","0110","0111","1000","1001","1010"
                ,"1011","1100","1101","1110","1111" };
            string dec = "0123456789abcdef";
            string[,] Rcon = new string[,] {
                {"01","02","04","08","10","20","40","80","1b","36"},
                {"00","00","00","00","00","00","00","00","00","00"},
                {"00","00","00","00","00","00","00","00","00","00"},
                {"00","00","00","00","00","00","00","00","00","00"}
            };
            Dictionary<char, string> Cov = new Dictionary<char, string>();
            Dictionary<string, char> COVDec = new Dictionary<string, char>();
            Dictionary<char, int> subB = new Dictionary<char, int>();
            for (int i = 0; i < dec.Length; i++)
            {
                Cov[dec[i]] = Bin[i];
                COVDec[Bin[i]] = dec[i];
                subB[dec[i]] = i;
            }
            string[,] PLaintTextMat = new string[4, 4];
            string[,] KeyMat = new string[4, 4];
            string[,] AddRoundKey = new string[4, 4];
            string[,] SubBytes = new string[4, 4];
            string[,] W = new string[4, 4];
            string[,] Keycopy = new string[4, 4];
            string[,] str = new string[4, 4];
            int len1 = (plainText.Length / 2 + (plainText.Length % 2 == 0 ? 0 : 1));
            int len2 = (key.Length / 2 + (key.Length % 2 == 0 ? 0 : 1));
            List<string> KeyWithoutX = new List<string>();
            List<string> plainWithoutX = new List<string>();
            ///////////////////////////////////////////////////////////
            for (int i = 0; i < len1; i++)
            {
                string ch = plainText.Substring(i * 2, i * 2 + 2 > plainText.Length ? 1 : 2).ToLower();
                if (ch == "0x") continue;
                else
                {
                    plainWithoutX.Add(ch);
                }
            }
            for (int i = 0; i < len2; i++)
            {
                string ch = key.Substring(i * 2, i * 2 + 2 > key.Length ? 1 : 2).ToLower();
                if (ch == "0x") continue;
                else
                {
                    KeyWithoutX.Add(ch);
                }
            }
            //////////////////////////////////////////////
            int cn = 0;
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    PLaintTextMat[j, i] = plainWithoutX[cn];
                    KeyMat[j, i] = KeyWithoutX[cn];
                    cn++;
                }
            }
            /////////////////////Add Round Key/////////////////////////////
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    AddRoundKey[i, j] = COVDec[mp.XOR(Cov[PLaintTextMat[i, j][0]], Cov[KeyMat[i, j][0]])].ToString() +
                             COVDec[mp.XOR(Cov[PLaintTextMat[i, j][1]], Cov[KeyMat[i, j][1]])].ToString();
                }
            }
            ///////////////////////////////rounds///////////////////////////////////////
            for (int round = 0; round < 9; round++)
            {
                /////////////////////////////SubBytes////////////////////////////
                for (int i = 0; i < 4; i++)
                {
                    for (int j = 0; j < 4; j++)
                    {
                        SubBytes[i, j] = S_Box[subB[AddRoundKey[i, j][0]], subB[AddRoundKey[i, j][1]]];
                    }
                }
                /////////////////////////////////////shiftRows//////////////////////////////////////////
                for (int i = 1; i < 4; i++)
                {
                    int c = i;
                    while (c > 0)
                    {
                        string temp = SubBytes[i, 0];
                        for (int j = 1; j < 4; j++)
                        {
                            SubBytes[i, j - 1] = SubBytes[i, j];
                        }
                        SubBytes[i, 3] = temp;
                        c--;
                    }
                }
                /////////////////////////////MixColumn////////////////////////////////////
                int[,] decnum = new int[4, 4];
                for (int i = 0; i < 4; i++)
                {
                    for (int j = 0; j < 4; j++)
                    {
                        int de = int.Parse(SubBytes[i, j], System.Globalization.NumberStyles.HexNumber);
                        decnum[i, j] = de;
                    }
                }

                byte[,] B = new byte[4, 4];
                for (int i = 0; i < 4; i++)
                {
                    for (int j = 0; j < 4; j++)
                    {

                        B[i, j] = byte.Parse(decnum[i, j].ToString());
                    }
                }
                byte[,] BB = mp.MixColumns(B);
                for (int i = 0; i < 4; i++)
                {
                    for (int j = 0; j < 4; j++)
                    {
                        if (BB[i, j].ToString("X").ToLower().Length < 2)
                            str[i, j] = "0" + BB[i, j].ToString("X").ToLower();
                        else
                        {
                            str[i, j] = BB[i, j].ToString("X").ToLower();
                        }
                    }
                }
                ///////////////////////////////AddRoundKey/////////////////////////////////
                for (int i = 0; i < 4; i++)
                {
                    for (int j = 0; j < 4; j++)
                    {
                        Keycopy[i, j] = KeyMat[i, j];
                    }
                }
                string tem = KeyMat[0, KeyMat.GetLength(0) - 1];
                for (int i = 1; i < 4; i++)
                {
                    KeyMat[i - 1, KeyMat.GetLength(0) - 1] = KeyMat[i, KeyMat.GetLength(0) - 1];
                }
                KeyMat[KeyMat.GetLength(0) - 1, KeyMat.GetLength(0) - 1] = tem;
                for (int i = 0; i < Rcon.GetLength(0); i++)
                {
                    KeyMat[i, KeyMat.GetLength(0) - 1] = S_Box[subB[KeyMat[i, KeyMat.GetLength(0) - 1][0]], subB[KeyMat[i, KeyMat.GetLength(0) - 1][1]]];
                }
                for (int i = 0; i < 4; i++)
                {
                    string c1 = COVDec[mp.XOR(Cov[KeyMat[i, 0][0]], Cov[KeyMat[i, KeyMat.GetLength(0) - 1][0]])].ToString();
                    string c2 = COVDec[mp.XOR(Cov[KeyMat[i, 0][1]], Cov[KeyMat[i, KeyMat.GetLength(0) - 1][1]])].ToString();
                    W[i, 0] = COVDec[mp.XOR(Cov[c1[0]], Cov[Rcon[i, round][0]])].ToString() + COVDec[mp.XOR(Cov[c2[0]], Cov[Rcon[i, round][1]])].ToString();
                }
                for (int i = 1; i < 4; i++)
                {
                    for (int j = 0; j < 4; j++)
                    {
                        string ch1 = COVDec[mp.XOR(Cov[Keycopy[j, i][0]], Cov[W[j, i - 1][0]])].ToString();
                        string ch2 = COVDec[mp.XOR(Cov[Keycopy[j, i][1]], Cov[W[j, i - 1][1]])].ToString();
                        W[j, i] = ch1 + ch2;
                    }
                }
                for (int i = 0; i < 4; i++)
                {
                    for (int j = 0; j < 4; j++)
                    {
                        KeyMat[i, j] = W[i, j];
                    }
                }
                for (int i = 0; i < 4; i++)
                {
                    for (int j = 0; j < 4; j++)
                    {
                        string cs1 = COVDec[mp.XOR(Cov[str[j, i][0]], Cov[KeyMat[j, i][0]])].ToString();
                        string cs2 = COVDec[mp.XOR(Cov[str[j, i][1]], Cov[KeyMat[j, i][1]])].ToString();
                        AddRoundKey[j, i] = cs1 + cs2;
                    }
                }
            }
            /////////////////////////////SubBytes////////////////////////////
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    SubBytes[i, j] = S_Box[subB[AddRoundKey[i, j][0]], subB[AddRoundKey[i, j][1]]];
                }
            }
            /////////////////////////////////////shiftRows//////////////////////////////////////////
            for (int i = 1; i < 4; i++)
            {
                int c = i;
                while (c > 0)
                {
                    string temp = SubBytes[i, 0];
                    for (int j = 1; j < 4; j++)
                    {
                        SubBytes[i, j - 1] = SubBytes[i, j];
                    }
                    SubBytes[i, 3] = temp;
                    c--;
                }
            }

            ///////////////////////////////////////////////////////////////
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    Keycopy[i, j] = KeyMat[i, j];
                }
            }
            string te = KeyMat[0, KeyMat.GetLength(0) - 1];
            for (int i = 1; i < 4; i++)
            {
                KeyMat[i - 1, KeyMat.GetLength(0) - 1] = KeyMat[i, KeyMat.GetLength(0) - 1];
            }
            KeyMat[KeyMat.GetLength(0) - 1, KeyMat.GetLength(0) - 1] = te;
            for (int i = 0; i < Rcon.GetLength(0); i++)
            {
                KeyMat[i, KeyMat.GetLength(0) - 1] = S_Box[subB[KeyMat[i, KeyMat.GetLength(0) - 1][0]], subB[KeyMat[i, KeyMat.GetLength(0) - 1][1]]];
            }
            for (int i = 0; i < 4; i++)
            {
                string c1 = COVDec[mp.XOR(Cov[KeyMat[i, 0][0]], Cov[KeyMat[i, KeyMat.GetLength(0) - 1][0]])].ToString();
                string c2 = COVDec[mp.XOR(Cov[KeyMat[i, 0][1]], Cov[KeyMat[i, KeyMat.GetLength(0) - 1][1]])].ToString();
                W[i, 0] = COVDec[mp.XOR(Cov[c1[0]], Cov[Rcon[i, 9][0]])].ToString() + COVDec[mp.XOR(Cov[c2[0]], Cov[Rcon[i, 9][1]])].ToString();
            }
            for (int i = 1; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    string ch1 = COVDec[mp.XOR(Cov[Keycopy[j, i][0]], Cov[W[j, i - 1][0]])].ToString();
                    string ch2 = COVDec[mp.XOR(Cov[Keycopy[j, i][1]], Cov[W[j, i - 1][1]])].ToString();
                    W[j, i] = ch1 + ch2;
                }
            }
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    KeyMat[i, j] = W[i, j];
                }
            }
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    string cs1 = COVDec[mp.XOR(Cov[SubBytes[j, i][0]], Cov[KeyMat[j, i][0]])].ToString();
                    string cs2 = COVDec[mp.XOR(Cov[SubBytes[j, i][1]], Cov[KeyMat[j, i][1]])].ToString();
                    AddRoundKey[j, i] = cs1 + cs2;
                }
            }
            string CipherText = "";
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    CipherText += AddRoundKey[j, i];
                }
            }
            return ("0x" + CipherText.ToUpper());
        }
    }
}
