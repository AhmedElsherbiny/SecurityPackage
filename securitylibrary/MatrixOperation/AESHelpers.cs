using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.MatrixOperation
{
    class AESHelpers
    {
        byte[,] Sbox = new byte[,]
            {
                 {0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76},
                 {0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0},
                 {0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15},
                 {0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75},
                 {0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84},
                 {0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf},
                 {0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8},
                 {0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2},
                 {0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73},
                 {0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb},
                 {0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79},
                 {0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08},
                 {0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a},
                 {0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e},
                 {0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf},
                 {0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16}
            };
        string[,] InverS_Box = new string[,]
            {
                 {"52","09","6a","d5","30","36","a5","38","bf","40","a3","9e","81","f3","d7","fb"},
                 {"7c","e3","39","82","9b","2f","ff","87","34","8e","43","44","c4","de","e9","cb"},
                 {"54","7b","94","32","a6","c2","23","3d","ee","4c","95","0b","42","fa","c3","4e"},
                 {"08","2e","a1","66","28","d9","24","b2","76","5b","a2","49","6d","8b","d1","25"},
                 {"72","f8","f6","64","86","68","98","16","d4","a4","5c","cc","5d","65","b6","92"},
                 {"6c","70","48","50","fd","ed","b9","da","5e","15","46","57","a7","8d","9d","84"},
                 {"90","d8","ab","00","8c","bc","d3","0a","f7","e4","58","05","b8","b3","45","06"},
                 {"d0","2c","1e","8f","ca","3f","0f","02","c1","af","bd","03","01","13","8a","6b"},
                 {"3a","91","11","41","4f","67","dc","ea","97","f2","cf","ce","f0","b4","e6","73"},
                 {"96","ac","74","22","e7","ad","35","85","e2","f9","37","e8","1c","75","df","6e"},
                 {"47","f1","1a","71","1d","29","c5","89","6f","b7","62","0e","aa","18","be","1b"},
                 {"fc","56","3e","4b","c6","d2","79","20","9a","db","c0","fe","78","cd","5a","f4"},
                 {"1f","dd","a8","33","88","07","c7","31","b1","12","10","59","27","80","ec","5f"},
                 {"60","51","7f","a9","19","b5","4a","0d","2d","e5","7a","9f","93","c9","9c","ef"},
                 {"a0","e0","3b","4d","ae","2a","f5","b0","c8","eb","bb","3c","83","53","99","61"},
                 {"17","2b","04","7e","ba","77","d6","26","e1","69","14","63","55","21","0c","7d"}
            };
        string dec = "0123456789abcdef";
        Dictionary<char, string> Cov = new Dictionary<char, string>();
        Dictionary<string, char> COVDec = new Dictionary<string, char>();
        Dictionary<char, int> subB = new Dictionary<char, int>();
        byte[,] Rcon = new byte[11, 4] {
                                   {0x00, 0x00, 0x00, 0x00}, 
                                   {0x01, 0x00, 0x00, 0x00},
                                   {0x02, 0x00, 0x00, 0x00},
                                   {0x04, 0x00, 0x00, 0x00},
                                   {0x08, 0x00, 0x00, 0x00},
                                   {0x10, 0x00, 0x00, 0x00},
                                   {0x20, 0x00, 0x00, 0x00},
                                   {0x40, 0x00, 0x00, 0x00},
                                   {0x80, 0x00, 0x00, 0x00},
                                   {0x1b, 0x00, 0x00, 0x00},
                                   {0x36, 0x00, 0x00, 0x00}};
        static Byte GMul(Byte a, Byte b)
        { // Galois Field (256) Multiplication of two Bytes
            Byte p = 0;
            Byte counter;
            Byte hi_bit_set;
            for (counter = 0; counter < 8; counter++)
            {
                if ((b & 1) != 0)
                {
                    p ^= a;
                }
                hi_bit_set = (Byte)(a & 0x80);
                a <<= 1;
                if (hi_bit_set != 0)
                {
                    a ^= 0x1b; /* x^8 + x^4 + x^3 + x + 1 */
                }
                b >>= 1;
            }
            return p;
        }

        static byte[,] InverseMixColumns(byte[,] s)
        { // 's' is the main State matrix, 'ss' is a temp matrix of the same dimensions as 's'.
            Byte[,] ss = new Byte[4, 4];
            for (int c = 0; c < 4; c++)
            {
                ss[0, c] = (Byte)(GMul(0x0e, s[0, c]) ^ GMul(0x0b, s[1, c]) ^ GMul(0x0d, s[2, c]) ^ GMul(0x09, s[3, c]));
                ss[1, c] = (Byte)(GMul(0x09, s[0, c]) ^ GMul(0x0e, s[1, c]) ^ GMul(0x0b, s[2, c]) ^ GMul(0x0d, s[3, c]));
                ss[2, c] = (Byte)(GMul(0x0d, s[0, c]) ^ GMul(0x09, s[1, c]) ^ GMul(0x0e, s[2, c]) ^ GMul(0x0b, s[3, c]));
                ss[3, c] = (Byte)(GMul(0x0b, s[0, c]) ^ GMul(0x0d, s[1, c]) ^ GMul(0x09, s[2, c]) ^ GMul(0x0e, s[3, c]));
            }

            //ss.CopyTo(s, 0);
            return ss;
        }
        public byte[,] KeyExpansion(byte[] key)
        {

            int Nb = 4;
            int Nr = 10;
            byte[,] w = new byte[Nb * (Nr + 1), 4];  // 4 columns of bytes corresponds to a word

            for (int row = 0; row < 4; ++row)
            {
                w[row, 0] = key[4 * row];
                w[row, 1] = key[4 * row + 1];
                w[row, 2] = key[4 * row + 2];
                w[row, 3] = key[4 * row + 3];
            }

            byte[] temp = new byte[4];

            for (int row = 4; row < Nb * (Nr + 1); ++row)
            {
                temp[0] = w[row - 1, 0]; temp[1] = w[row - 1, 1];
                temp[2] = w[row - 1, 2]; temp[3] = w[row - 1, 3];

                if (row % 4 == 0)
                {
                    temp = SubWord(RotWord(temp));

                    temp[0] = (byte)((int)temp[0] ^ (int)Rcon[row / 4, 0]);
                    temp[1] = (byte)((int)temp[1] ^ (int)Rcon[row / 4, 1]);
                    temp[2] = (byte)((int)temp[2] ^ (int)Rcon[row / 4, 2]);
                    temp[3] = (byte)((int)temp[3] ^ (int)Rcon[row / 4, 3]);
                }

                w[row, 0] = (byte)((int)w[row - 4, 0] ^ (int)temp[0]);
                w[row, 1] = (byte)((int)w[row - 4, 1] ^ (int)temp[1]);
                w[row, 2] = (byte)((int)w[row - 4, 2] ^ (int)temp[2]);
                w[row, 3] = (byte)((int)w[row - 4, 3] ^ (int)temp[3]);

            }  // for loop
            return w;
        }  // KeyExpansion()

        private byte[] SubWord(byte[] word)
        {
            byte[] result = new byte[4];
            result[0] = Sbox[word[0] >> 4, word[0] & 0x0f];
            result[1] = Sbox[word[1] >> 4, word[1] & 0x0f];
            result[2] = Sbox[word[2] >> 4, word[2] & 0x0f];
            result[3] = Sbox[word[3] >> 4, word[3] & 0x0f];
            return result;
        }

        private byte[] RotWord(byte[] word)
        {
            byte[] result = new byte[4];
            result[0] = word[1];
            result[1] = word[2];
            result[2] = word[3];
            result[3] = word[0];
            return result;
        }
        public string[,] invSubBytes(byte[,] AddRoundKey)
        {
            string[,] SubBytes = new string[4, 4];
            for (int i = 0; i < dec.Length; i++)
            {
                subB[dec[i]] = i;
            }
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    SubBytes[i, j] = InverS_Box[subB[AddRoundKey[i, j].ToString("x2")[0]], subB[AddRoundKey[i, j].ToString("x2")[1]]];
                }
            }
            return SubBytes;
        }
        public string[,] invShiftRows(string[,] SubBytes)
        {
            for (int i = 1; i < 4; i++)
            {
                int c = i;
                while (c > 0)
                {
                    string temp = SubBytes[i, 3];
                    for (int j = 3; j > 0; j--)
                    {
                        SubBytes[i, j] = SubBytes[i, j - 1];
                    }
                    SubBytes[i, 0] = temp;
                    c--;
                }
            }
            return SubBytes;
        }
        public byte[,] InvMixColumns(string[,] shift)
        {
            string[,] str = new string[4, 4];
            int[,] decnum = new int[4, 4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    int de = int.Parse(shift[i, j], System.Globalization.NumberStyles.HexNumber);
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
            byte[,] BB = InverseMixColumns(B);
            return BB;
        }
        public byte[,] AddRound(int round, byte[,] CipherTextMat, byte[,] KEXpansion)
        {
            byte[,] AddRoundKey = new byte[4, 4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    AddRoundKey[i, j] = (byte)((int)CipherTextMat[i, j] ^ (int)KEXpansion[((round * 4) + j), i]);
                }
            }
            return AddRoundKey;
        }
        public byte[,] FromStringTObyte(string[,] Byte)
        {
            byte[,] B = new byte[4, 4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {

                    B[i, j] = byte.Parse(Byte[i, j], System.Globalization.NumberStyles.HexNumber); ;
                }
            }
            return B;
        }
        public string[,] FromByteToString(byte[,] BB)
        {
            string[,] str = new string[4, 4];
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
            return str;
        }
    }
}
