using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using SecurityLibrary;
using SecurityLibrary.RSA;
using SecurityLibrary.AES;
using SecurityLibrary.MD5;
namespace UISecurity
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }

        private void button1_Click(object sender, EventArgs e)
        {
            if (comboBox1.Text.Contains("Ceaser"))
            {
                Ceaser c = new Ceaser();
                string Res = c.Encrypt(textBox1.Text.ToString(), int.Parse(textBox3.Text.ToString()));
                textBox4.Text = Res;
            }
            else if (comboBox1.Text.Contains("Monoalphabetic"))
            {
                Monoalphabetic c = new Monoalphabetic();
                string Res = c.Encrypt(textBox1.Text.ToString(), textBox3.Text.ToString());
                textBox4.Text = Res;
            }
            else if (comboBox1.Text.Contains("Columnar"))
            {
                Columnar c = new Columnar();
                List<int> key = new List<int>();
                for (int i = 0; i < textBox3.Text.Length; i++)
                {
                    key.Add(int.Parse(textBox3.Text[i].ToString()));
                }
                string Res = c.Encrypt(textBox1.Text.ToString(), key);
                textBox4.Text = Res;
            }
            else if (comboBox1.Text.Contains("HillCipher"))
            {
                HillCipher c = new HillCipher();
                List<int> key1 = new List<int>();
                List<int> Plaintext1 = new List<int>();
                string Res = "";
                List<int> ResDig = new List<int>();
                if (char.IsDigit(textBox3.Text[0]) && char.IsDigit(textBox1.Text[0]))
                {
                    for (int i = 0; i < textBox1.Text.Length; i++)
                    {
                        Plaintext1.Add(int.Parse(textBox1.Text[i].ToString()));
                    }
                    for (int i = 0; i < textBox3.Text.Length; i++)
                    {
                        key1.Add(int.Parse(textBox3.Text[i].ToString()));
                    }
                    ResDig = c.Encrypt(Plaintext1, key1);
                    textBox4.Text = ResDig.ToString();
                }
                else
                {
                    Res = c.Encrypt(textBox1.Text.ToString(), textBox3.Text.ToString());
                    textBox4.Text = Res;
                }
                
            }
            else if (comboBox1.Text.Contains("PlayFair"))
            {
                PlayFair c = new PlayFair();
                string Res = c.Encrypt(textBox1.Text.ToString(), textBox3.Text.ToString());
                textBox4.Text = Res;
            }
            else if (comboBox1.Text.Contains("RailFence"))
            {
                RailFence c = new RailFence();
                string Res = c.Encrypt(textBox1.Text.ToString(),int.Parse(textBox3.Text.ToString()));
                textBox4.Text = Res;
            }
            else if (comboBox1.Text.Contains("RepeatingKeyVigenere"))
            {
                RepeatingkeyVigenere c = new RepeatingkeyVigenere();
                string Res = c.Encrypt(textBox1.Text.ToString(), textBox3.Text.ToString());
                textBox4.Text = Res;
            }
            else if (comboBox1.Text.Contains("AutokeyVigenere"))
            {
                AutokeyVigenere c = new AutokeyVigenere();
                string Res = c.Encrypt(textBox1.Text.ToString(), textBox3.Text.ToString());
                textBox4.Text = Res;
            }
            else if (comboBox1.Text.Contains("RSA"))
            {
                RSA c = new RSA();
                string s = textBox1.Text.ToString();
                string[] str = s.Split(' ');
                int p = int.Parse(str[0]);
                int q = int.Parse(str[1]);
                int M = int.Parse(str[2]);
                int ee = int.Parse(str[3]);
                int Res = c.Encrypt(p, q, M, ee);
                textBox4.Text = Res.ToString();
            }
            else if (comboBox1.Text.Contains("AES"))
            {
                AES c = new AES();
                string Res = c.Encrypt(textBox1.Text.ToString(), textBox3.Text.ToString());
                textBox4.Text = Res;
            }
            else if (comboBox1.Text.Contains("MD5"))
            {
                MD5 c = new MD5();
                string Res = c.GetHash(textBox1.Text.ToString());
                textBox4.Text = Res;
            }
        }

        private void button3_Click(object sender, EventArgs e)
        {
            if (comboBox1.Text.Contains("Ceaser"))
            {
                Ceaser c = new Ceaser();
                string Res = c.Decrypt(textBox2.Text.ToString(), int.Parse(textBox3.Text.ToString()));
                textBox4.Text = Res;
            }
            else if (comboBox1.Text.Contains("Monoalphabetic"))
            {
                Monoalphabetic c = new Monoalphabetic();
                string Res = c.Decrypt(textBox2.Text.ToString(), textBox3.Text.ToString());
                textBox4.Text = Res;
            }
            else if (comboBox1.Text.Contains("Columnar"))
            {
                Columnar c = new Columnar();
                List<int> key = new List<int>();
                for (int i = 0; i < textBox3.Text.Length; i++)
                {
                    key.Add(int.Parse(textBox3.Text[i].ToString()));
                }
                string Res = c.Decrypt(textBox2.Text.ToString(), key);
                textBox4.Text = Res;
            }
            else if (comboBox1.Text.Contains("HillCipher"))
            {
                HillCipher c = new HillCipher();
                List<int> key1 = new List<int>();
                List<int> Plaintext1 = new List<int>();
                string Res = "";
                List<int> ResDig = new List<int>();
                if (char.IsDigit(textBox3.Text[0]) && char.IsDigit(textBox1.Text[0]))
                {
                    for (int i = 0; i < textBox2.Text.Length; i++)
                    {
                        Plaintext1.Add(int.Parse(textBox2.Text[i].ToString()));
                    }
                    for (int i = 0; i < textBox3.Text.Length; i++)
                    {
                        key1.Add(int.Parse(textBox3.Text[i].ToString()));
                    }
                    ResDig = c.Decrypt(Plaintext1, key1);
                    textBox4.Text = ResDig.ToString();
                }
                else
                {
                    Res = c.Decrypt(textBox2.Text.ToString(), textBox3.Text.ToString());
                    textBox4.Text = Res;
                }

            }
            else if (comboBox1.Text.Contains("PlayFair"))
            {
                PlayFair c = new PlayFair();
                string Res = c.Decrypt(textBox2.Text.ToString(), textBox3.Text.ToString());
                textBox4.Text = Res;
            }
            else if (comboBox1.Text.Contains("RailFence"))
            {
                RailFence c = new RailFence();
                string Res = c.Decrypt(textBox2.Text.ToString(), int.Parse(textBox3.Text.ToString()));
                textBox4.Text = Res;
            }
            else if (comboBox1.Text.Contains("RepeatingKeyVigenere"))
            {
                RepeatingkeyVigenere c = new RepeatingkeyVigenere();
                string Res = c.Decrypt(textBox2.Text.ToString(), textBox3.Text.ToString());
                textBox4.Text = Res;
            }
            else if (comboBox1.Text.Contains("AutokeyVigenere"))
            {
                AutokeyVigenere c = new AutokeyVigenere();
                string Res = c.Decrypt(textBox2.Text.ToString(), textBox3.Text.ToString());
                textBox4.Text = Res;
            }
            else if (comboBox1.Text.Contains("RSA"))
            {
                RSA c = new RSA();
                string s = textBox1.Text.ToString();
                string[] str = s.Split(' ');
                int p = int.Parse(str[0]);
                int q = int.Parse(str[1]);
                int M = int.Parse(str[2]);
                int ee = int.Parse(str[3]);
                int Res = c.Decrypt(p, q, M, ee);
                textBox4.Text = Res.ToString();
            }
            else if (comboBox1.Text.Contains("AES"))
            {
                AES c = new AES();
                string Res = c.Decrypt(textBox2.Text.ToString(), textBox3.Text.ToString());
                textBox4.Text = Res;
            }
        }

        private void button2_Click(object sender, EventArgs e)
        {
            if (comboBox1.Text.Contains("Ceaser"))
            {
                Ceaser c = new Ceaser();
                int Res = c.Analyse(textBox1.Text.ToString(), textBox2.Text.ToString());
                textBox4.Text = Res.ToString();
            }
            else if (comboBox1.Text.Contains("Monoalphabetic"))
            {
                Monoalphabetic c = new Monoalphabetic();
                string Res = c.Analyse(textBox1.Text.ToString(), textBox2.Text.ToString());
                textBox4.Text = Res;
            }
            else if (comboBox1.Text.Contains("Columnar"))
            {
                Columnar c = new Columnar();
                List<int> key = new List<int>();
                for (int i = 0; i < textBox3.Text.Length; i++)
                {
                    key.Add(int.Parse(textBox3.Text[i].ToString()));
                }
                List<int> Res = c.Analyse(textBox1.Text.ToString(), textBox2.Text.ToString());
                textBox4.Text = Res.ToString();
            }
            else if (comboBox1.Text.Contains("HillCipher"))
            {
                HillCipher c = new HillCipher();
                List<int> key1 = new List<int>();
                List<int> Plaintext1 = new List<int>();
                string Res = "";
                List<int> ResDig = new List<int>();
                if (textBox5.Text == "2")
                {
                    if (char.IsDigit(textBox1.Text[0]) && char.IsDigit(textBox2.Text[0]))
                    {
                        for (int i = 0; i < textBox1.Text.Length; i++)
                        {
                            Plaintext1.Add(int.Parse(textBox1.Text[i].ToString()));
                        }
                        for (int i = 0; i < textBox2.Text.Length; i++)
                        {
                            key1.Add(int.Parse(textBox2.Text[i].ToString()));
                        }
                        ResDig = c.Analyse(Plaintext1, key1);
                        textBox4.Text = ResDig.ToString();
                    }
                    else
                    {
                        Res = c.Analyse(textBox1.Text.ToString(), textBox2.Text.ToString());
                        textBox4.Text = Res;
                    }
                }
                else if (textBox5.Text == "3")
                {
                    if (char.IsDigit(textBox1.Text[0]) && char.IsDigit(textBox2.Text[0]))
                    {
                        for (int i = 0; i < textBox1.Text.Length; i++)
                        {
                            Plaintext1.Add(int.Parse(textBox1.Text[i].ToString()));
                        }
                        for (int i = 0; i < textBox2.Text.Length; i++)
                        {
                            key1.Add(int.Parse(textBox2.Text[i].ToString()));
                        }
                        ResDig = c.Analyse3By3Key(Plaintext1, key1);
                        textBox4.Text = ResDig.ToString();
                    }
                    else
                    {
                        Res = c.Analyse3By3Key(textBox1.Text.ToString(), textBox2.Text.ToString());
                        textBox4.Text = Res;
                    }
                }

            }
            else if (comboBox1.Text.Contains("RailFence"))
            {
                RailFence c = new RailFence();
                int Res = c.Analyse(textBox1.Text.ToString(), textBox2.Text.ToString());
                textBox4.Text = Res.ToString();
            }
            else if (comboBox1.Text.Contains("RepeatingKeyVigenere"))
            {
                RepeatingkeyVigenere c = new RepeatingkeyVigenere();
                string Res = c.Analyse(textBox1.Text.ToString(), textBox2.Text.ToString());
                textBox4.Text = Res;
            }
            else if (comboBox1.Text.Contains("AutokeyVigenere"))
            {
                AutokeyVigenere c = new AutokeyVigenere();
                string Res = c.Analyse(textBox1.Text.ToString(), textBox2.Text.ToString());
                textBox4.Text = Res;
            }
        }
        }
    }
