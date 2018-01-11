using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SecurityLibrary.MatrixOperation;
namespace SecurityLibrary.MD5
{
    public class MD5
    {
        public string GetHash(string text)
        {
            //throw new NotImplementedException();
            MatrixOP m = new MatrixOP();
            return m.tohexString(m.ComputeMD5(Encoding.ASCII.GetBytes(text)));
        }
    }
}
