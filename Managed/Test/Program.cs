using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ENet.Test
{
    class Program
    {
        static void Main(string[] args)
        {
            Runtime.Initialize();
            try
            {



            }
            finally
            {
                Runtime.Shutdown();
            }
        }
    }
}
