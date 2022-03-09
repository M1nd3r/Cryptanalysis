using System;

namespace Cryptanalysis {
    class Program {
        static void Main(string[] args) {
            Console.WriteLine(Convert.ToByte('1'.ToString()));
            var cp = new Experiments.CipherRunner();
            cp.SetInputs("0000000000000000");
            cp.Run(20);
            cp.Print();
        }
    }
}
