using System;

namespace Cryptanalysis {
    class Program {
        static void Main(string[] args) {
            var cp = new Experiments.CipherRunner();
            cp.SetInputs("0001001000110100");
            cp.Run(17);
            cp.Print();
            
            
        }
    }
}
