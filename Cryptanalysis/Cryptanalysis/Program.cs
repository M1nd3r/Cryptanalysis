using Cryptanalysis.Experiments;

namespace Cryptanalysis {

    internal class Program {

        private static void Main(string[] args) {
            Attack a = new AttackOnCipherFour();
            a.PrintCipherRepeatedlyAndPrintSuccessRate(100);
        }
    }
}
