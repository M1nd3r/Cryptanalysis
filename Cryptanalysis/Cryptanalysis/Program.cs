using Cryptanalysis.Experiments;

namespace Cryptanalysis {

    internal class Program {

        private static void Main(string[] args) {
            Attack
                y = new AttackOnCipherD(),
                x = new AttackOnCipherA(),
                a = new AttackOnCipherFour(),
                b = new TruncatedDifferentialsAttack(),
                c = new CorrelationAttackOnLFSR(),
                d = new FastCorrelationAttackOnLFSR(),
                e = new AttackOnFinalCipher(),
                f = new AttackOnFinalCiphertextExample();

            //y.BreakCipher();
            y.BreakCipherRepeatedlyAndPrintSuccessRate(100);
            /*
            x.BreakCipher();
            a.BreakCipherRepeatedlyAndPrintSuccessRate(10);
            b.BreakCipherRepeatedlyAndPrintSuccessRate(10);
            c.BreakCipher();
            //c.BreakCipherRepeatedlyAndPrintSuccessRate(10);
            d.BreakCipher();
            //d.BreakCipherRepeatedlyAndPrintSuccessRate(10);
            e.BreakCipher();
            f.BreakCipher();
            */
        }
    }
}
