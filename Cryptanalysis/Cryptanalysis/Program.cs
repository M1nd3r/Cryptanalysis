using Cryptanalysis.Experiments;

namespace Cryptanalysis {

    internal class Program {

        private static void Main(string[] args) {
            Attack
                a = new AttackOnCipherFour(),
                b = new TruncatedDifferentialsAttack(),
                c = new CorrelationAttackOnLFSR(),
                d = new FastCorrelationAttackOnLFSR(),
                e = new AttackOnFinalCipher(),
                f = new AttackOnFinalCiphertextExample();

            a.BreakCipherRepeatedlyAndPrintSuccessRate(10);
            b.BreakCipherRepeatedlyAndPrintSuccessRate(10);
            c.BreakCipher();
            //c.BreakCipherRepeatedlyAndPrintSuccessRate(10);
            d.BreakCipher();
            //d.BreakCipherRepeatedlyAndPrintSuccessRate(10);
            e.BreakCipher();
            f.BreakCipher();
        }
    }
}
