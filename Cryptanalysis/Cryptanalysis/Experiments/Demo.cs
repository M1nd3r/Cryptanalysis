using System;

namespace Cryptanalysis.Experiments {

    internal class Demo {

        internal static void Show() {
            Console.WriteLine("This simple demo shows the output of some of the experiments. The experiments included in this demo are the following:" +
                "\n -> AttackOnCipherD.BreakCipherRepeatedlyAndPrintSuccessRate(100)" +
                "\n -> AttackOnCipherA.BreakCipher()" +
                "\n -> AttackOnCipherFour.BreakCipherRepeatedlyAndPrintSuccessRate(10)" +
                "\n -> TruncatedDifferentialsAttack.BreakCipherRepeatedlyAndPrintSuccessRate(10)" +
                "\n -> CorrelationAttackOnLFSR.BreakCipher()" +
                "\n -> FastCorrelationAttackOnLFSR.BreakCipher()" +
                "\n -> AttackOnFinalCipher.BreakCipher()" +
                "\n -> AttackOnFinalCipherCiphertextExample.BreakCipher()" +
                "\n \n After an attack is finished, you can proceed to the next one by pressing <Enter>."
            );

            Action[] attacks = {
                () => new AttackOnCipherD().BreakCipherRepeatedlyAndPrintSuccessRate(100),
                () => new AttackOnCipherA().BreakCipher(),
                () => new AttackOnCipherFour().BreakCipherRepeatedlyAndPrintSuccessRate(10),
                () => new TruncatedDifferentialsAttack().BreakCipherRepeatedlyAndPrintSuccessRate(10),
                () => new CorrelationAttackOnLFSR().BreakCipher(),
                () => new FastCorrelationAttackOnLFSR().BreakCipher(),
                () => new AttackOnFinalCipher().BreakCipher(),
                () => new AttackOnFinalCipherCiphertextExample().BreakCipher()
            };

            foreach (var attack in attacks) {
                ProceedToNextAttack();
                attack();
            }
        }

        private static void ProceedToNextAttack() {
            while (Console.KeyAvailable)
                Console.ReadKey(false);
            Console.WriteLine("\n>>> To proceed to the next attack, press <Enter>. <<<");
            ConsoleKeyInfo ck = Console.ReadKey(true);
            while (ck.Key != ConsoleKey.Enter)
                ck = Console.ReadKey(true);
            Console.WriteLine();
        }
    }
}
