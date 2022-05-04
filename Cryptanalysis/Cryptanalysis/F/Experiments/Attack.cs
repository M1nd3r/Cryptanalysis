using System;
using Cryptanalysis.F.Core;
using static Cryptanalysis.Core.Utils;

namespace Cryptanalysis.F.Experiments {
    abstract class Attack {
        protected Cipher cipher;
        protected IPrinter mainPrinter;
        protected IPrinter verbosePrinter;
        public abstract bool BreakCipher();
        public virtual SuccessRate BreakCipherRepeatedly(int repetitions) {
            if (repetitions < 1)
                throw new ArgumentException("Number of repetitions must be greater than 0.", nameof(repetitions));
            int succ = 0;
            for (int i = 0; i < repetitions; i++)
                IncrementSuccessWhenConditionIsMet(ref succ, BreakCipher());
            return new SuccessRate(succ, repetitions - succ);
        }
        public virtual void PrintCipherRepeatedlyAndPrintSuccessRate(int repetitions) {
            PrintSuccessRate(BreakCipherRepeatedly(repetitions));
        }
        private void PrintSuccessRate(SuccessRate sr) {
            int hyp = 15;
            mainPrinter.WriteLine(GetHyphens(hyp));
            mainPrinter.WriteLine("Total succ: " + sr.GetSuccessCount().ToString());
            mainPrinter.WriteLine("Total fail: " + sr.GetFailCount().ToString());
            mainPrinter.WriteLine("Success rate: " + sr.GetSuccessRatio().ToString("0.00"));
            mainPrinter.WriteLine(GetHyphens(hyp));
        }
        private void IncrementSuccessWhenConditionIsMet(ref int success, bool condition) {
            if (condition)
                success++;
        }
        protected virtual void PrintKeys() => PrintKeys(mainPrinter);
        protected void SetCipher(Cipher c) => this.cipher = c;
        protected void SetMainPrinter(IPrinter printer) => this.mainPrinter = printer;
        protected void SetVerbosePrinter(IPrinter printer) => this.verbosePrinter = printer;
        private void PrintKeys(IPrinter printer) {
            var keys = AttackUtils.GetKeys(cipher);
            for (int i = 0; i < keys.Count; i++) {
                printer.Write("key_" + i.ToString() + ": ");
                printer.WriteLine(keys[i]);
            }
        }
    }
}
