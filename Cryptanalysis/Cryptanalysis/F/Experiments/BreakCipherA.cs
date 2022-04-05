using Cryptanalysis.F.Core;
using static Cryptanalysis.Core.DefaultCiphers;
using static Cryptanalysis.Core.Utils;

namespace Cryptanalysis.F.Experiments {

    internal static partial class Attacks {

        public static void BreakCipherA() {
            var mainPrinter = new ConsolePrinter();
            var verbosePrinter = new ConsolePrinter();
            var cipherA = GetCipherA(verbosePrinter);
            PrintKeys(cipherA, mainPrinter);
        }
    }
}
