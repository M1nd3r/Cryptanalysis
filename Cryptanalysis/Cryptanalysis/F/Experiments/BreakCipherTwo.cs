using Cryptanalysis.F.Core;
using static Cryptanalysis.Core.DefaultCiphers;
using static Cryptanalysis.Core.Utils;

namespace Cryptanalysis.F.Experiments {

    internal static partial class Attacks {

        public static void BreakCipherTwo() {
            var mainPrinter = new ConsolePrinter();
            var verbosePrinter = new ConsolePrinter();
            var cipherTwo = GetCipherTwo(verbosePrinter);
            var res = cipherTwo.Encode(ConvertToByteArr("0001"));
            var ser = cipherTwo.Decode(res);
        }
    }
}
