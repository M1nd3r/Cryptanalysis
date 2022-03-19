using Cryptanalysis.F.Core;
using static Cryptanalysis.Core.DefaultCiphers;
using static Cryptanalysis.Core.Utils;

namespace Cryptanalysis.F.Experiments {

    internal static partial class Attacks {

        public static void BreakCipherFour() {
            var consolePrint = new ConsolePrinter();
            var printerUsed = consolePrint;

            var cipherFour = GetCipherFour(printerUsed);

            var input = ConvertToByteArr("0001001000110100");
            var res = cipherFour.Encode(input);
            consolePrint.WriteLine(res);
            var ser = cipherFour.Decode(res);
            consolePrint.WriteLine(ser);
            consolePrint.WriteLine(input);
        }
    }
}
