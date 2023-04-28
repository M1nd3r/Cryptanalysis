using System.Collections.Generic;
using Cryptanalysis.Core;
using static Cryptanalysis.Core.DefaultCiphers;
using static Cryptanalysis.Core.Utils;

namespace Cryptanalysis.Experiments {

    internal class AttackOnCipherD : Attack {

        private IList<byte[]>
            plaintexts,
            ciphertexts;

        public override bool BreakCipher() {
            SetMainPrinter(new ConsolePrinter());
            SetVerbosePrinter(new DummyPrinter());
            SetCipher(GetCipherD(verbosePrinter));

            PrintKeys();

            int numberOfPlaintexts = 10000;
            GeneratePlaintexts(numberOfPlaintexts);
            GenerateCiphertexts();

            PrintXorOfFirstPositionOnAllKeys(mainPrinter);

            var r = CountXorsInTexts();
            var testXor = XorAllKeys();

            mainPrinter.WriteLine("Guessed value based on mask 8000:  " + GetResultBasedOnR(r).ToString());
            mainPrinter.WriteLine("Absolute value based on mask 8000: " + r.ToString());

            return HandleResult(GetResultBasedOnR(r) == testXor[0]);
        }

        private int CountXorsInTexts() {
            int r = 0;
            for (int i = 0; i < plaintexts.Count; i++) {
                if (Xor(plaintexts[i][0], ciphertexts[i][0]) == 0)
                    r++;
            }
            return r;
        }

        private void GenerateCiphertexts() {
            ciphertexts = new List<byte[]>();
            foreach (var p in plaintexts)
                ciphertexts.Add(cipher.Encode(p));
        }

        private void GeneratePlaintexts(int numberOfPlatintexts) {
            plaintexts = new List<byte[]>();
            for (int i = 0; i < numberOfPlatintexts; i++)
                plaintexts.Add(GetRndInput(16));
        }

        private byte GetResultBasedOnR(int r) {
            if (r < plaintexts.Count / 2)
                return 0;
            return 1;
        }

        private void HandleFail() {
            mainPrinter.WriteLine("Failed! Incorrect guess.");
            mainPrinter.WriteLine(GetHyphens(20));
        }

        private bool HandleResult(bool succ) {
            if (succ) {
                HandleSucc();
                return succ;
            }
            HandleFail();
            return succ;
        }

        private void HandleSucc() {
            mainPrinter.WriteLine("Success!");
            mainPrinter.WriteLine(GetHyphens(20));
        }

        private void PrintXorOfFirstPositionOnAllKeys(IPrinter printer) {
            printer.WriteLine("Xor on first position of the keys: " + XorAllKeys()[0].ToString());
        }

        private byte[] XorAllKeys() {
            var keys = AttackUtils.GetKeys(cipher);
            byte[] r = new byte[16];
            foreach (var key in keys)
                r = XORs(key, r);
            return r;
        }
    }
}
