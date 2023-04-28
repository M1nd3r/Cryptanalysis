using System;
using System.Collections.Generic;
using Cryptanalysis.Common;
using Cryptanalysis.Core;
using static Cryptanalysis.Core.DefaultCiphers;
using static Cryptanalysis.Core.DefaultFlowChangers;
using static Cryptanalysis.Core.Utils;
using static Cryptanalysis.Experiments.AttackUtils;

namespace Cryptanalysis.Experiments {

    internal class FastCorrelationAttackOnLFSR : Attack {
        private readonly int threshold = 8;

        private byte[]
                    plaintext,
            ciphertext,
            xorOrig;

        private List<int> validPoints = new List<int>();

        public override bool BreakCipher() {
            SetMainPrinter(new ConsolePrinter());
            SetVerbosePrinter(new ConsolePrinter());
            SetCipher(GetLFSRCipher());
            mainPrinter.WriteLine("");
            PrintKeys();

            int plaintextLength = 2000;
            plaintext = GetRndInput(plaintextLength);
            SetCiphertext();

            // Comparing output with output of single LFSR
            var realKeys = GetKeys(cipher);
            var comparingLFSR = CreateCipherFromLFSR(new LFSRchanger(realKeys[0], GetLFSR_7));
            var verifyLFSR = CreateCipherFromLFSR(new LFSRchanger(realKeys[0], GetLFSR_7));
            var newRealKey = GetKeys(comparingLFSR);

            var singleLFSRciphertext = GetSingleLFSRciphertext(comparingLFSR);
            verbosePrinter.WriteLine(ciphertext);
            verbosePrinter.WriteLine(singleLFSRciphertext);

            xorOrig = XORs(ciphertext, plaintext);
            var xorSingle = XORs(singleLFSRciphertext, plaintext);
            verbosePrinter.WriteLine("After XORing with plaintext:");
            verbosePrinter.WriteLine(xorOrig);
            verbosePrinter.WriteLine(xorSingle);

            GetAllValidPoints();
            PrintSelectedBits(verbosePrinter);

            verbosePrinter.WriteLine(Math.Round(CheckSimilarity(xorOrig, xorSingle), 2).ToString());
            verbosePrinter.WriteLine(Math.Round(CheckSimilarity(xorOrig, xorSingle, validPoints), 2).ToString());

            var testc = FindSevenAdjacent();
            if (testc == -1) {
                mainPrinter.WriteLine("failed to find perfect sequence.");
                return false;
            }

            for (int i = 6; i >= 0; i--) {
                verbosePrinter.Write(xorOrig[validPoints[testc - i]].ToString());
            }
            verbosePrinter.WriteLine(" - index " + validPoints[testc].ToString());

            byte[] finisher = new byte[validPoints[testc] + 1];

            for (int i = 0; i < 7; i++) {
                finisher[finisher.Length - i - 1] = xorOrig[validPoints[testc - i]];
            }
            for (int i = finisher.Length - 7 - 1; i >= 0; i--) {
                finisher[i] = Xor(finisher[i + 6], finisher[i + 7]);
            }

            verbosePrinter.WriteLine(finisher);
            verbosePrinter.WriteLine(xorSingle);
            verbosePrinter.WriteLine(Math.Round(CheckSimilarity(finisher, xorSingle), 2).ToString());
            mainPrinter.WriteLine("Recovered key: ");
            mainPrinter.WriteLine(finisher.SubArray(0, 7));
            mainPrinter.WriteLine("Original key:  ");
            mainPrinter.WriteLine(newRealKey[0]);
            for (int i = 0; i < 500; i++) {
                verbosePrinter.Write(verifyLFSR.Encode(new byte[] { 0 }));
            }
            return HandleResult(AreKeysTheSame(finisher.SubArray(0, 7), newRealKey[0]));
        }

        private bool AreKeysTheSame(byte[] a, byte[] b) {
            for (int i = 0; i < a.Length; i++) {
                if (a[i] != b[i])
                    return false;
            }
            return true;
        }

        private int FindSevenAdjacent() {
            int c = 1;
            int a = validPoints[0];
            for (int i = 1; i < validPoints.Count; i++) {
                if (validPoints[i] == a + 1)
                    c++;
                else
                    c = 1;
                if (c == 7)
                    return i;
                a = validPoints[i];
            }
            return -1;
        }

        private void GetAllValidPoints() {
            validPoints = new List<int>();
            for (int i = threshold; i < xorOrig.Length - threshold; i++) {
                if (IsSatisfying(i))
                    validPoints.Add(i);
            }
        }

        private byte[] GetSingleLFSRciphertext(Cipher c) {
            return c.Encode(plaintext);
        }

        private bool HandleResult(bool succ) {
            if (succ)
                mainPrinter.WriteLine("Successfully decoded");
            else
                mainPrinter.WriteLine("Fail!");
            return succ;
        }

        private bool IsSatisfying(int i) {
            return
                xorOrig[i] == Xor(xorOrig[i - 1], xorOrig[i - 7])
                && xorOrig[i] == Xor(xorOrig[i + 1], xorOrig[i - 6])
                && xorOrig[i] == Xor(xorOrig[i + 6], xorOrig[i + 7])
                //&& xorOrig[i] == Xor(Xor(xorOrig[i + 8], xorOrig[i + 2]), xorOrig[i + 1])
                ;
        }

        private void PrintSelectedBits(IPrinter printer) {
            for (int i = 0; i < xorOrig.Length; i++) {
                if (validPoints.Contains(i))
                    printer.Write(xorOrig[i].ToString());
                else
                    printer.Write("-");
            }
            printer.WriteLine("");
        }

        private void SetCiphertext() {
            ciphertext = cipher.Encode(plaintext);
        }
    }
}
