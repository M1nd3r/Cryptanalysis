using System;
using System.Collections.Generic;
using Cryptanalysis.Common;
using Cryptanalysis.Core;
using static Cryptanalysis.Core.DefaultCiphers;
using static Cryptanalysis.Core.DefaultFlowChangers;
using static Cryptanalysis.Core.Utils;
using static Cryptanalysis.Experiments.AttackUtils;

namespace Cryptanalysis.Experiments {

    internal class AttackOnFinalCipher : Attack {

        protected byte[]
            plaintext,
            ciphertext;

        private readonly int ciphertextLength = 1000;
        private IList<byte[]> realKeys;

        public override bool BreakCipher() {
            SetMainPrinter(new ConsolePrinter());
            SetVerbosePrinter(new DummyPrinter());
            plaintext = new byte[ciphertextLength];
            SetCipherAndCiphertext(plaintext);
            realKeys = GetKeys(cipher);
            mainPrinter.WriteLine("");
            mainPrinter.WriteLine(ciphertext);

            var listKeyXciphPairs = PhaseOne();
            var listKeyTciphPairs = PhaseTwo();
            var t = PhaseThree(listKeyXciphPairs, listKeyTciphPairs);

            PrintResultTriplets(t);
            PrintKeys();

            var twoObtainedKeys = GetKeyXKeyT(t);
            var obtainedKeyX = twoObtainedKeys.GetKeyXY;
            var obtainedKeyT = twoObtainedKeys.GetKeyT;
            var obtainedKeyY = PhaseFour(obtainedKeyT);

            return HandleResult(obtainedKeyX, obtainedKeyY, obtainedKeyT);
        }

        public virtual void SetCipherAndCiphertext(byte[] plaintext) {
            SetCipher(GetFinalCipher());
            ciphertext = cipher.Encode(plaintext);
        }

        private byte[] EncodeUsingT(byte[] xoredBitrsing, byte[] outputT) {
            byte[] r = new byte[xoredBitrsing.Length];
            for (int i = 0; i < xoredBitrsing.Length; i++) {
                if (xoredBitrsing[i] == 1)
                    r[i] = outputT[i];
                else
                    r[i] = Neg(outputT[i]);
            }
            return r;
        }

        private KeyXkeyTmaxProb GetKeyXKeyT(IList<KeyXkeyTmaxProb> list) {
            var r = list[0];
            for (int i = 1; i < list.Count; i++) {
                if (list[i].GetProb > r.GetProb)
                    r = list[i];
            }
            return r;
        }

        private byte[] GetTciphertext(byte[] obtainedKeyT) {
            var c = CreateCipherFromLFSR(new LFSRchanger(obtainedKeyT, GetFinalLFSR_11_T));
            return c.Encode(new byte[ciphertext.Length]);
        }

        private bool HandleResult(byte[] keyX, byte[] keyY, byte[] keyT) {
            verbosePrinter.Write("Obtained key X: ");
            verbosePrinter.WriteLine(keyX);

            verbosePrinter.Write("Obtained key Y: ");
            verbosePrinter.WriteLine(keyY);
            verbosePrinter.Write("Obtained key T: ");
            verbosePrinter.WriteLine(keyT);

            return
                CompareArrValues(keyX, realKeys[0])
                && CompareArrValues(keyY, realKeys[1])
                && CompareArrValues(keyT, realKeys[3]);
        }

        private byte[] PhaseFour(byte[] obtainedKeyT) {
            var ciphertextT = GetTciphertext(obtainedKeyT);
            var keys = GenerateAllPossibleKeys(11);
            var zeroes = new byte[ciphertext.Length];
            var bestGuess = new KeyXkeyTmaxProb(null, null, -1);

            for (int i = 1; i < keys.Count; i++) {
                var c = CreateCipherFromLFSR(new LFSRchanger(keys[i], GetFinalLFSR_11_Y));
                var text = c.Encode(zeroes);
                var tt = EncodeUsingT(text, ciphertextT);
                var prob = CheckSimilarity(tt, ciphertext);
                if (prob > bestGuess.GetProb)
                    bestGuess = new KeyXkeyTmaxProb(keys[i], null, prob);
            }
            return bestGuess.GetKeyXY;
        }

        //Generates all possible combinations (127) for LFSR_X (ignoring all-zeroes key)
        private IList<KeyCiphertext> PhaseOne() {
            var keys = GenerateAllPossibleKeys(7);
            IList<KeyCiphertext> pairs = new List<KeyCiphertext>();
            for (int i = 1; i < keys.Count; i++) {
                var c = CreateCipherFromLFSR(new LFSRchanger(keys[i], GetFinalLFSR_7_X));
                pairs.Add(new KeyCiphertext(keys[i], c.Encode(new byte[ciphertext.Length])));
            }
            return pairs;
        }

        private IList<KeyXkeyTmaxProb> PhaseThree(IList<KeyCiphertext> keyXpairs, IList<KeyCiphertext> KeyTpairs) {
            IList<KeyXkeyTmaxProb> keyXkeyTprob = new List<KeyXkeyTmaxProb>();

            foreach (var kp in keyXpairs) {
                verbosePrinter.Write("Testing keyX: ");
                verbosePrinter.WriteLine(kp.GetKey);
                var bestGuess = new KeyXkeyTmaxProb(null, null, -1);
                foreach (var key in KeyTpairs) {
                    var test = EncodeUsingT(kp.GetCiphertext, key.GetCiphertext);
                    var prob = CheckSimilarity(test, ciphertext);
                    if (prob > bestGuess.GetProb)
                        bestGuess = new KeyXkeyTmaxProb(kp.GetKey, key.GetKey, prob);
                }
                keyXkeyTprob.Add(new KeyXkeyTmaxProb(bestGuess));
            }
            return keyXkeyTprob;
        }

        private IList<KeyCiphertext> PhaseTwo() {
            var keys = GenerateAllPossibleKeys(11);
            IList<KeyCiphertext> pairs = new List<KeyCiphertext>();
            var zeroes = new byte[ciphertext.Length];
            for (int i = 1; i < keys.Count; i++) {
                var c = CreateCipherFromLFSR(new LFSRchanger(keys[i], GetFinalLFSR_11_T));
                pairs.Add(new KeyCiphertext(keys[i], c.Encode(zeroes)));
            }
            return pairs;
        }

        private void PrintResultTriplets(IList<KeyXkeyTmaxProb> l) {
            foreach (var t in l) {
                verbosePrinter.Write(t.GetKeyXY);
                verbosePrinter.Write(", ");
                verbosePrinter.Write(t.GetKeyT);
                verbosePrinter.Write(", ");
                verbosePrinter.WriteLine(Math.Round(t.GetProb, 2).ToString());
            }
        }

        private class KeyCiphertext {

            private readonly byte[]
                keyX,
                ciphertext;

            public KeyCiphertext(byte[] keyX, byte[] ciphertext) {
                this.keyX = keyX;
                this.ciphertext = ciphertext;
            }

            public byte[] GetCiphertext { get => ciphertext; }
            public byte[] GetKey { get => keyX; }
        }

        //Generates all possible combinations (2047) for LFSR_T (ignoring all-zeroes key)
        private class KeyXkeyTmaxProb {

            private readonly byte[]
                keyX,
                keyT;

            private readonly double prob;

            public KeyXkeyTmaxProb(byte[] keyX, byte[] keyT, double prob) {
                this.keyX = keyX;
                this.keyT = keyT;
                this.prob = prob;
            }

            public KeyXkeyTmaxProb(KeyXkeyTmaxProb keyKeyProb) {
                this.keyX = keyKeyProb.keyX;
                this.keyT = keyKeyProb.keyT;
                this.prob = keyKeyProb.prob;
            }

            public byte[] GetKeyT { get => keyT; }
            public byte[] GetKeyXY { get => keyX; }
            public double GetProb { get => prob; }
        }
    }
}
