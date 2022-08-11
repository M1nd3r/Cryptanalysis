using System;
using System.Collections.Generic;
using Cryptanalysis.Common;
using Cryptanalysis.Core;
using static Cryptanalysis.Core.DefaultCiphers;
using static Cryptanalysis.Core.DefaultFlowChangers;
using static Cryptanalysis.Core.Utils;
using static Cryptanalysis.Experiments.AttackUtils;

namespace Cryptanalysis.Experiments {

    internal class CorrelationAttackOnLFSR : Attack {

        private byte[]
            plaintext,
            ciphertext;

        public override bool BreakCipher() {
            SetMainPrinter(new ConsolePrinter());
            SetVerbosePrinter(new DummyPrinter());
            SetCipher(GetLFSRCipher());
            mainPrinter.WriteLine("");
            PrintKeys();

            int plaintextLength = 150;

            plaintext = GetRndInput(plaintextLength);
            SetCiphertext();
            byte[][] keys = new byte[][]{
                BreakFirstLFSR(),
                BreakSecondLFSR(),
                BreakThirdLFSR()
            };
            PrintRecoveredKeys(mainPrinter, keys);
            return CompareKeysAndHandleResult(keys);
        }

        private static void PrintRecoveredKeys(IPrinter p, byte[][] keys) {
            p.WriteLine("Discovered keys:");
            foreach (var key in keys)
                p.WriteLine(key);
            p.WriteLine("");
        }

        private byte[] BreakFirstLFSR() {
            return BreakLFSR(GetLFSR_7, 7);
        }

        private byte[] BreakLFSR(Func<byte[], LFSR> lfsrGenerator, int len) {
            var possibleKeys = GenerateAllPossibleKeys(len);
            var resultList = new List<KeyProbability>();
            for (int i = 0; i < possibleKeys.Count; i++) {
                LFSR reg = lfsrGenerator(possibleKeys[i]);
                var newCiphertext = reg.Encode(plaintext);
                resultList.Add(new KeyProbability(possibleKeys[i], ComputeLikness(newCiphertext)));
                verbosePrinter.Write(possibleKeys[i]);
                verbosePrinter.Write(" ");
                verbosePrinter.WriteLine(ComputeLikness(newCiphertext).ToString());
            }
            resultList.Sort();
            return resultList[0].key;
        }

        private byte[] BreakSecondLFSR() {
            return BreakLFSR(GetLFSR_11, 11);
        }

        private byte[] BreakThirdLFSR() {
            return BreakLFSR(GetLFSR_15, 15);
        }

        private bool CompareKeys(List<byte[]> keys, byte[][] guess) {
            if (keys.Count != guess.GetLength(0))
                return false;
            for (int i = 0; i < keys.Count; i++) {
                if (!CompareArrValues(keys[i], guess[i]))
                    return false;
            }
            return true;
        }

        private bool CompareKeysAndHandleResult(byte[][] guess) {
            var succ = CompareKeys(GetKeys(cipher), guess);
            mainPrinter.WriteLine(GetSuccessOrFailString(succ));
            return succ;
        }

        private int ComputeLikness(byte[] newCiphertext) {
            int r = 0;
            for (int i = 0; i < ciphertext.Length; i++) {
                if (ciphertext[i] == newCiphertext[i])
                    r++;
            }
            return r;
        }

        private void SetCiphertext() {
            ciphertext = cipher.Encode(plaintext);
        }

        private struct KeyProbability : IComparable {
            public readonly byte[] key;
            public readonly int probability;

            public KeyProbability(byte[] key, int probability) {
                this.key = key;
                this.probability = probability;
            }

            public int CompareTo(object obj) {
                if (obj is KeyProbability kp) {
                    if (probability > kp.probability)
                        return -1;
                    if (probability == kp.probability)
                        return 0;
                    return 1;
                }
                return -1;
            }
        }
    }
}
