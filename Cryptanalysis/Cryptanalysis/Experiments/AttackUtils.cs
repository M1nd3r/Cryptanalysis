using System;
using System.Collections.Generic;
using Cryptanalysis.Common;
using Cryptanalysis.Core;
using static Cryptanalysis.Core.Utils;
using static Cryptanalysis.Core.Verifiers;

namespace Cryptanalysis.Experiments {

    internal static class AttackUtils {

        internal static IList<byte[]> GenerateAllPossibleKeys(int length) {
            if (length <= 0)
                throw new ArgumentException("Length cannot be less than one.");
            if (length >= 29)
                throw new ArgumentException("This length is too big, it is not supported.");
            int total = (int)Math.Pow(2, length);
            var list = new List<byte[]>();
            for (int i = 0; i < total; i++)
                list.Add(ConvertToBinary(i, length));
            return list;
        }

        internal static string GetFailString() => "Fail!";

        internal static List<byte[]> GetKeys(Cipher cipher) {
            var listXorWithKeys = new List<AChanger>();
            listXorWithKeys.AddRange(
                ((List<AChanger>)cipher.GetType()
                .GetField(
                    "changers",
                    System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)
                .GetValue(cipher)).FindAll(x => x is XORwithKey));

            var listLFSRmix = ((List<AChanger>)cipher.GetType()
                .GetField(
                    "changers",
                    System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)
                .GetValue(cipher)).FindAll(x => (x is LFSR3Mix || x is FinalCipher));

            var listLFSR7 = ((List<AChanger>)cipher.GetType()
                .GetField(
                    "changers",
                    System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)
                .GetValue(cipher)).FindAll(x => x is LFSRchanger);

            List<byte[]> ret = new List<byte[]>();
            foreach (var xorKey in listXorWithKeys) {
                var key = (byte[])xorKey.GetType()
                    .GetField(
                        "key",
                        System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)
                    .GetValue(xorKey);
                ret.Add(key);
            }
            var listLSFR = new List<LFSR>();
            foreach (var lfsrmix in listLFSRmix) {
                listLSFR.AddRange((LFSR[])lfsrmix.GetType()
                    .GetField(
                        "LFSR_Dec",
                        System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)
                    .GetValue(lfsrmix));
            }
            foreach (var lfsr in listLFSR7) {
                listLSFR.Add((LFSR)lfsr.GetType()
                    .GetField(
                        "LFSR_Dec",
                        System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)
                    .GetValue(lfsr));
            }

            foreach (var lfsr in listLSFR) {
                var key = (byte[])lfsr.GetType()
                    .GetField(
                        "key",
                        System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)
                    .GetValue(lfsr);
                ret.Add(key);
            }
            return ret;
        }

        internal static string GetSuccessOrFailString(bool succ) {
            if (succ)
                return GetSuccessString();
            return GetFailString();
        }

        internal static string GetSuccessString() => "Success!";

        internal static bool NotContains(this IList<byte[]> list, byte[] value) {
            foreach (var item in list) {
                if (AreEqual(item, value))
                    return false;
            }
            return true;
        }
    }
}
