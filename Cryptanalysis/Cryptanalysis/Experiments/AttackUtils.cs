using System.Collections.Generic;
using Cryptanalysis.Common;
using Cryptanalysis.Core;
using static Cryptanalysis.Core.Verifiers;

namespace Cryptanalysis.Experiments {

    internal static class AttackUtils {

        internal static List<byte[]> GetKeys(Cipher cipher) {
            List<AChanger> listRefl =
                ((List<AChanger>)cipher.GetType()
                .GetField(
                    "changers",
                    System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)
                .GetValue(cipher)).FindAll(x => x is XORwithKey);
            List<byte[]> ret = new List<byte[]>();
            foreach (var xorKey in listRefl) {
                var key = (byte[])xorKey.GetType().GetField("key", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance).GetValue(xorKey);
                ret.Add(key);
            }
            return ret;
        }

        internal static bool NotContains(this IList<byte[]> list, byte[] value) {
            foreach (var item in list) {
                if (AreEqual(item, value))
                    return false;
            }
            return true;
        }
    }
}
