using System;
using Cryptanalysis.F.Core;
using static Cryptanalysis.F.Core.Verifiers;

namespace Cryptanalysis.F.Common {
    class XORwithKey : AChanger {
        private byte[] key;
        public XORwithKey(byte[] key) {
            this.key = key;
        }
        protected override void ApplyInternal(ref byte[] arr) {
            CheckAreEqual(arr.Length, key.Length);
            Xor(ref arr);
        }
        protected override void ApplyInverseInternal(ref byte[] arr) {
            CheckAreEqual(arr.Length, key.Length);
            Xor(ref arr);
        }
        protected static byte Xor(byte a, byte b) {
            if (a == 0 && b == 0)
                return 0;
            if (a == 1 && b == 1)
                return 0;
            if (a == 1 && b == 0)
                return 1;
            if (a == 0 && b == 1)
                return 1;
            throw new ArgumentException("At least one of the arguments is not zero or one!");
        }
        private void Xor(ref byte[] arr) {
            for (int i = 0; i < arr.Length; i++)
                arr[i] = Xor(arr[i], key[i]);
        }
    }
}
