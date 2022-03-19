using Cryptanalysis.F.Core;
using static Cryptanalysis.F.Core.Verifiers;

namespace Cryptanalysis.F.Common {

    internal class Sbox4x4 : AChanger {
        private readonly Sbox4 sbox;

        public Sbox4x4(Sbox4 sbox) {
            this.sbox = sbox;
        }

        protected override void ApplyInternal(ref byte[] arr) {
            CheckAreEqual(16, arr.Length);
            for (int i = 0; i < 4; i++) {
                byte[] r = arr.SubArray(4 * i, 4);
                sbox.Apply(ref r);
                for (int j = 0; j < 4; j++) {
                    arr[4 * i + j] = r[j];
                }
            }
        }

        protected override void ApplyInverseInternal(ref byte[] arr) {
            CheckAreEqual(16, arr.Length);
            for (int i = 0; i < 4; i++) {
                var r = arr.SubArray(4 * i, 4);
                sbox.ApplyInverse(ref r);
                for (int j = 0; j < 4; j++) {
                    arr[4 * i + j] = r[j];
                }
            }
        }
    }
}
