using System;
using Cryptanalysis.Core;
using static Cryptanalysis.Core.Utils;

namespace Cryptanalysis.Common {

    internal class LFSRchanger : AChanger {

        private readonly LFSR
            LFSR_Enc,
            LFSR_Dec;

        public LFSRchanger(byte[] key, Func<byte[], LFSR> f) {
            LFSR_Enc = f(key);
            LFSR_Dec = f(key);
        }

        protected override void ApplyInternal(ref byte[] arr) {
            for (int i = 0; i < arr.Length; i++)
                arr[i] = Xor(arr[i], LFSR_Enc.GetNextBit());
        }

        protected override void ApplyInverseInternal(ref byte[] arr) {
            for (int i = 0; i < arr.Length; i++)
                arr[i] = Xor(arr[i], LFSR_Dec.GetNextBit());
        }
    }
}
