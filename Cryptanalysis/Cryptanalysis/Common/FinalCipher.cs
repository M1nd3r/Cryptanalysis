using Cryptanalysis.Core;
using static Cryptanalysis.Core.DefaultFlowChangers;
using static Cryptanalysis.Core.Utils;

namespace Cryptanalysis.Common {

    internal abstract class AFinalCipher : AChanger {

        protected readonly LFSR[]
            LFSR_Enc,
            LFSR_Dec;

        protected AFinalCipher(byte[] key7x, byte[] key11y, byte[] key15z, byte[] key11t) {
            LFSR_Enc = new LFSR[] {
                GetFinalLFSR_7_X(key7x),
                GetFinalLFSR_11_Y(key11y),
                GetFinalLFSR_15_Z(key15z),
                GetFinalLFSR_11_T(key11t)
            };
            LFSR_Dec = new LFSR[] {
                GetFinalLFSR_7_X(key7x),
                GetFinalLFSR_11_Y(key11y),
                GetFinalLFSR_15_Z(key15z),
                GetFinalLFSR_11_T(key11t)
            };
        }
    }

    internal class FinalCipher : AFinalCipher {

        public FinalCipher(byte[] key7x, byte[] key11y, byte[] key15z, byte[] key11t)
            : base(key7x, key11y, key15z, key11t) { }

        public FinalCipher() : base(GetRndKey(7), GetRndKey(11), GetRndKey(15), GetRndKey(11)) {
        }

        protected override void ApplyInternal(ref byte[] arr) {
            for (int i = 0; i < arr.Length; i++)
                arr[i] = Xor(arr[i], GetNextMixedOutput(LFSR_Enc));
        }

        protected override void ApplyInverseInternal(ref byte[] arr) {
            for (int i = 0; i < arr.Length; i++)
                arr[i] = Xor(arr[i], GetNextMixedOutput(LFSR_Dec));
        }

        private byte GetNextMixedOutput(LFSR[] registers) {
            var nextBits = new byte[registers.Length];
            for (int i = 0; i < registers.Length; i++) {
                nextBits[i] = registers[i].GetNextBit();
            }
            var r = And(nextBits[0], nextBits[1]);
            r = Xor(r, And(nextBits[1], nextBits[2]));
            r = Xor(r, And(nextBits[2], nextBits[0]));
            if (r == 1)
                return nextBits[3];
            return Neg(nextBits[3]);
        }
    }
}
