using Cryptanalysis.Core;
using static Cryptanalysis.Core.DefaultFlowChangers;
using static Cryptanalysis.Core.Utils;

namespace Cryptanalysis.Common {

    internal class LFSR3Mix : AChanger {

        private readonly LFSR[]
            LFSR_Enc,
            LFSR_Dec;

        public LFSR3Mix() {
            byte[]
                key7 = GetRndKey(8),
                key11 = GetRndKey(12),
                key15 = GetRndKey(16);
            LFSR_Enc = new LFSR[] {
                GetLFSR_7(key7),
                GetLFSR_11(key11),
                GetLFSR_15(key15)
            };
            LFSR_Dec = new LFSR[] {
                GetLFSR_7(key7),
                GetLFSR_11(key11),
                GetLFSR_15(key15)
            };
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
            byte r = 0;
            r = Xor(r, And(nextBits[0], nextBits[1]));
            r = Xor(r, And(nextBits[1], nextBits[2]));
            r = Xor(r, And(nextBits[2], nextBits[0]));
            return r;
        }
    }
}
