using System;
using Cryptanalysis.Core;
using static Cryptanalysis.Core.Utils;

namespace Cryptanalysis.Common {

    internal class LFSR {
        private readonly int degree;

        private readonly byte[]
            func,
            key;

        private byte[] state;

        public LFSR(byte[] func, byte[] key) {
            this.func = func ?? throw new ArgumentNullException(nameof(func));
            this.key = key ?? throw new ArgumentNullException(nameof(key));
            VerifyFuncIsValid();
            VerifyKeyIsValid();
            SetInitialState();
            degree = GetDegree();
        }

        public byte[] Encode(byte[] input) {
            var r = new byte[input.Length];
            for (int i = 0; i < input.Length; i++)
                r[i] = Xor(input[i], GetNextBit());
            return r;
        }

        public byte GetNextBit() {
            byte r = state[^1];
            SetNewBit();
            return r;
        }

        private int GetDegree() {
            int maxDegree = -1;
            for (int i = 0; i < func.Length; i++) {
                if (func[i] == 1)
                    maxDegree = i;
            }
            return maxDegree;
        }

        private void SetInitialState() {
            this.state = new byte[key.Length];
            for (int i = 0; i < key.Length; i++) {
                state[key.Length - 1 - i] = key[i];
            }
        }

        private void SetNewBit() {
            byte newBit = 0;
            for (int i = 0; i <= degree; i++) {
                if (func[i] == 1)
                    newBit = Xor(newBit, state[i]);
            }
            for (int i = state.Length - 1; i > 0; i--)
                state[i] = state[i - 1];
            state[0] = newBit;
        }

        private void VerifyFuncIsValid() {
            int maxDeg = -1;
            for (int i = 0; i < func.Length; i++) {
                Verifiers.CheckIsZeroOrOne(func[i]);
                if (func[i] == 1)
                    maxDeg = i;
            }
            if (maxDeg == -1)
                throw new ArgumentException("Function has no non-zero elements!");
        }

        private void VerifyKeyIsValid() {
            if (func.Length != key.Length)
                throw new ArgumentException("The length of the key is not correct!");
            for (int i = 0; i < key.Length; i++)
                Verifiers.CheckIsZeroOrOne(key[i]);
        }
    }
}
