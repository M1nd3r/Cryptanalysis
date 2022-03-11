using System;
using static Cryptanalysis.Core.Constants;

namespace Cryptanalysis.Core.Common {
    class XOR : Gate {
        private int inputsLen;
        public XOR(string name, int inputsLen) : base(name) {
            if (inputsLen < 1)
                throw new ArgumentException();
            this.inputsLen = inputsLen;
            inputs = InSlot.GetInSlots(2 * inputsLen);
            outputs = OutSlot.GetOutSlots(inputsLen);
        }
        private XOR(XOR g) : this(g.Name, g.inputsLen) {
        }

        public override Gate Duplicate() {
            return new XOR(this);
        }

        public override void Run() {
            for (int i = 0; i < inputsLen; i++)
                outputs[i].Set(xor(inputs[i].Get, inputs[i + inputsLen].Get));
        }
        private static byte xor(byte a, byte b) {
            return (a, b) switch {
                (BYTE_ONE, BYTE_ZERO) => BYTE_ONE,
                (BYTE_ZERO, BYTE_ONE) => BYTE_ONE,
                (BYTE_ZERO, BYTE_ZERO) => BYTE_ZERO,
                (BYTE_ONE, BYTE_ONE) => BYTE_ZERO,
                _ => BYTE_UNDEFINED,
            };
        }
    }
}
