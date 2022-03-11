using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static Cryptanalysis.Core.Constants;

namespace Cryptanalysis.Core {

    class TransitionFunction {
        List<byte[]>
            inputs,
            outputs;
        private int defaultOutputsCount;
        public TransitionFunction(int defaultOutputsCount) {
            inputs = new List<byte[]>();
            outputs = new List<byte[]>();
            this.defaultOutputsCount = defaultOutputsCount;
        }
        public void Perform(ref List<InSlot> input, ref List<OutSlot> outputs) {
            var inp = ConvertToByte(input);
            var output = GetOutput(inp);
            SetOutputs(ref outputs, output);
        }
        private static byte[] ConvertToByte(List<InSlot> input) {
            var r = new byte[input.Count];
            for (int i = 0; i < input.Count; i++)
                r[i] = input[i].Get;
            return r;
        }
        private static bool AreEqual(byte[] a, byte[] b) {
            if (a == null || b == null)
                return false;
            if (a.Length != b.Length)
                return false;
            for (int i = 0; i < a.Length; i++) {
                if (a[i] != b[i])
                    return false;
            }
            return true;
        }
        private byte[] GetOutput(byte[] arrIn) {
            for (int i = 0; i < inputs.Count; i++) {
                if (AreEqual(arrIn, inputs[i]))
                    return outputs[i];
            }
            //Failed to find corresponding input/output pair
            byte[] arrOut = new byte[defaultOutputsCount];
            for (int i = 0; i < arrOut.Length; i++)
                arrOut[i] = BYTE_UNDEFINED;
            return arrOut;
        }
        private static void SetOutputs(ref List<OutSlot> outputs, byte[] valueToSet) {
            if (outputs.Count != valueToSet.Length)
                throw new Exception("Number of output slots of the gate and of number of values to set are not the same");
            for (int i = 0; i < outputs.Count; i++)
                outputs[i].Set(valueToSet[i]);
        }
        public void AddInputOutputPair(byte[] input, byte[] output) {
            this.inputs.Add(input);
            this.outputs.Add(output);
        }
    }
}
