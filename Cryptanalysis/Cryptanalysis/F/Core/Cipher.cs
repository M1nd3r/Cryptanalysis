using System;
using System.Collections.Generic;

namespace Cryptanalysis.F.Core {
    class Cipher {
        private IList<AChanger> changers;
        private Flow flow;
        public Cipher(IList<AChanger> flowChangers) {
            this.flow = new Flow(null);
            changers = flowChangers;
        }
        public byte[] Encode(byte[] input) {
            flow.SetInput(CreateCopy(input));
            for (int i = 0; i < changers.Count; i++)
                flow.Apply(changers[i]);
            return flow.GetDeepCopy();
        }
        public byte[] Decode(byte[] input) {
            flow.SetInput(input);
            for (int i = changers.Count - 1; i >= 0; i--)
                flow.ApplyInverse(changers[i]);
            return flow.GetDeepCopy();
        }
        private byte[] CreateCopy(byte[] arr) {
            byte[] x = new byte[arr.Length];
            Array.Copy(arr, x, arr.Length);
            return x;
        }
    }
}
