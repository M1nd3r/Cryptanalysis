using System.Collections.Generic;
using static Cryptanalysis.Core.Utils;

namespace Cryptanalysis.F.Core {

    internal class Cipher {
        private readonly Flow flow;
        private readonly IList<AChanger> changers;

        public Cipher(IList<AChanger> flowChangers) {
            this.flow = new Flow(null);
            changers = flowChangers;
        }

        public byte[] Decode(byte[] input) {
            flow.SetInput(input);
            for (int i = changers.Count - 1; i >= 0; i--)
                flow.ApplyInverse(changers[i]);
            return flow.GetDeepCopy();
        }

        public byte[] Encode(byte[] input) {
            flow.SetInput(CreateCopy(input));
            for (int i = 0; i < changers.Count; i++)
                flow.Apply(changers[i]);
            return flow.GetDeepCopy();
        }
    }
}
