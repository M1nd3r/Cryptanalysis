namespace Cryptanalysis.F.Core {

    internal class Flow {
        private byte[] arr;

        public Flow(byte[] input) {
            this.arr = input;
        }

        public int Length => arr.Length;

        public void Apply(AChanger changer) {
            changer.Apply(ref arr);
        }

        public void ApplyInverse(AChanger changer) {
            changer.ApplyInverse(ref arr);
        }

        public byte[] GetDeepCopy() {
            var r = new byte[arr.Length];
            for (int i = 0; i < arr.Length; i++)
                r[i] = arr[i];
            return r;
        }

        public void SetInput(byte[] arr)
            => this.arr = arr;
    }
}
