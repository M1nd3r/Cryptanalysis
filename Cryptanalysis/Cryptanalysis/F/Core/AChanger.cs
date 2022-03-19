namespace Cryptanalysis.F.Core {
    abstract class AChanger {
        protected IPrinter printer = new DummyPrinter();
        protected abstract void ApplyInternal(ref byte[] arr);
        protected abstract void ApplyInverseInternal(ref byte[] arr);
        public void Apply(ref byte[] arr) {
            Print(arr, " in");
            ApplyInternal(ref arr);
            Print(arr, " out");
        }
        public void ApplyInverse(ref byte[] arr) {
            Print(arr, " in");
            ApplyInverseInternal(ref arr);
            Print(arr, " out");
        }
        public void SetPrinter(IPrinter printer)
            => this.printer = printer;
        private void Print(byte[] arr, string s = "") {
            printer.Write(arr);
            printer.WriteLine(" - " + this.GetType().ToString() + s);
        }
    }
}
