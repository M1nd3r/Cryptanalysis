namespace Cryptanalysis.F.Core {
    class DummyPrinter : IPrinter {
        public void Write(string s) { }
        public void Write(byte[] arr) { }
        public void WriteLine(string s) { }
        public void WriteLine(byte[] arr) { }
    }
}
