namespace Cryptanalysis.F.Core {
    interface IPrinter {
        void WriteLine(string s);
        void WriteLine(byte[] arr);
        void Write(string s);
        void Write(byte[] arr);
    }
}
