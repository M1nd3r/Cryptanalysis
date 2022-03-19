namespace Cryptanalysis.F.Core {

    internal interface IPrinter {

        void Write(string s);

        void Write(byte[] arr);

        void WriteLine(string s);

        void WriteLine(byte[] arr);
    }
}
