using System;

namespace Cryptanalysis.F.Core {
    class ConsolePrinter : IPrinter {
        public void WriteLine(byte[] arr) {
            Write(arr);
            WriteLine("");
        }
        public void WriteLine(string s) => Console.WriteLine(s);
        public void Write(string s) => Console.Write(s);

        public void Write(byte[] arr) {
            if (arr == null) {
                Console.Write("null");
                return;
            }
            for (int i = 0; i < arr.Length; i++)
                Console.Write(arr[i]);
        }
    }
}
