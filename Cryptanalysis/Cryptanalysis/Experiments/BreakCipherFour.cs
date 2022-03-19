namespace Cryptanalysis.Experiments {
    class BreakCipherFour {
        public static void Do() {
            var cp = new CipherRunner();
            cp.SetInputs("0001001000110100");
            cp.Run(17);
            cp.Print();
        }
    }
}
