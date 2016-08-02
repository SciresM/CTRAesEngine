using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using Microsoft.VisualStudio.TestTools.UnitTesting;

using AesEngineTest.Properties;

using CTR;

namespace AesEngineTest
{
    [TestClass]
    public class UnitTests
    {
        private static readonly byte[] nistPlaintext =
            "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710"
                .ToByteArray();

        private static readonly byte[] nistKey = "2b7e151628aed2a6abf7158809cf4f3c".ToByteArray();

        [TestMethod]
        public void TestZeroKeyNCCHCrypto()
        {
            using (MemoryStream inStream = new MemoryStream())
            using (MemoryStream outStream = new MemoryStream())
            {
                inStream.Write(Resources.FBI_zerokeys_ncch, 0, Resources.FBI_zerokeys_ncch.Length);
                outStream.Write(Resources.FBI_zerokeys_ncch, 0, Resources.FBI_zerokeys_ncch.Length);
                inStream.Seek(0, SeekOrigin.Begin);
                outStream.Seek(0, SeekOrigin.Begin);
                var Engine = new AesEngine();
                Engine.DecryptNCCH(inStream, outStream);
                outStream.Seek(0, SeekOrigin.Begin);
                ValidateNCCH(outStream);
            }
        }

        [TestMethod]
        public void TestNCSDCrypto()
        {
            using (MemoryStream inStream = new MemoryStream())
            using (MemoryStream outStream = new MemoryStream())
            {
                inStream.Write(Resources.FBI_zerokeys_3ds, 0, Resources.FBI_zerokeys_3ds.Length);
                outStream.Write(Resources.FBI_zerokeys_3ds, 0, Resources.FBI_zerokeys_3ds.Length);
                inStream.Seek(0, SeekOrigin.Begin);
                outStream.Seek(0, SeekOrigin.Begin);
                var Engine = new AesEngine();
                Engine.DecryptGameNCSD(inStream, outStream);
                outStream.Seek(0, SeekOrigin.Begin);
                File.WriteAllBytes("E:/fbi_dec.3ds",outStream.ToArray());
                ValidateGameNSCD(outStream);
            }
        }

        [TestMethod]
        public void TestAesCBC()
        {
            var Engine = new AesEngine();
            Engine.SelectKeyslot(0x11);
            Engine.SetNormalKey(nistKey);
            Engine.SetIV("000102030405060708090a0b0c0d0e0f".ToByteArray());
            Engine.SetMode(AesMode.CBC);
            byte[] encrypted = Engine.Encrypt(nistPlaintext);
            CollectionAssert.AreEqual(encrypted, "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b273bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7".ToByteArray());
            byte[] decrypted = Engine.Decrypt(encrypted);
            CollectionAssert.AreEqual(nistPlaintext, decrypted);
        }

        [TestMethod]
        public void TestAesECB()
        {
            var Engine = new AesEngine();
            Engine.SelectKeyslot(0x11);
            Engine.SetNormalKey(nistKey);
            Engine.SetMode(AesMode.ECB);
            byte[] encrypted = Engine.Encrypt(nistPlaintext);
            CollectionAssert.AreEqual(encrypted, "3ad77bb40d7a3660a89ecaf32466ef97f5d3d58503b9699de785895a96fdbaaf43b1cd7f598ece23881b00e3ed0306887b0c785e27e8ad3f8223207104725dd4".ToByteArray());
            byte[] decrypted = Engine.Decrypt(encrypted);
            CollectionAssert.AreEqual(nistPlaintext, decrypted);
        }

        [TestMethod]
        public void TestAesCTR()
        {
            var Engine = new AesEngine();
            Engine.SelectKeyslot(0x11);
            Engine.SetNormalKey(nistKey);
            Engine.SetIV("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff".ToByteArray());
            Engine.SetMode(AesMode.CTR);
            byte[] encrypted = Engine.Encrypt(nistPlaintext);
            CollectionAssert.AreEqual(encrypted, "874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee".ToByteArray());
            byte[] decrypted = Engine.Decrypt(encrypted);
            CollectionAssert.AreEqual(nistPlaintext, decrypted);
        }

        [TestMethod]
        public void TestAesCCM()
        {
            var Engine = new AesEngine();
            Engine.SelectKeyslot(0x11);
            Engine.SetMode(AesMode.CCM);
            // Uses data from English pre-release "Example" ORAS QR code.
            Engine.SetNormalKey("044AC6D4576EEA180C12AE92E24FA369".ToByteArray());
            Engine.SetNonce("D4EEB874289E6C13A4578621".ToByteArray());
            byte[] mac = "EF0C908A30ADAEE74C0F8120B6703E2C".ToByteArray();
            Engine.SetMAC(mac);
            byte[] encrypted =
                "5470E724C18E2D2D68B390E0D54E87EBB28E21B1C20552AA35FF6393436DCBAF0E680B6D37D2F0593E677D6229C3D186D3B561699B014A2F6CB4AB523035C317C6957A583E5031977F872D08677F530441B049C9D9A365776B63245DBC25EF35E79EB2FBA870A20F1A02CD13FCD8E7511EBF5D29C125BDDAB9AC4426A1FE2B39B23AF861A0D05E31A0505FBEDBFE78B6FBA0D92435D3A83C7CC5DBA50CC3E9A4556631CE5BC20F9D35AD4CC877C84176A84C160D7BB6C31C4EAB09C536D6BB8EB2D4B30A446D9578BB23EBB18B4FA7F44D1223340C5D3846D299609F9E6FEDBC0AD5527D6AB6D0426AAC8F576C2AF8B6C6CEB5090BACFE735A074DBFEB7B05FEBF585F8FBF6466F46BD3D55CC19755437A082400C88490F8E899B732E3E54E0FB4DD1C70CFC85FE959319767BCE2DF47E8903529935A62BDC052A46BC860BADAE212EBFACF36972946DEFE9D2B990896FB20EC2B7AD35408845E1D4F020CF2AD124B4E2539393E7488173A00C28584380E87B8447EF74F7A65DA4E81B383017F62F5A3845A302E0F3CD28A1F62141174E63C546E9A1CDFD156F5880599E306BCB65C71623E8585E2869A0E510899F2E4C8A68360D74EB056AE347B42F7BC8BC6B762C6933ADAD723D95DF5A5BD5A9EB88208E669AA19F3BBDFAAE860E963C4D48B8CE527DE02E9F2EE54388D4FC9C73AAFB44053CE84E88518C0CAD9D175B3AB15E4276385AC200AC448468982DEA1E881A22E5BCF5DEA52"
                    .ToByteArray();
            byte[] decrypted =
                "542E11C193DBB9232B164C6BFFFF0000000000003500000000004F0072006C0061006E0064006F0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005900610079000000000000000000000000000000000000000000000000000000000044006F00200079006F007500720020006200650073007400000000000000000000000000000000000000000000000000000000000000000000000000480065006C006C006F0021000000000000000000000000000000000000000000000043006F006E00670072006100740075006C006100740069006F006E0073002100000002000008FF00000000350015551FDA66FC0000009C010F0046005B000041011300000000000000000000000B0019131205460363D5554182FF0000003500F900940022010042010B0000000000000000000000110F1A1B0810460463F138AADA020100003A0039007F002301004302060000000000000000000000050F021B13034602631E1E1E1E1EAD1314151617FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF121314151617000000000000000000000000000000000000000C0C0C0C0C0C00000000000000000000000000000000000000010101010101000000000000000000000000000000000000000000000000000000000000000000000000"
                    .ToByteArray();
            byte[] decTest = Engine.Decrypt(encrypted);
            CollectionAssert.AreEqual(decrypted, decTest);
            // Clear MAC to verify the calculated actually matches
            Engine.SetMAC("00000000000000000000000000000000".ToByteArray());
            byte[] encTest = Engine.Encrypt(decrypted);
            CollectionAssert.AreEqual(encrypted, encTest);
            CollectionAssert.AreEqual(mac, Engine.GetMAC());
        }

        [TestMethod]
        public void TestKeyScrambler()
        {
            var Engine = new AesEngine();
            Engine.SelectKeyslot(0x11);
            Engine.SetMode(AesMode.ECB);
            byte[] knownKey = "EE2EA93B450FFCF4D562FF02040122C8".ToByteArray();
            byte[] knownResult = "44D193F977EC6092388ABFE4D9C73A97".ToByteArray();

            byte[] KeyX = new byte[0x10];
            byte[] KeyY = new byte[0x10];
            Engine.SetKeyX(KeyX);
            Engine.SetKeyY(KeyY);
            Engine.SetIV(new byte[0x10]);
            byte[] firstEncrypted = Engine.Encrypt(new byte[0x10]);
            KeyX[0xF] = 1;
            KeyY[0xF] = 4;
            Engine.SetKeyX(KeyX);
            Engine.SetKeyY(KeyY);
            byte[] secondEncrypted = Engine.Encrypt(new byte[0x10]);
            Engine.SetNormalKey(knownKey);
            byte[] knownEncrypted = Engine.Encrypt(new byte[0x10]);
            CollectionAssert.AreEqual(knownResult, knownEncrypted);
            CollectionAssert.AreEqual(knownResult, firstEncrypted);
            CollectionAssert.AreEqual(knownResult, secondEncrypted);
        }


        private static void ValidateGameNSCD(Stream ncsdStream)
        {
            byte[] _u32 = new byte[4];
            ncsdStream.Seek(0x100, SeekOrigin.Begin);
            ncsdStream.Read(_u32, 0, 4);
            string magic = new string(_u32.Select(b => (char)b).ToArray());
            if (magic != "NCSD")
                throw new ArgumentException("Invalid NCSD passed to decryption method!");
            ncsdStream.Seek(0x120, SeekOrigin.Begin);
            long[] Offsets = new long[8];
            long[] Sizes = new long[8];
            for (int i = 0; i < 8; i++)
            {
                ncsdStream.Read(_u32, 0, 4);
                Offsets[i] = BitConverter.ToUInt32(_u32, 0) * 0x200;
                ncsdStream.Read(_u32, 0, 4);
                Sizes[i] = BitConverter.ToUInt32(_u32, 0) * 0x200;
            }

            for (int i = 0; i < 8; i++)
            {
                if (Sizes[i] > 0)
                {
                    ncsdStream.Seek(Offsets[i], SeekOrigin.Begin);
                    ValidateNCCH(ncsdStream);
                }
            }
            ncsdStream.Seek(0, SeekOrigin.Begin);
        }

        private static void ValidateNCCH(Stream ncchStream, bool exheader = true, bool exefs = true, bool romfs = true)
        {
            long startOffset = ncchStream.Position;

            byte[] ExheaderHash = new byte[0x20];
            byte[] ExeFSHash = new byte[0x20];
            byte[] RomFSHash = new byte[0x20];

            byte[] _u32 = new byte[4];
            ncchStream.Seek(0x100, SeekOrigin.Current);
            ncchStream.Read(_u32, 0, 4);
            string magic = new string(_u32.Select(b => (char)b).ToArray());
            if (magic != "NCCH")
                throw new ArgumentException("Passed stream isn't an NCCH!");
            ncchStream.Seek(0x5C, SeekOrigin.Current);
            ncchStream.Read(ExheaderHash, 0, ExheaderHash.Length);
            ncchStream.Read(_u32, 0, 4);
            uint ExheaderSize = BitConverter.ToUInt32(_u32, 0);
            ncchStream.Seek(0x1C, SeekOrigin.Current);
            ncchStream.Read(_u32, 0, 4);
            long ExeFSOffset = BitConverter.ToUInt32(_u32, 0) * 0x200;
            ncchStream.Seek(4, SeekOrigin.Current);
            ncchStream.Read(_u32, 0, 4);
            uint ExeFSHashSize = BitConverter.ToUInt32(_u32, 0) * 0x200;
            ncchStream.Seek(4, SeekOrigin.Current);
            ncchStream.Read(_u32, 0, 4);
            long RomFSOffset = BitConverter.ToUInt32(_u32, 0) * 0x200;
            ncchStream.Seek(4, SeekOrigin.Current);
            ncchStream.Read(_u32, 0, 4);
            uint RomFSHashSize = BitConverter.ToUInt32(_u32, 0) * 0x200;
            ncchStream.Seek(4, SeekOrigin.Current);
            ncchStream.Read(ExeFSHash, 0, ExeFSHash.Length);
            ncchStream.Read(RomFSHash, 0, RomFSHash.Length);
            if (exheader && ExheaderSize > 0)
            {
                ncchStream.Seek(startOffset + 0x200, SeekOrigin.Begin);
                byte[] Exheader = new byte[ExheaderSize];
                ncchStream.Read(Exheader, 0, Exheader.Length);
                CollectionAssert.AreEqual((new SHA256Managed()).ComputeHash(Exheader), ExheaderHash);
            }
            if (exefs && ExeFSHashSize > 0)
            {
                ncchStream.Seek(startOffset + ExeFSOffset, SeekOrigin.Begin);
                byte[] ExefsHashRegion = new byte[ExeFSHashSize];
                ncchStream.Read(ExefsHashRegion, 0, ExefsHashRegion.Length);
                CollectionAssert.AreEqual((new SHA256Managed()).ComputeHash(ExefsHashRegion), ExeFSHash);
            }
            if (romfs && RomFSHashSize > 0)
            {
                ncchStream.Seek(startOffset + RomFSOffset, SeekOrigin.Begin);
                byte[] RomfsHashRegion = new byte[RomFSHashSize];
                ncchStream.Read(RomfsHashRegion, 0, RomfsHashRegion.Length);
                CollectionAssert.AreEqual((new SHA256Managed()).ComputeHash(RomfsHashRegion), RomFSHash);
            }
            ncchStream.Seek(startOffset, SeekOrigin.Begin);
        }
    }
}
