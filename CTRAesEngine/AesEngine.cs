using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

using Security.Cryptography;

namespace CTR
{
    public enum AesMode
    {
        CCM = 0,
        CTR = 1,
        CBC = 2,
        ECB = 3
    }
    public class AesEngine
    {
        private byte[][] KeyXs;
        private byte[][] KeyYs;

        private byte[][] NormalKeys;

        private byte[] CTR_IV_NONCE;

        private byte[] MAC;

        private AesMode Mode;

        private int Slot;

        public AesEngine()
        {
            KeyXs = new byte[0x40][];
            KeyYs = new byte[0x40][];
            NormalKeys = new byte[0x40][];

            CTR_IV_NONCE = new byte[0x10];
            MAC = new byte[0x10];

            for (int i = 0; i < NormalKeys.Length; i++)
            {
                KeyXs[i] = new byte[0x10];
                KeyYs[i] = new byte[0x10];
                NormalKeys[i] = new byte[0x10];
            }

            InitializeKeyslots();
            Slot = 0;
        }

        public byte[] Encrypt(byte[] input)
        {
            byte[] output = new byte[input.Length];

            byte[] key = (byte[])(NormalKeys[Slot].Clone());
            byte[] ctr_iv_nonce = new byte[0x10];
            CTR_IV_NONCE.CopyTo(ctr_iv_nonce, 0);

            switch (Mode)
            {
                case AesMode.CCM:
                    byte[] nonce = ctr_iv_nonce.Take(0xC).ToArray();
                    using (var _aes = new AuthenticatedAesCng { Key = key, IV = nonce, CngMode = CngChainingMode.Ccm, Padding = PaddingMode.None })
                    {
                        using (var encryptor = _aes.CreateAuthenticatedEncryptor())
                        using (CryptoStream cs = new CryptoStream(new MemoryStream(output), encryptor, CryptoStreamMode.Write))
                        {
                            cs.Write(input, 0, input.Length);
                            cs.FlushFinalBlock();
                            SetMAC(encryptor.GetTag());
                        }
                    }
                    break;
                case AesMode.CBC:
                    using (var _aes = new AesManaged { Key = key, IV = ctr_iv_nonce, Mode = CipherMode.CBC, Padding = PaddingMode.None })
                    {
                        _aes.CreateEncryptor(_aes.Key, _aes.IV).TransformBlock(input, 0, input.Length, output, 0);
                    }
                    break;
                case AesMode.CTR:
                    using (var _aes = new AesCtr(ctr_iv_nonce))
                    {
                        _aes.CreateEncryptor(key).TransformBlock(input, 0, input.Length, output, 0);
                    }
                    break;
                case AesMode.ECB:
                    using (var _aes = new AesManaged {Key = key, IV = ctr_iv_nonce, Mode = CipherMode.ECB, Padding = PaddingMode.None})
                    {
                        _aes.CreateEncryptor(_aes.Key, _aes.IV).TransformBlock(input, 0, input.Length, output, 0);
                    }
                    break;
            }
            return output;
        }

        public void Encrypt(Stream inStream, Stream outStream, long count)
        {
            byte[] key = (byte[])(NormalKeys[Slot].Clone());
            byte[] ctr_iv_nonce = new byte[0x10];
            CTR_IV_NONCE.CopyTo(ctr_iv_nonce, 0);
            switch (Mode)
            {
                case AesMode.CCM:
                    byte[] nonce = ctr_iv_nonce.Take(0xC).ToArray();
                    using (var _aes = new AuthenticatedAesCng { Key = key, IV = nonce, CngMode = CngChainingMode.Ccm, Padding = PaddingMode.None })
                    {
                        using (var encryptor = _aes.CreateAuthenticatedEncryptor())
                        {
                            byte[] inBuf;
                            byte[] outBuf;
                            while (count > 0)
                            {
                                inBuf = new byte[count > 0x100000 ? 0x100000 : count];
                                outBuf = new byte[count > 0x100000 ? 0x100000 : count];
                                inStream.Read(inBuf, 0, inBuf.Length);
                                encryptor.TransformBlock(inBuf, 0, inBuf.Length, outBuf, 0);
                                outStream.Write(outBuf, 0, outBuf.Length);
                                count -= inBuf.Length;
                            }
                            SetMAC(encryptor.GetTag());
                        }
                    }
                    break;
                case AesMode.CBC:
                    using (var _aes = new AesManaged { Key = key, IV = ctr_iv_nonce, Mode = CipherMode.CBC, Padding = PaddingMode.None })
                    {
                        using (var encryptor = _aes.CreateEncryptor(_aes.Key, _aes.IV))
                        {
                            byte[] inBuf;
                            byte[] outBuf;
                            while (count > 0)
                            {
                                inBuf = new byte[count > 0x100000 ? 0x100000 : count];
                                outBuf = new byte[count > 0x100000 ? 0x100000 : count];
                                inStream.Read(inBuf, 0, inBuf.Length);
                                encryptor.TransformBlock(inBuf, 0, inBuf.Length, outBuf, 0);
                                outStream.Write(outBuf, 0, outBuf.Length);
                                count -= inBuf.Length;
                            }
                        }
                    }
                    break;
                case AesMode.CTR:
                    using (var _aes = new AesCtr(ctr_iv_nonce))
                    {
                        using (var encryptor = _aes.CreateEncryptor(key))
                        {
                            byte[] inBuf;
                            byte[] outBuf;
                            while (count > 0)
                            {
                                inBuf = new byte[count > 0x100000 ? 0x100000 : count];
                                outBuf = new byte[count > 0x100000 ? 0x100000 : count];
                                inStream.Read(inBuf, 0, inBuf.Length);
                                encryptor.TransformBlock(inBuf, 0, inBuf.Length, outBuf, 0);
                                outStream.Write(outBuf, 0, outBuf.Length);
                                count -= inBuf.Length;
                            }
                        }
                    }
                    break;
                case AesMode.ECB:
                    using (var _aes = new AesManaged { Key = key, IV = ctr_iv_nonce, Mode = CipherMode.ECB, Padding = PaddingMode.None })
                    {
                        using (var encryptor = _aes.CreateEncryptor(key, _aes.IV))
                        {
                            byte[] inBuf;
                            byte[] outBuf;
                            while (count > 0)
                            {
                                inBuf = new byte[count > 0x100000 ? 0x100000 : count];
                                outBuf = new byte[count > 0x100000 ? 0x100000 : count];
                                inStream.Read(inBuf, 0, inBuf.Length);
                                encryptor.TransformBlock(inBuf, 0, inBuf.Length, outBuf, 0);
                                outStream.Write(outBuf, 0, outBuf.Length);
                                count -= inBuf.Length;
                            }
                        }
                    }
                    break;
            }
        }

        public byte[] Decrypt(byte[] input)
        {
            byte[] output = new byte[input.Length];

            byte[] key = (byte[])(NormalKeys[Slot].Clone());
            byte[] ctr_iv_nonce = new byte[0x10];
            CTR_IV_NONCE.CopyTo(ctr_iv_nonce, 0);

            switch (Mode)
            {
                case AesMode.CCM:
                    byte[] nonce = ctr_iv_nonce.Take(0xC).ToArray();
                    using (var _aes = new AuthenticatedAesCng { Key = key, IV = nonce, Tag = GetMAC(), CngMode = CngChainingMode.Ccm, Padding = PaddingMode.None})
                    {
                        using (CryptoStream cs = new CryptoStream(new MemoryStream(output), _aes.CreateAuthenticatedEncryptor(), CryptoStreamMode.Write))
                        {
                            cs.Write(input, 0, input.Length);
                            cs.FlushFinalBlock();
                        }
                    }
                    break;
                case AesMode.CBC:
                    using (var _aes = new AesManaged { Key = key, IV = ctr_iv_nonce, Mode = CipherMode.CBC, Padding = PaddingMode.None })
                    {
                        _aes.CreateDecryptor(_aes.Key, _aes.IV).TransformBlock(input, 0, input.Length, output, 0);
                    }
                    break;
                case AesMode.CTR:
                    using (var _aes = new AesCtr(ctr_iv_nonce))
                    {
                        _aes.CreateDecryptor(key).TransformBlock(input, 0, input.Length, output, 0);
                    }
                    break;
                case AesMode.ECB:
                    using (var _aes = new AesManaged { Key = key, IV = ctr_iv_nonce, Mode = CipherMode.ECB, Padding = PaddingMode.None })
                    {
                        _aes.CreateDecryptor(_aes.Key, _aes.IV).TransformBlock(input, 0, input.Length, output, 0);
                    }
                    break;
            }

            return output;
        }

        public void Decrypt(Stream inStream, Stream outStream, long count)
        {
            byte[] key = (byte[])(NormalKeys[Slot].Clone());
            byte[] ctr_iv_nonce = new byte[0x10];
            CTR_IV_NONCE.CopyTo(ctr_iv_nonce, 0);
            switch (Mode)
            {
                case AesMode.CCM:
                    byte[] nonce = ctr_iv_nonce.Take(0xC).ToArray();
                    using (var _aes = new AuthenticatedAesCng { Key = key, IV = nonce, Tag = GetMAC(), CngMode = CngChainingMode.Ccm, Padding = PaddingMode.None })
                    {
                        using (var decryptor = _aes.CreateAuthenticatedEncryptor())
                        {
                            byte[] inBuf;
                            byte[] outBuf;
                            while (count > 0)
                            {
                                inBuf = new byte[count > 0x100000 ? 0x100000 : count];
                                outBuf = new byte[count > 0x100000 ? 0x100000 : count];
                                inStream.Read(inBuf, 0, inBuf.Length);
                                decryptor.TransformBlock(inBuf, 0, inBuf.Length, outBuf, 0);
                                outStream.Write(outBuf, 0, outBuf.Length);
                                count -= inBuf.Length;
                            }
                        }
                    }
                    break;
                case AesMode.CBC:
                    using (var _aes = new AesManaged { Key = key, IV = ctr_iv_nonce, Mode = CipherMode.CBC, Padding = PaddingMode.None })
                    {
                        using (var decryptor = _aes.CreateDecryptor(_aes.Key, _aes.IV))
                        {
                            byte[] inBuf;
                            byte[] outBuf;
                            while (count > 0)
                            {
                                inBuf = new byte[count > 0x100000 ? 0x100000 : count];
                                outBuf = new byte[count > 0x100000 ? 0x100000 : count];
                                inStream.Read(inBuf, 0, inBuf.Length);
                                decryptor.TransformBlock(inBuf, 0, inBuf.Length, outBuf, 0);
                                outStream.Write(outBuf, 0, outBuf.Length);
                                count -= inBuf.Length;
                            }
                        }
                    }
                    break;
                case AesMode.CTR:
                    using (var _aes = new AesCtr(ctr_iv_nonce))
                    {
                        using (var decryptor = _aes.CreateDecryptor(key))
                        {
                            byte[] inBuf;
                            byte[] outBuf;
                            while (count > 0)
                            {
                                inBuf = new byte[count > 0x100000 ? 0x100000 : count];
                                outBuf = new byte[count > 0x100000 ? 0x100000 : count];
                                inStream.Read(inBuf, 0, inBuf.Length);
                                decryptor.TransformBlock(inBuf, 0, inBuf.Length, outBuf, 0);
                                outStream.Write(outBuf, 0, outBuf.Length);
                                count -= inBuf.Length;
                            }
                        }
                    }
                    break;
                case AesMode.ECB:
                    using (var _aes = new AesManaged { Key = key, IV = ctr_iv_nonce, Mode = CipherMode.ECB, Padding = PaddingMode.None })
                    {
                        using (var decryptor = _aes.CreateDecryptor(key, _aes.IV))
                        {
                            byte[] inBuf;
                            byte[] outBuf;
                            while (count > 0)
                            {
                                inBuf = new byte[count > 0x100000 ? 0x100000 : count];
                                outBuf = new byte[count > 0x100000 ? 0x100000 : count];
                                inStream.Read(inBuf, 0, inBuf.Length);
                                decryptor.TransformBlock(inBuf, 0, inBuf.Length, outBuf, 0);
                                outStream.Write(outBuf, 0, outBuf.Length);
                                count -= inBuf.Length;
                            }
                        }
                    }
                    break;
            }
        }

        public void SelectKeyslot(int keyslot)
        {
            if (keyslot < 0 || keyslot >= 0x40)
                throw new ArgumentException("Invalid keyslot selected. Must be in range [0, 0x40).");
            Slot = keyslot;
        }

        public void SetMode(AesMode m)
        {
            Mode = m;
        }

        public void SetCTR(byte[] ctr)
        {
            if (ctr.Length != 0x10)
                return;
            ctr.CopyTo(CTR_IV_NONCE, 0);
        }

        public void SetCTR(ulong high, ulong low)
        {
            BitConverter.GetBytes(high).Reverse().ToArray().CopyTo(CTR_IV_NONCE, 0);
            BitConverter.GetBytes(low).Reverse().ToArray().CopyTo(CTR_IV_NONCE, 8);
        }

        public void SetIV(byte[] iv)
        {
            if (iv.Length != 0x10)
                return;
            iv.CopyTo(CTR_IV_NONCE, 0);
        }

        public void SetNonce(byte[] nonce)
        {
            if (nonce.Length != 0xC)
                return;
            byte[] n = new byte[0x10];
            nonce.CopyTo(n, 0);
            n.CopyTo(CTR_IV_NONCE, 0);
        }

        public void SetMAC(byte[] mac)
        {
            if (mac.Length != 0x10)
                return;
            mac.CopyTo(MAC, 0);
        }

        public byte[] GetMAC()
        {
            return (byte[])MAC.Clone();
        }

        public void SetKeyX(int keyslot, byte[] key)
        {
            if (key.Length != 0x10)
                return;
            key.CopyTo(KeyXs[keyslot], 0);
            if (keyslot <= 3)
                KeyScrambler.GetDSINormalKey(KeyXs[keyslot], KeyYs[keyslot]).CopyTo(NormalKeys[keyslot], 0);
            else
                KeyScrambler.GetNormalKey(KeyXs[keyslot], KeyYs[keyslot]).CopyTo(NormalKeys[keyslot], 0);
        }

        public void SetKeyX(byte[] key)
        {
            if (key.Length != 0x10)
                return;
            key.CopyTo(KeyXs[Slot], 0);
            if (Slot <= 3)
                KeyScrambler.GetDSINormalKey(KeyXs[Slot], KeyYs[Slot]).CopyTo(NormalKeys[Slot], 0);
            else
                KeyScrambler.GetNormalKey(KeyXs[Slot], KeyYs[Slot]).CopyTo(NormalKeys[Slot], 0);
        }

        public void SetKeyY(int keyslot, byte[] key)
        {
            if (key.Length != 0x10)
                return;
            key.CopyTo(KeyYs[keyslot], 0);
            if (keyslot <= 3)
                KeyScrambler.GetDSINormalKey(KeyXs[keyslot], KeyYs[keyslot]).CopyTo(NormalKeys[keyslot], 0);
            else
                KeyScrambler.GetNormalKey(KeyXs[keyslot], KeyYs[keyslot]).CopyTo(NormalKeys[keyslot], 0);
        }

        public void SetKeyY(byte[] key)
        {
            if (key.Length != 0x10)
                return;
            key.CopyTo(KeyYs[Slot], 0);
            if (Slot <= 3)
                KeyScrambler.GetDSINormalKey(KeyXs[Slot], KeyYs[Slot]).CopyTo(NormalKeys[Slot], 0);
            else
                KeyScrambler.GetNormalKey(KeyXs[Slot], KeyYs[Slot]).CopyTo(NormalKeys[Slot], 0);
        }

        public void SetNormalKey(int keyslot, byte[] key)
        {
            if (key.Length != 0x10)
                return;
            key.CopyTo(NormalKeys[keyslot], 0);
        }
        public void SetNormalKey(byte[] key)
        {
            if (key.Length != 0x10)
                return;
            key.CopyTo(NormalKeys[Slot], 0);
        }

        public void InitializeKeyslots()
        {
            // Dumb.
            LoadHardcodedKeys();

            // Soon
            /* LoadKeysFromBootrom(); */
        }

        // Temporary! Will be deleted after ARM9 Bootrom dumps appear.
        // Really just used for testing purposes.
        public void LoadHardcodedKeys()
        {
            // For legality reasons, these keys cannot be included in the public upload.
            // Insert them yourself before building, or wait for ARM9 bootrom dumps
            // and my implementation of key loading from the bootrom.
            SetKeyX(0x3, "00000000000000000000000000000000".ToByteArray());
            SetKeyY(0x3, "00000000000000000000000000000000".ToByteArray());

            SetKeyY(0x5, "00000000000000000000000000000000".ToByteArray());

            SetKeyX(0x18, "00000000000000000000000000000000".ToByteArray());
            SetKeyX(0x19, "00000000000000000000000000000000".ToByteArray());
            SetKeyX(0x1A, "00000000000000000000000000000000".ToByteArray());
            SetKeyX(0x1B, "00000000000000000000000000000000".ToByteArray());
            SetKeyX(0x1C, "00000000000000000000000000000000".ToByteArray());
            SetKeyX(0x1D, "00000000000000000000000000000000".ToByteArray());
            SetKeyX(0x1E, "00000000000000000000000000000000".ToByteArray());
            SetKeyX(0x1F, "00000000000000000000000000000000".ToByteArray());

            SetKeyX(0x25, "00000000000000000000000000000000".ToByteArray());

            SetKeyY(0x2F, "00000000000000000000000000000000".ToByteArray());

            for (int i = 0; i < 4; i++)
                SetKeyX(0x38+i, "00000000000000000000000000000000".ToByteArray());
        }

        public void LoadKeysFromBootrom()
        {
            // Implement after ARM9 Bootrom dumps appear.
            // Will use bootrom as an embedded resource.
        }

        public void LoadKeysFromBootromFile(byte[] bootrom)
        {
            // Will use LoadKeysFromBootrom() implementation for those who
            // don't want to manually compile with bootrom as a resource.
        }

        public void DecryptGameNCSD(Stream ncsdInStream, Stream ncsdOutStream)
        {
            if (ncsdInStream.Position != ncsdOutStream.Position)
                throw new ArgumentException("Instream and Outstream must be synchronized.");
            byte[] _u32 = new byte[4];
            ncsdInStream.Seek(0x100, SeekOrigin.Begin);
            ncsdInStream.Read(_u32, 0, 4);
            string magic = new string(_u32.Select(b => (char)b).ToArray());
            if (magic != "NCSD")
                throw new ArgumentException("Invalid NCSD passed to decryption method!");
            ncsdInStream.Seek(0x120, SeekOrigin.Begin);
            long[] Offsets = new long[8];
            long[] Sizes = new long[8];
            for (int i = 0; i < 8; i++)
            {
                ncsdInStream.Read(_u32, 0, 4);
                Offsets[i] = BitConverter.ToUInt32(_u32, 0) * 0x200;
                ncsdInStream.Read(_u32, 0, 4);
                Sizes[i] = BitConverter.ToUInt32(_u32, 0) * 0x200;
            }

            for (int i = 0; i < 8; i++)
            {
                if (Sizes[i] > 0)
                {
                    ncsdInStream.Seek(Offsets[i], SeekOrigin.Begin);
                    ncsdOutStream.Seek(Offsets[i], SeekOrigin.Begin);
                    DecryptNCCH(ncsdInStream, ncsdOutStream);
                }
            }
            ncsdInStream.Seek(0, SeekOrigin.Begin);
            ncsdOutStream.Seek(0, SeekOrigin.Begin);
        }

        public void DecryptNCCH(Stream ncchInStream, Stream ncchOutStream, byte[] seed = null)
        {
            var StartOffset = ncchInStream.Position;
            if (StartOffset != ncchOutStream.Position)
                throw new ArgumentException("Instream and Outstream must be synchronized.");
            byte[] NCCHKeyY = new byte[0x10];
            byte[] SeedKeyY = new byte[0x10];
            ncchInStream.Read(NCCHKeyY, 0, NCCHKeyY.Length);
            #region GetNCCHMetadata
            BinaryReader br = new BinaryReader(ncchInStream);
            br.BaseStream.Seek(0xF0, SeekOrigin.Current);
            string magic = new string(br.ReadChars(4));
            if (magic != "NCCH")
                throw new ArgumentException("Invalid NCCH passed to decryption method!");
            br.BaseStream.Seek(0x10, SeekOrigin.Current);
            uint SeedHash = br.ReadUInt32();
            ulong ProgramID = br.ReadUInt64();
            br.BaseStream.Seek(0x60, SeekOrigin.Current);
            uint ExheaderLen = br.ReadUInt32();
            br.BaseStream.Seek(4, SeekOrigin.Current);
            br.BaseStream.Seek(3, SeekOrigin.Current);
            byte CryptoMethod = br.ReadByte();
            br.BaseStream.Seek(3, SeekOrigin.Current);
            byte BitFlags = br.ReadByte();
            bool UsesFixedKey = (BitFlags & 1) > 0;
            bool UsesSeedCrypto = (BitFlags & 0x20) > 0;
            bool UsesCrypto = (BitFlags & 0x4) == 0;
            if (UsesFixedKey) // Fixed Key
            {
                byte[] zeroKey = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
                byte[] sysKey = { 0x52, 0x7C, 0xE6, 0x30, 0xA9, 0xCA, 0x30, 0x5F, 0x36, 0x96, 0xF3, 0xCD, 0xE9, 0x54, 0x19, 0x4B };
                if ((ProgramID & ((ulong)0x10 << 32)) > 0)
                    SetNormalKey(0x11, sysKey);
                else
                    SetNormalKey(0x11, zeroKey);
            }
            if (UsesSeedCrypto) // Seed Crypto
            {
                if (seed == null)
                    throw new ArgumentNullException("Seed must not be null for NCCH using seed crypto.");
                if (seed.Length != 0x10)
                    throw new ArgumentException("Content lock seeds must be 0x10 bytes long.");
                byte[] SeedCheck = new byte[0x18];
                seed.CopyTo(SeedCheck, 0);
                BitConverter.GetBytes(ProgramID).CopyTo(SeedCheck, 0x10);
                uint TestHash = BitConverter.ToUInt32((new SHA256Managed()).ComputeHash(SeedCheck), 0);
                if (TestHash != SeedHash)
                    throw new ArgumentException("Content lock seed is incorrect. Cannot decrypt NCCH.");
                byte[] SeedBuffer = new byte[0x20];
                NCCHKeyY.CopyTo(SeedBuffer, 0);
                seed.CopyTo(SeedBuffer, 0x10);
                Array.Copy((new SHA256Managed()).ComputeHash(SeedBuffer), 0, SeedKeyY, 0, 0x10);
            }
            // Assume 0x800 Exheader + AccessDesc
            br.BaseStream.Seek(0x10, SeekOrigin.Current);
            long ExeFSOffset = br.ReadUInt32() * 0x200;
            long ExeFSSize = br.ReadUInt32() * 0x200;
            br.BaseStream.Seek(8, SeekOrigin.Current);
            long RomFSOffset = br.ReadUInt32() * 0x200;
            long RomFSSize = br.ReadUInt32() * 0x200;
            #endregion

            if (UsesCrypto)
            {
                SetMode(AesMode.CTR);
                if (ExheaderLen > 0)
                {
                    ncchInStream.Seek(StartOffset + 0x200, SeekOrigin.Begin);
                    ncchOutStream.Seek(StartOffset + 0x200, SeekOrigin.Begin);
                    if (UsesFixedKey)
                        SelectKeyslot(0x11);
                    else
                    {
                        SelectKeyslot(0x2C);
                        SetKeyY(NCCHKeyY);
                    }
                    SetCTR(ProgramID, (ulong)(1) << 56);
                    Decrypt(ncchInStream, ncchOutStream, 0x800);
                }
                if (ExeFSSize > 0)
                {
                    ncchInStream.Seek(StartOffset + ExeFSOffset, SeekOrigin.Begin);
                    ncchOutStream.Seek(StartOffset + ExeFSOffset, SeekOrigin.Begin);
                    if (UsesFixedKey)
                        SelectKeyslot(0x11);
                    else
                    {
                        SelectKeyslot(0x2C);
                        SetKeyY(NCCHKeyY);
                    }
                    SetCTR(ProgramID, (ulong)(2) << 56);
                    Decrypt(ncchInStream, ncchOutStream, 0x200);
                    ncchOutStream.Seek(-0x200, SeekOrigin.Current);
                    byte[] ExeFSMeta = new byte[0x200];
                    ncchOutStream.Read(ExeFSMeta, 0, ExeFSMeta.Length);
                    for (int i = 0; i < 10; i++)
                    {
                        string file_name = Encoding.ASCII.GetString(ExeFSMeta, i * 0x10, 8);
                        uint file_ofs = BitConverter.ToUInt32(ExeFSMeta, i * 0x10 + 8) + 0x200;
                        uint file_size = BitConverter.ToUInt32(ExeFSMeta, i * 0x10 + 0xC);
                        if (file_size % 0x200 != 0)
                            file_size += (0x200 - (file_size % 0x200));
                        if (file_size == 0 || file_ofs + file_size > RomFSOffset - ExeFSOffset)
                            continue;
                        ncchInStream.Seek(StartOffset + ExeFSOffset + file_ofs, SeekOrigin.Begin);
                        ncchOutStream.Seek(StartOffset + ExeFSOffset + file_ofs, SeekOrigin.Begin);
                        if (UsesFixedKey)
                            SelectKeyslot(0x11);
                        else
                        {
                            if (file_name == "icon" || file_name == "banner")
                            {
                                SelectKeyslot(0x2C);
                                SetKeyY(NCCHKeyY);
                            }
                            else
                            {
                                switch (CryptoMethod)
                                {
                                    case 1:
                                        SelectKeyslot(0x25);
                                        break;
                                    case 0xA:
                                        SelectKeyslot(0x18);
                                        break;
                                    case 0xB:
                                        SelectKeyslot(0x1B);
                                        break;
                                    default:
                                        SelectKeyslot(0x2C);
                                        break;
                                }
                                SetKeyY(UsesSeedCrypto ? SeedKeyY : NCCHKeyY);
                            }
                        }
                        SetCTR(ProgramID, ((ulong)(2) << 56) + file_ofs / 0x10);
                        Decrypt(ncchInStream, ncchOutStream, file_size);
                    }
                }
                if (RomFSSize > 0)
                {
                    ncchInStream.Seek(StartOffset + RomFSOffset, SeekOrigin.Begin);
                    ncchOutStream.Seek(StartOffset + RomFSOffset, SeekOrigin.Begin);
                    if (UsesFixedKey)
                        SelectKeyslot(0x11);
                    else
                    {
                        switch (CryptoMethod)
                        {
                            case 1:
                                SelectKeyslot(0x25);
                                break;
                            case 0xA:
                                SelectKeyslot(0x18);
                                break;
                            case 0xB:
                                SelectKeyslot(0x1B);
                                break;
                            default:
                                SelectKeyslot(0x2C);
                                break;
                        }
                        SetKeyY(UsesSeedCrypto ? SeedKeyY : NCCHKeyY);
                    }
                    SetCTR(ProgramID, (ulong)(3) << 56);
                    Decrypt(ncchInStream, ncchOutStream, RomFSSize);
                }
            }
            ncchOutStream.Seek(StartOffset + 0x188 + 3, SeekOrigin.Begin);
            ncchOutStream.WriteByte(0);
            ncchOutStream.Seek(3, SeekOrigin.Current);
            ncchOutStream.WriteByte((byte)((BitFlags & ((0x1 | 0x20) ^ 0xFF)) | 0x4));

            ncchInStream.Seek(StartOffset, SeekOrigin.Begin);
            ncchOutStream.Seek(StartOffset, SeekOrigin.Begin);
            // And we're done.
        }
    }
    public static class StringExtentions
    {
        public static byte[] ToByteArray(this string toTransform)
        {
            return Enumerable
                .Range(0, toTransform.Length / 2)
                .Select(i => Convert.ToByte(toTransform.Substring(i * 2, 2), 16))
                .ToArray();
        }
    }
}
