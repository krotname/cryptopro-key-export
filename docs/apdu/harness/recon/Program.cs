using System;
using System.Collections.Generic;
using System.Text;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;

// Реконструкция d неэкспортируемого контейнера jcrec на JaCarta PRO.
// Файлы сняты нативным winscard-прокси; primary.key = SEQUENCE{ OCTET STRING A(32), [0] B(32) }.
// Задача: разобрать поле [0](32) и восстановить d, сверив d·G.X с открытым ключом (оракул).

class Program
{
    static byte[] H(string s) {
        var b = new byte[s.Length / 2];
        for (int i = 0; i < b.Length; i++) b[i] = Convert.ToByte(s.Substring(i * 2, 2), 16);
        return b;
    }

    static void Main()
    {
        // Захвачено нативным прокси (keycopy jcrec, ключ обмена, путь CC02):
        byte[] A    = H("862AC34030C354B2E2A44D73EA2CE85777E5E572BC7529C35606A5460F8C9926"); // primary OCTET STRING
        byte[] B    = H("AD82E59817586BF07CE6C7B6E0747FBEF929499E637CCC6C338C3A25AFC7FAF5"); // primary [0]
        byte[] mask = H("4593BDF74EB85BBD098B18ECFB96D8EAEC77A1C6C63C44B4525BFF9B5EA175BC"); // masks.key маска
        byte[] salt = H("B7AEDC5CE28B33A9D1F9E67E");                                         // masks.key соль KDF
        // Оракул: открытый ключ обмена (csptest -export), X‖Y little-endian.
        byte[] Xle  = H("DCDB2B4F53DEA2A989BC5595B47F5208F35EACC97792D0DD08B56B45FDE1CDD1");
        string curveOid = "1.2.643.2.2.36.0";

        var domain = ECGost3410NamedCurves.GetByOid(new DerObjectIdentifier(curveOid));
        BigInteger q = domain.N;
        BigInteger targetX = new BigInteger(1, Rev(Xle)); // X big-endian как число

        Console.WriteLine($"curve={curveOid} q_bits={q.BitLength}");
        Console.WriteLine($"targetX={Hex(Pad32(targetX))}");

        foreach (string pwd in new[] { "1122", "" })
        {
            byte[] sk = DeriveStorageKey(pwd, salt);
            byte[] Adec = EcbDecrypt(sk, A);
            byte[] Bdec = EcbDecrypt(sk, B);
            byte[] AB = new byte[64]; Array.Copy(A, 0, AB, 0, 32); Array.Copy(B, 0, AB, 32, 32);
            byte[] ABdec = EcbDecrypt(sk, AB);
            byte[] ABdec0 = Sub(ABdec, 0, 32), ABdec1 = Sub(ABdec, 32, 32);

            // кандидаты 32-байтовых значений (как little-endian числа mod q)
            var vals = new Dictionary<string, BigInteger>
            {
                ["A"]      = Num(A, q),
                ["Adec"]   = Num(Adec, q),
                ["B"]      = Num(B, q),
                ["Bdec"]   = Num(Bdec, q),
                ["mask"]   = Num(mask, q),
                ["ABdec0"] = Num(ABdec0, q),
                ["ABdec1"] = Num(ABdec1, q),
            };

            // формулы: d = f(u,v). Проверяем все пары и одиночные.
            foreach (var u in vals)
            {
                // одиночное: d = u
                Check(pwd, $"d={u.Key}", u.Value, domain, targetX, q);
                foreach (var v in vals)
                {
                    if (v.Value.SignValue == 0) continue;
                    BigInteger vinv = v.Value.ModInverse(q);
                    Check(pwd, $"d={u.Key}*{v.Key}^-1", u.Value.Multiply(vinv).Mod(q), domain, targetX, q);
                    Check(pwd, $"d={u.Key}*{v.Key}",     u.Value.Multiply(v.Value).Mod(q), domain, targetX, q);
                }
            }
            // тройные: d = u * m1^-1 * m2^-1 (две маски: mask и B/Bdec)
            foreach (var uKey in new[] { "Adec", "Bdec", "ABdec0", "ABdec1" })
            {
                BigInteger u = vals[uKey];
                foreach (var m1 in new[] { "mask" })
                foreach (var m2 in new[] { "B", "Bdec" })
                {
                    if (vals[m1].SignValue == 0 || vals[m2].SignValue == 0) continue;
                    BigInteger d = u.Multiply(vals[m1].ModInverse(q)).Multiply(vals[m2].ModInverse(q)).Mod(q);
                    Check(pwd, $"d={uKey}*{m1}^-1*{m2}^-1", d, domain, targetX, q);
                    BigInteger d2 = u.Multiply(vals[m1].ModInverse(q)).Multiply(vals[m2]).Mod(q);
                    Check(pwd, $"d={uKey}*{m1}^-1*{m2}", d2, domain, targetX, q);
                }
            }
        }
        Console.WriteLine("=== перебор завершён ===");

        // --- полная сверка найденного d и анализ поля A (пустой пароль) ---
        Console.WriteLine("\n=== проверка d = decrypt(B)·mask^-1 (пустой пароль) и роль A ===");
        byte[] sk0 = DeriveStorageKey("", salt);
        BigInteger m = Num(mask, q);
        BigInteger dd = Num(EcbDecrypt(sk0, B), q).Multiply(m.ModInverse(q)).Mod(q);
        ECPoint pub2 = domain.G.Multiply(dd).Normalize();
        byte[] xr = Pad32(pub2.AffineXCoord.ToBigInteger());
        byte[] yr = Pad32(pub2.AffineYCoord.ToBigInteger());
        byte[] Yle = H("17A134D981ED22EBA19BDC104D15CB514F3E7839E1723F105A1BD8B859608D32");
        Console.WriteLine($"d       = {Hex(Pad32(dd))}");
        Console.WriteLine($"d·G.X   = {Hex(xr)}");
        Console.WriteLine($"Q.X     = {Hex(Rev(Xle))}   совпало={Hex(xr)==Hex(Rev(Xle))}");
        Console.WriteLine($"d·G.Y   = {Hex(yr)}");
        Console.WriteLine($"Q.Y     = {Hex(Rev(Yle))}   совпало={Hex(yr)==Hex(Rev(Yle))}");

        // Роль A: что даёт decrypt(A)? сравним с d, mask, X, Y, и с decrypt(B).
        byte[] Adec0 = EcbDecrypt(sk0, A);
        byte[] Bdec0 = EcbDecrypt(sk0, B);
        Console.WriteLine($"\ndecrypt(A) (LE-hex сырой) = {Hex(Adec0)}");
        Console.WriteLine($"decrypt(B) (LE-hex сырой) = {Hex(Bdec0)}");
        BigInteger aNum = Num(Adec0, q), bNum = Num(Bdec0, q);
        Console.WriteLine($"decrypt(A)·mask^-1 mod q = {Hex(Pad32(aNum.Multiply(m.ModInverse(q)).Mod(q)))}");
        Console.WriteLine($"decrypt(A)·decrypt(B)^-1 = {Hex(Pad32(aNum.Multiply(bNum.ModInverse(q)).Mod(q)))}");
        Console.WriteLine($"decrypt(B)·decrypt(A)^-1 = {Hex(Pad32(bNum.Multiply(aNum.ModInverse(q)).Mod(q)))}");
        // Проверим гипотезу «A — зашифрованный ключ под маской d·A = что-то»: A как точка? нет.
        // Проверим: даёт ли decrypt(A) публичную X (т.е. A хранит открытый ключ)?
        Console.WriteLine($"decrypt(A)==Q.X_le? {Hex(Adec0)==Hex(Xle)}   decrypt(A)==Q.Y_le? {Hex(Adec0)==Hex(Yle)}");

        // --- то же на удалённом контейнере jcnx (байты из APDU-трассы keycopy), оракул — отпечаток header.key ---
        Console.WriteLine("\n=== jcnx (удалён; проверка по 8-байтовому отпечатку X из header.key) ===");
        byte[] Bx   = H("EED9A5789F642A1A1ABD03CFB136FCF7D646020AEA333E1437D97C70347CE2AB"); // primary [0]
        byte[] mkx  = H("ADF4166647178A023958F128EE9A3102133C0168946B217E22E556ED2981AD7F"); // masks.key маска
        byte[] sx   = H("13368456DE015B3FCFF62D82");                                         // masks.key соль
        byte[] fpEx = H("0AA12D0B7A9FDE24");                                                 // header.key тег 8B: X_le[0..8] обменного ключа
        byte[] skx = DeriveStorageKey("", sx);
        BigInteger dx = Num(EcbDecrypt(skx, Bx), q).Multiply(Num(mkx, q).ModInverse(q)).Mod(q);
        ECPoint pubx = domain.G.Multiply(dx).Normalize();
        byte[] xLe = Rev(Pad32(pubx.AffineXCoord.ToBigInteger()));
        byte[] fpGot = Sub(xLe, 0, 8);
        Console.WriteLine($"jcnx d     = {Hex(Pad32(dx))}");
        Console.WriteLine($"X_le[0..8] = {Hex(fpGot)}   отпечаток header = {Hex(fpEx)}   совпало={Hex(fpGot)==Hex(fpEx)}");
    }

    static void Check(string pwd, string recipe, BigInteger d, X9ECParameters domain, BigInteger targetX, BigInteger q)
    {
        if (d.SignValue == 0) return;
        ECPoint pub = domain.G.Multiply(d).Normalize();
        if (pub.IsInfinity) return;
        BigInteger x = pub.AffineXCoord.ToBigInteger();
        if (x.Equals(targetX))
        {
            Console.WriteLine($"*** СОВПАЛО ***  pwd='{pwd}'  {recipe}");
            Console.WriteLine($"    d = {Hex(Pad32(d))}");
        }
    }

    // ---- number helpers ----
    static BigInteger Num(byte[] le, BigInteger q) => new BigInteger(1, Rev(le)).Mod(q);
    static byte[] Rev(byte[] a) { var r = (byte[])a.Clone(); Array.Reverse(r); return r; }
    static byte[] Sub(byte[] a, int off, int len) { var r = new byte[len]; Array.Copy(a, off, r, 0, len); return r; }
    static string Hex(byte[] b) { var sb = new StringBuilder(); foreach (var x in b) sb.Append(x.ToString("X2")); return sb.ToString(); }
    static byte[] Pad32(BigInteger v) { byte[] b = v.ToByteArrayUnsigned(); if (b.Length == 32) return b; var r = new byte[32]; Array.Copy(b, 0, r, 32 - b.Length, b.Length); return r; }

    // ================= ГОСТ-примитивы (по ContainerKeyExtractor соседней ветки) =================
    static readonly byte[][] ParamZRows =
    {
        new byte[] { 0x1,0x7,0xe,0xd,0x0,0x5,0x8,0x3,0x4,0xf,0xa,0x6,0x9,0xc,0xb,0x2 },
        new byte[] { 0x8,0xe,0x2,0x5,0x6,0x9,0x1,0xc,0xf,0x4,0xb,0x0,0xd,0xa,0x3,0x7 },
        new byte[] { 0x5,0xd,0xf,0x6,0x9,0x2,0xc,0xa,0xb,0x7,0x8,0x1,0x4,0x3,0xe,0x0 },
        new byte[] { 0x7,0xf,0x5,0xa,0x8,0x1,0x6,0xd,0x0,0x9,0x3,0xe,0xb,0x4,0x2,0xc },
        new byte[] { 0xc,0x8,0x2,0x1,0xd,0x4,0xf,0x6,0x7,0x0,0xa,0x5,0x3,0xe,0x9,0xb },
        new byte[] { 0xb,0x3,0x5,0x8,0x2,0xf,0xa,0xd,0xe,0x1,0x7,0x4,0xc,0x9,0x6,0x0 },
        new byte[] { 0x6,0x8,0x2,0x3,0x9,0xa,0x5,0xc,0x1,0xe,0x4,0x7,0xb,0xd,0x0,0xf },
        new byte[] { 0xc,0x4,0x6,0x2,0xa,0x5,0xb,0x9,0xe,0x8,0xd,0x7,0x0,0x3,0xf,0x1 },
    };
    const string CpkdfSeed = "DENEFH028.760246785.IUEFHWUIO.EF";
    static readonly byte[] ParamZSBox = Flatten(ParamZRows);
    static byte[] Flatten(byte[][] rows) { var r = new byte[128]; for (int i = 0; i < 8; i++) Array.Copy(rows[7 - i], 0, r, i * 16, 16); return r; }

    static byte[] Streebog256(params byte[][] parts)
    {
        var d = new Gost3411_2012_256Digest();
        foreach (var p in parts) d.BlockUpdate(p, 0, p.Length);
        var o = new byte[d.GetDigestSize()]; d.DoFinal(o, 0); return o;
    }
    static byte[] EcbDecrypt(byte[] key, byte[] data)
    {
        var e = new Gost28147Engine();
        e.Init(false, new ParametersWithSBox(new KeyParameter(key), ParamZSBox));
        var o = new byte[data.Length];
        for (int i = 0; i < data.Length; i += 8) e.ProcessBlock(data, i, o, i);
        return o;
    }
    static byte[] DeriveStorageKey(string password, byte[] salt)
    {
        const int bs = 64;
        byte[] pwdSparse = Sparse(Encoding.UTF8.GetBytes(password ?? ""));
        int iterations = pwdSparse.Length == 0 ? 2 : 2000;
        byte[] hash = Streebog256(salt, pwdSparse);
        byte[] c = Pad(Encoding.ASCII.GetBytes(CpkdfSeed), bs);
        for (int i = 0; i < iterations; i++) c = Pad(Streebog256(Xor(c, 0x36), hash, Xor(c, 0x5C), hash), bs);
        c = Streebog256(Slice(Xor(c, 0x36), 32), salt, Slice(Xor(c, 0x5C), 32), pwdSparse);
        return Streebog256(Slice(Pad(c, bs), 32));
    }
    static byte[] Sparse(byte[] p) { var b = new byte[p.Length * 4]; for (int i = 0; i < p.Length; i++) b[i * 4] = p[i]; return b; }
    static byte[] Pad(byte[] a, int len) { if (a.Length >= len) return a; var r = new byte[len]; Array.Copy(a, r, a.Length); return r; }
    static byte[] Xor(byte[] a, byte v) { var r = new byte[a.Length]; for (int i = 0; i < a.Length; i++) r[i] = (byte)(a[i] ^ v); return r; }
    static byte[] Slice(byte[] a, int len) { var r = new byte[len]; Array.Copy(a, r, Math.Min(len, a.Length)); return r; }
}
