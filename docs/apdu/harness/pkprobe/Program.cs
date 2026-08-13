using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;

// PKCS#11 private-key APDU trace host for Rutoken ECP 3.0.
// Preloads the proxy winscard.dll so rtPKCS11ECP's winscard import binds to it
// (a .NET apphost hardens the DLL search path, so plain app-local placement is bypassed).
//
//   pkprobe <slotIndex> <pin> <proxy-winscard-path>
//
// Generates a GOST R 34.10-2012-256 key pair ON the token (CKA_EXTRACTABLE=false),
// then exercises every operation that could reveal the private key:
//   - read CKA_VALUE      (expect refusal)
//   - C_Sign a 32-byte digest (expect success: proves the key is USABLE on-card)
//   - C_WrapKey           (expect CKR_KEY_NOT_WRAPPABLE)
// Finally destroys its own key pair. All traffic is captured by the preloaded proxy.
class P
{
    static int Main(string[] a)
    {
        if (a.Length < 3) { Console.Error.WriteLine("usage: pkprobe <slotIndex> <pin> <proxy-winscard-path>"); return 2; }
        int slotIndex = int.Parse(a[0]);
        string pin = a[1];
        string proxy = a[2];

        IntPtr h = NativeLibrary.Load(proxy);
        Console.WriteLine($"# preloaded proxy winscard: {proxy} -> 0x{h.ToInt64():X}");

        const string lib = @"C:\Windows\System32\rtPKCS11ECP.dll";
        const string prefix = "cpxapdu-";
        var f = new Pkcs11InteropFactories();
        using IPkcs11Library p11 = f.Pkcs11LibraryFactory.LoadPkcs11Library(f, lib, AppType.MultiThreaded);
        var slots = p11.GetSlotList(SlotsType.WithTokenPresent);
        ISlot slot = slots[slotIndex - 1];
        ITokenInfo ti = slot.GetTokenInfo();
        Console.WriteLine($"# slot {slot.SlotId}: model='{ti.Model.Trim()}' serial='{ti.SerialNumber.Trim()}' fw={ti.FirmwareVersion}");

        var af = f.ObjectAttributeFactory;
        using ISession s = slot.OpenSession(SessionType.ReadWrite);
        s.Login(CKU.CKU_USER, pin);
        Console.WriteLine("C_Login(CKU_USER): OK");

        byte[] id = System.Text.Encoding.ASCII.GetBytes(prefix + "key");
        var pubT = new List<IObjectAttribute>
        {
            af.Create(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY),
            af.Create(CKA.CKA_KEY_TYPE, (ulong)CKK.CKK_GOSTR3410),
            af.Create(CKA.CKA_TOKEN, true),
            af.Create(CKA.CKA_PRIVATE, false),
            af.Create(CKA.CKA_LABEL, prefix + "key"),
            af.Create(CKA.CKA_ID, id),
            af.Create(CKA.CKA_GOSTR3410_PARAMS, new byte[] { 0x06, 0x09, 0x2A, 0x85, 0x03, 0x07, 0x01, 0x02, 0x01, 0x01, 0x01 }),
            af.Create(CKA.CKA_GOSTR3411_PARAMS, new byte[] { 0x06, 0x08, 0x2A, 0x85, 0x03, 0x07, 0x01, 0x01, 0x02, 0x02 }),
        };
        var privT = new List<IObjectAttribute>
        {
            af.Create(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY),
            af.Create(CKA.CKA_KEY_TYPE, (ulong)CKK.CKK_GOSTR3410),
            af.Create(CKA.CKA_TOKEN, true),
            af.Create(CKA.CKA_PRIVATE, true),
            af.Create(CKA.CKA_LABEL, prefix + "key"),
            af.Create(CKA.CKA_ID, id),
            af.Create(CKA.CKA_SENSITIVE, true),
            af.Create(CKA.CKA_EXTRACTABLE, false),
            af.Create(CKA.CKA_SIGN, true),
        };

        Console.WriteLine("\n### C_GenerateKeyPair GOST R 34.10-2012-256 (on token) ###");
        IObjectHandle pub, priv;
        using (var mech = f.MechanismFactory.Create(CKM.CKM_GOSTR3410_KEY_PAIR_GEN))
            s.GenerateKeyPair(mech, pubT, privT, out pub, out priv);
        Console.WriteLine("keypair generated");

        Console.WriteLine("\n### read public key CKA_VALUE (allowed) ###");
        try { var v = s.GetAttributeValue(pub, new List<CKA> { CKA.CKA_VALUE })[0].GetValueAsByteArray(); Console.WriteLine($"public key: {v?.Length ?? 0} bytes"); }
        catch (Exception e) { Console.WriteLine("refused: " + e.Message); }

        Console.WriteLine("\n### read private key CKA_VALUE (must refuse) ###");
        try { var v = s.GetAttributeValue(priv, new List<CKA> { CKA.CKA_VALUE })[0].GetValueAsByteArray(); Console.WriteLine($"!!! READ {v?.Length ?? 0} bytes"); }
        catch (Exception e) { Console.WriteLine("refused: " + e.Message); }

        Console.WriteLine("\n### C_Sign 32-byte digest with private key (PSO on card) ###");
        try
        {
            var digest = new byte[32]; for (int i = 0; i < 32; i++) digest[i] = (byte)(i + 1);
            using var sm = f.MechanismFactory.Create(CKM.CKM_GOSTR3410);
            byte[] sig = s.Sign(sm, priv, digest);
            Console.WriteLine($"signature: {sig?.Length ?? 0} bytes (computed on token; private key never returned)");
        }
        catch (Exception e) { Console.WriteLine("sign failed: " + e.Message); }

        Console.WriteLine("\n### C_WrapKey private key (must refuse) ###");
        try
        {
            var wrapT = new List<IObjectAttribute>
            {
                af.Create(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY),
                af.Create(CKA.CKA_KEY_TYPE, (ulong)CKK.CKK_GOST28147),
                af.Create(CKA.CKA_TOKEN, false),
                af.Create(CKA.CKA_LABEL, prefix + "wrapper"),
                af.Create(CKA.CKA_WRAP, true),
                af.Create(CKA.CKA_GOST28147_PARAMS, new byte[] { 0x06, 0x07, 0x2A, 0x85, 0x03, 0x02, 0x02, 0x1F, 0x01 }),
            };
            using var gen = f.MechanismFactory.Create(CKM.CKM_GOST28147_KEY_GEN);
            IObjectHandle wrapper = s.GenerateKey(gen, wrapT);
            using var wm = f.MechanismFactory.Create(CKM.CKM_GOST28147_KEY_WRAP);
            byte[] wrapped = s.WrapKey(wm, wrapper, priv);
            Console.WriteLine($"!!! WRAPPED {wrapped?.Length ?? 0} bytes");
        }
        catch (Exception e) { Console.WriteLine("refused: " + e.Message); }

        Console.WriteLine("\n### cleanup: destroy generated objects ###");
        int removed = 0;
        foreach (IObjectHandle o in s.FindAllObjects(new List<IObjectAttribute>()))
        {
            string label;
            try { label = s.GetAttributeValue(o, new List<CKA> { CKA.CKA_LABEL })[0].GetValueAsString() ?? ""; } catch { label = ""; }
            if (label.StartsWith(prefix, StringComparison.Ordinal))
            { try { s.DestroyObject(o); removed++; } catch { } }
        }
        Console.WriteLine($"destroyed {removed} objects");
        s.Logout();
        return 0;
    }
}
