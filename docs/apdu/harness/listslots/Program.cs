using System;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;

// Read-only slot lister: index, model, serial, PIN-counter flags. No C_Login.
class P
{
    static int Main()
    {
        string lib = @"C:\Windows\System32\rtPKCS11ECP.dll";
        var f = new Pkcs11InteropFactories();
        using IPkcs11Library p11 = f.Pkcs11LibraryFactory.LoadPkcs11Library(f, lib, AppType.MultiThreaded);
        var slots = p11.GetSlotList(SlotsType.WithTokenPresent);
        Console.WriteLine($"slots with token: {slots.Count}");
        int i = 0;
        foreach (ISlot s in slots)
        {
            i++;
            ITokenInfo ti = s.GetTokenInfo();
            var fl = ti.TokenFlags;
            Console.WriteLine($"[{i}] slotId={s.SlotId} desc='{s.GetSlotInfo().SlotDescription.Trim()}'");
            Console.WriteLine($"     model='{ti.Model.Trim()}' serial='{ti.SerialNumber.Trim()}' fw={ti.FirmwareVersion} label='{ti.Label.Trim()}'");
            Console.WriteLine($"     PIN: toBeChanged={fl.UserPinToBeChanged} countLow={fl.UserPinCountLow} finalTry={fl.UserPinFinalTry} locked={fl.UserPinLocked}");
        }
        return 0;
    }
}
