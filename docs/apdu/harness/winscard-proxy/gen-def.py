#!/usr/bin/env python3
# Генерирует winscard.def: все экспорты системного winscard.dll форвардятся в winscard_orig.dll,
# кроме SCardTransmit — он реализован в winscard_proxy.c. Требует pefile (pip install pefile).
import pefile

pe = pefile.PE(r"C:\Windows\System32\winscard.dll")
names = [e.name.decode() for e in pe.DIRECTORY_ENTRY_EXPORT.symbols if e.name]
with open("winscard.def", "w") as f:
    f.write("LIBRARY winscard\nEXPORTS\n")
    for n in names:
        if n == "SCardTransmit":
            f.write("SCardTransmit\n")            # реальная функция из winscard_proxy.c
        else:
            f.write(f"{n}=winscard_orig.{n}\n")    # форвардер в копию настоящей DLL
print(f"winscard.def: {len(names)} экспортов")
