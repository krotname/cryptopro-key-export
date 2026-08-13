using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Xunit;

namespace CryptoProExport.Tests
{
    /// <summary>
    /// Чистая логика поддержки Рутокен ЭЦП/Lite через PKCS#11: классификация модели,
    /// локализованные названия семейств и состояний PIN, поиск библиотеки.
    /// Обращения к железу тут нет — оно проверяется e2e на живом токене.
    /// </summary>
    public class Pkcs11TokenTests
    {
        [Theory]
        [InlineData("Rutoken ECP", RutokenKind.RutokenEcp)]      // реальная модель нашего токена
        [InlineData("Rutoken ECP 2.0", RutokenKind.RutokenEcp)]
        [InlineData("Rutoken lite", RutokenKind.RutokenLite)]
        [InlineData("Rutoken Lite", RutokenKind.RutokenLite)]
        [InlineData("Rutoken S", RutokenKind.RutokenS)]
        [InlineData("Rutoken", RutokenKind.RutokenS)]            // без уточнения — файловый профиль
        [InlineData("Рутокен ЭЦП", RutokenKind.RutokenEcp)]      // кириллическая метка тоже опознаётся
        [InlineData("JaCarta GOST", RutokenKind.Other)]
        [InlineData("eToken PRO", RutokenKind.Other)]
        [InlineData("", RutokenKind.Unknown)]
        [InlineData(null, RutokenKind.Unknown)]
        [InlineData("SomeCard 42", RutokenKind.Unknown)]
        public void Classify_MapsModelToFamily(string model, RutokenKind expected)
        {
            Assert.Equal(expected, Pkcs11Token.Classify(model));
        }

        [Fact]
        public void Classify_IsCaseInsensitive()
        {
            Assert.Equal(RutokenKind.RutokenEcp, Pkcs11Token.Classify("RUTOKEN ecp"));
            Assert.Equal(RutokenKind.RutokenLite, Pkcs11Token.Classify("rutoken LITE"));
        }

        [Fact]
        public void Classify_FallsBackToManufacturerWhenModelSaysNothing()
        {
            // Живая JaCarta 13.08.2026: model='PRO', manufacturerID='Aladdin R.D.'.
            // По одной модели носитель попадал бы в «не опознан».
            Assert.Equal(RutokenKind.Unknown, Pkcs11Token.Classify("PRO"));
            Assert.Equal(RutokenKind.Other, Pkcs11Token.Classify("PRO", "Aladdin R.D."));
        }

        [Fact]
        public void Classify_PrefersModelOverManufacturer()
        {
            // Модель говорит внятно — производителя не спрашиваем.
            Assert.Equal(RutokenKind.RutokenLite, Pkcs11Token.Classify("Rutoken lite", "Aktiv Co."));
        }

        [Fact]
        public void Classify_DoesNotGuessRutokenFamilyFromManufacturer()
        {
            // «Aktiv Co.» без внятной модели остаётся неопознанным намеренно: иначе носитель
            // попал бы в файловый обход rtCOMLite как Рутокен S (RutokenExporter.ShouldWalk).
            Assert.Equal(RutokenKind.Unknown, Pkcs11Token.Classify("SomeCard 42", "Aktiv Co."));
        }

        [Theory]
        [InlineData(RutokenKind.RutokenS)]
        [InlineData(RutokenKind.RutokenLite)]
        [InlineData(RutokenKind.RutokenEcp)]
        [InlineData(RutokenKind.Other)]
        [InlineData(RutokenKind.Unknown)]
        public void KindName_IsLocalizedForEveryFamily(RutokenKind kind)
        {
            string name = Pkcs11Token.KindName(kind);
            Assert.False(string.IsNullOrWhiteSpace(name));
            Assert.DoesNotContain(Strings.MissingMarkerStart, name, StringComparison.Ordinal);
        }

        [Fact]
        public void PinState_PrefersMostSevereFlag()
        {
            // Заблокированный PIN важнее «последней попытки», та — важнее «счётчик на исходе».
            string locked = Pkcs11Token.PinState(new Pkcs11TokenInfo { PinLocked = true, PinFinalTry = true });
            string final = Pkcs11Token.PinState(new Pkcs11TokenInfo { PinFinalTry = true, PinCountLow = true });
            string low = Pkcs11Token.PinState(new Pkcs11TokenInfo { PinCountLow = true });
            string def = Pkcs11Token.PinState(new Pkcs11TokenInfo { PinDefault = true });
            string ok = Pkcs11Token.PinState(new Pkcs11TokenInfo());

            Assert.Equal(Strings.Get("pin.state.locked"), locked);
            Assert.Equal(Strings.Get("pin.state.finaltry"), final);
            Assert.Equal(Strings.Get("pin.state.countlow"), low);
            Assert.Equal(Strings.Get("pin.state.default"), def);
            Assert.Equal(Strings.Get("pin.state.ok"), ok);
        }

        [Fact]
        public void Combine_KeepsContainersAndTheirCerts()
        {
            var cert = new byte[] { 1, 2, 3 };
            var containers = new List<Pkcs11Container>
            {
                new Pkcs11Container { Name = "cont", Application = "CryptoPro CSP", Certificate = cert },
            };
            var certs = new Dictionary<string, byte[]> { ["cont"] = cert };

            var result = Pkcs11Token.Combine(containers, certs);

            // Сертификат уже приложен к контейнеру — второй записи быть не должно.
            Assert.Single(result);
            Assert.Equal("cont", result[0].Name);
            Assert.False(result[0].CertificateOnly);
        }

        [Fact]
        public void Combine_SurfacesCertificateWithoutMatchingContainer()
        {
            // Сценарий отказа до правки: сертификат с меткой, которой нет ни у одного CKO_DATA,
            // исчезал полностью — ни в списке, ни в извлечении командой token.
            var cert = new byte[] { 9, 9 };
            var containers = new List<Pkcs11Container>
            {
                new Pkcs11Container { Name = "cont", Application = "CryptoPro CSP" },
            };
            var certs = new Dictionary<string, byte[]> { ["одинокий"] = cert };

            var result = Pkcs11Token.Combine(containers, certs);

            Assert.Equal(2, result.Count);
            var lone = Assert.Single(result, c => c.CertificateOnly);
            Assert.Equal("одинокий", lone.Name);
            Assert.Same(cert, lone.Certificate);
            // У контейнера без сертификата ничего не появилось.
            Assert.Null(result.Single(c => c.Name == "cont").Certificate);
        }

        [Fact]
        public void Combine_ToleratesNulls()
        {
            Assert.Empty(Pkcs11Token.Combine(null, null));
        }

        [Fact]
        public void SmartCardReaders_SelectsEveryReaderUnsafeForFileWalk()
        {
            var tokens = new List<Pkcs11TokenInfo>
            {
                new Pkcs11TokenInfo { Reader = "Aktiv Rutoken ECP 0", Kind = RutokenKind.RutokenEcp },
                new Pkcs11TokenInfo { Reader = "Aktiv Rutoken lite 0", Kind = RutokenKind.RutokenLite },
                new Pkcs11TokenInfo { Reader = "Aktiv ruToken 0", Kind = RutokenKind.RutokenS },
                new Pkcs11TokenInfo { Reader = null, Kind = RutokenKind.RutokenEcp },
                null,
            };

            var set = Pkcs11Token.SmartCardReaders(tokens);

            Assert.Equal(2, set.Count);
            Assert.Contains("Aktiv Rutoken ECP 0", set);
            Assert.Contains("Aktiv Rutoken lite 0", set);
            Assert.DoesNotContain("Aktiv ruToken 0", set);
        }

        [Fact]
        public void SmartCardReaders_IncludesForeignVendorsUnderFacelessReaderNames()
        {
            // Имя считывателя может ничего не говорить о вендоре («ACS ACR38U 0»), а PKCS#11
            // уже опознал носитель по производителю. Без этого списка ShouldWalk пустил бы его
            // в файловый обход rtCOMLite, где ReadBinary рушит кучу процесса (замечание Codex, PR #25).
            var tokens = new List<Pkcs11TokenInfo>
            {
                new Pkcs11TokenInfo { Reader = "ACS ACR38U 0", Kind = RutokenKind.Other },
            };

            var set = Pkcs11Token.SmartCardReaders(tokens);

            Assert.Contains("ACS ACR38U 0", set);
            Assert.False(RutokenExporter.ShouldWalk("ACS ACR38U 0", set));
        }

        [Fact]
        public void SmartCardReaders_ToleratesNull()
        {
            Assert.Empty(Pkcs11Token.SmartCardReaders(null));
        }

        [Fact]
        public void LibraryCandidates_AreRootedAndNamed()
        {
            var candidates = Pkcs11Token.LibraryCandidates().ToArray();
            Assert.NotEmpty(candidates);
            Assert.All(candidates, c => Assert.True(System.IO.Path.IsPathRooted(c), c));
            Assert.Contains(candidates, c => c.EndsWith("rtPKCS11ECP.dll", StringComparison.OrdinalIgnoreCase));
        }

        [Fact]
        public void LibraryCandidates_CoverEveryKnownVendor()
        {
            // Одна библиотека показывает только своего вендора, поэтому кандидаты обязаны
            // быть у каждой известной: иначе носитель просто не увидят (так и было с JaCarta).
            var candidates = Pkcs11Token.LibraryCandidates().ToArray();
            Assert.NotEmpty(Pkcs11Token.KnownLibraries);
            Assert.All(Pkcs11Token.KnownLibraries, lib =>
            {
                Assert.False(string.IsNullOrWhiteSpace(lib.Vendor));
                Assert.Contains(candidates, c => c.EndsWith(lib.Dll, StringComparison.OrdinalIgnoreCase));
            });
            Assert.Contains(candidates, c => c.EndsWith("jcPKCS11-2.dll", StringComparison.OrdinalIgnoreCase));
        }

        [Fact]
        public void LibraryCandidates_ForSingleDllMentionOnlyThatDll()
        {
            var jc = Pkcs11Token.LibraryCandidates("jcPKCS11-2.dll").ToArray();
            Assert.NotEmpty(jc);
            Assert.All(jc, c => Assert.EndsWith("jcPKCS11-2.dll", c, StringComparison.OrdinalIgnoreCase));
        }

        [Fact]
        public void AvailableLibraries_ReturnsAtMostOnePathPerVendorAndNeverThrows()
        {
            // На машине без драйверов список пуст — это штатный случай, а не ошибка.
            var libs = Pkcs11Token.AvailableLibraries();
            Assert.All(libs, l =>
            {
                Assert.True(System.IO.File.Exists(l.Path), l.Path);
                Assert.Contains(Pkcs11Token.KnownLibraries, k => k.Vendor == l.Vendor);
            });
            Assert.Equal(libs.Count, libs.Select(l => l.Vendor).Distinct(StringComparer.Ordinal).Count());
            Assert.Equal(libs.Count > 0, Pkcs11Token.IsAvailable);
        }

        [Fact]
        public void Enumerate_NeverThrows_WhenLibraryMissingOrNoToken()
        {
            // На машине без драйвера Рутокена / без токена перечисление обязано
            // тихо вернуть пустой список, а не свалить приложение.
            var ex = Record.Exception(() => Pkcs11Token.Enumerate(readContainers: true, log: _ => { }));
            Assert.Null(ex);
        }

        [Fact]
        public void Enumerate_RespectsCancellation()
        {
            // Отмена должна доходить и до PKCS#11: зависший драйвер смарт-карты иначе
            // держал бы окно (кнопка «Отмена» есть у всех длинных операций).
            using var cts = new System.Threading.CancellationTokenSource();
            cts.Cancel();
            Assert.Throws<OperationCanceledException>(
                () => Pkcs11Token.Enumerate(readContainers: true, log: _ => { }, cancel: cts.Token));
        }

        // ---------- имя файла для снятого с токена сертификата ----------

        [Fact]
        public void CertFileName_KeepsLabelAndAddsSerial()
        {
            Assert.Equal("Ivanov_383a6954.cer", Pkcs11Token.CertFileName("Ivanov", "383a6954"));
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("   ")]
        public void CertFileName_FallsBackWhenSerialUnknown(string serial)
        {
            Assert.Equal("Ivanov.cer", Pkcs11Token.CertFileName("Ivanov", serial));
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        public void CertFileName_FallsBackWhenLabelUnknown(string label)
        {
            Assert.Equal("cert_1234.cer", Pkcs11Token.CertFileName(label, "1234"));
        }

        [Fact]
        public void CertFileName_ReplacesCharactersForbiddenInFileNames()
        {
            string name = Pkcs11Token.CertFileName(@"a/b\c:d*e?f""g<h>i|j", "s");
            Assert.DoesNotContain('/', name);
            Assert.DoesNotContain('\\', name);
            Assert.DoesNotContain(':', name);
            Assert.All(Path.GetInvalidFileNameChars(), ch => Assert.DoesNotContain(ch, name));
            Assert.EndsWith("_s.cer", name, StringComparison.Ordinal);
        }

        [Fact]
        public void UniqueCertPath_AddsSuffixInsteadOfOverwriting()
        {
            // Один и тот же контейнер на двух токенах различается серийником...
            var taken = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            string a = Pkcs11Token.UniqueCertPath(@"C:\out", "Ivanov", "aaa", taken);
            string b = Pkcs11Token.UniqueCertPath(@"C:\out", "Ivanov", "bbb", taken);
            Assert.NotEqual(a, b);

            // ...а при полном совпадении (тот же токен, две записи с одной меткой)
            // второй файл получает суффикс, а не затирает первый.
            string c = Pkcs11Token.UniqueCertPath(@"C:\out", "Ivanov", "aaa", taken);
            string d = Pkcs11Token.UniqueCertPath(@"C:\out", "Ivanov", "aaa", taken);
            Assert.Equal(Path.Combine(@"C:\out", "Ivanov_aaa(2).cer"), c);
            Assert.Equal(Path.Combine(@"C:\out", "Ivanov_aaa(3).cer"), d);
            Assert.Equal(4, taken.Count);
        }

        [Fact]
        public void UniqueCertPath_IgnoresCaseWhenComparingPaths()
        {
            // Windows-пути регистронезависимы: «IVANOV» и «ivanov» — один и тот же файл.
            var taken = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            Pkcs11Token.UniqueCertPath(@"C:\out", "IVANOV", "aaa", taken);
            string second = Pkcs11Token.UniqueCertPath(@"C:\out", "ivanov", "aaa", taken);
            Assert.EndsWith("(2).cer", second, StringComparison.Ordinal);
        }

        [Fact]
        public void LibraryCandidates_HasNoDuplicates()
        {
            var candidates = Pkcs11Token.LibraryCandidates().ToArray();
            Assert.Equal(candidates.Length, candidates.Distinct(StringComparer.OrdinalIgnoreCase).Count());
        }
    }
}
