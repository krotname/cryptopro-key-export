using System;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using Xunit;

namespace CryptoProExport.Tests
{
    /// <summary>Аргументы p12utility, разбор PE, вшитые зависимости и расшифровка ошибок.</summary>
    public class ToolingTests
    {
        [Fact]
        public void RepairArguments_ExchangeOnly()
        {
            string args = P12Utility.BuildRepairArguments(true, false, null, false);
            Assert.Equal("--cprepair --container_folder \".\" --cert \"cert_exchange.cer\" --keyexport", args);
        }

        [Fact]
        public void RepairArguments_SignatureOnly()
        {
            string args = P12Utility.BuildRepairArguments(false, true, null, false);
            Assert.Equal("--cprepair --container_folder \".\" --certsg \"cert_signature.cer\" --keyexport_sg", args);
        }

        [Fact]
        public void RepairArguments_BothCertsPasswordAndNormalHeader()
        {
            string args = P12Utility.BuildRepairArguments(true, true, "secret", true);
            Assert.Equal(
                "--cprepair --container_folder \".\" --cert \"cert_exchange.cer\" --keyexport " +
                "--certsg \"cert_signature.cer\" --keyexport_sg --passcp \"secret\" --normal_header",
                args);
        }

        [Fact]
        public void RepairArguments_EmptyPasswordIsOmitted()
        {
            Assert.DoesNotContain("--passcp", P12Utility.BuildRepairArguments(true, false, "", false));
        }

        [Fact]
        public void InstallCertificateArguments_KeepExactHdImageTarget()
        {
            string args = CertMgr.BuildInstallArguments(
                @"C:\backup\cert_exchange.cer", @"\\.\HDIMAGE\container", signatureKey: false);

            Assert.Equal(
                "-install -file \"C:\\backup\\cert_exchange.cer\" " +
                "-container \"\\\\.\\HDIMAGE\\container\" -silent", args);
        }

        [Theory]
        [InlineData(true, false, "exchange.cer", "signature.cer", "exchange.cer", null)]
        [InlineData(false, true, "exchange.cer", "signature.cer", null, "signature.cer")]
        [InlineData(true, true, "exchange.cer", "signature.cer", "exchange.cer", "signature.cer")]
        [InlineData(false, false, "exchange.cer", "signature.cer", null, null)]
        public void CertificatesForPresentKeys_DropsCertificatesForMissingKeySpecs(
            bool hasExchangeKey, bool hasSignatureKey,
            string exchange, string signature,
            string expectedExchange, string expectedSignature)
        {
            var actual = CertMgr.CertificatesForPresentKeys(
                hasExchangeKey, hasSignatureKey, exchange, signature);

            Assert.Equal(expectedExchange, actual.exchange);
            Assert.Equal(expectedSignature, actual.signature);
        }

        [Fact]
        public void MaskPassword_HidesContainerPassword()
        {
            string args = P12Utility.BuildRepairArguments(true, false, "пароль с пробелом", true);
            string masked = P12Utility.MaskPassword(args);
            Assert.DoesNotContain("пароль", masked);
            Assert.Contains("--passcp \"***\"", masked);
            Assert.Contains("--normal_header", masked); // остальные аргументы не потерялись
        }

        [Fact]
        public void MaskPassword_LeavesArgumentsWithoutPasswordAlone()
        {
            string args = P12Utility.BuildRepairArguments(true, false, null, false);
            Assert.Equal(args, P12Utility.MaskPassword(args));
        }

        [Fact]
        public void MaskQuotedValue_HidesCertmgrPin()
        {
            string masked = P12Utility.MaskQuotedValue(
                "-export -pfx -dest \"C:\\out.pfx\" -container \"cpx\" -pin \"тайна\" -silent", "-pin ");
            Assert.DoesNotContain("тайна", masked);
            Assert.Contains("-silent", masked);
            Assert.Contains("C:\\out.pfx", masked);
        }

        [Fact]
        public void MaskQuotedValue_IgnoresFlagInsideAnotherValue()
        {
            // Имя .pfx выбирает пользователь. Если оно само содержит «-pin », простой IndexOf
            // замаскировал бы путь, а настоящий пароль ушёл бы в журнал открытым текстом.
            string masked = P12Utility.MaskQuotedValue(
                "-export -pfx -dest \"C:\\backup -pin .pfx\" -pin \"тайна\" -silent", "-pin ");
            Assert.DoesNotContain("тайна", masked);
            Assert.Contains("C:\\backup -pin .pfx", masked);
            Assert.Contains("-pin \"***\"", masked);
        }

        [Fact]
        public void Quote_RejectsDoubleQuoteInsteadOfSilentlyTruncating()
        {
            // Утилиты КриптоПро разбирают командную строку сами: пароль my"pass дошёл бы до
            // них как «my», и .pfx молча получил бы не тот пароль, что ввёл пользователь.
            Assert.Throws<ArgumentException>(() => P12Utility.BuildRepairArguments(true, false, "my\"pass", false));
            Assert.Equal("\"обычный пароль\"", P12Utility.Quote("обычный пароль"));
        }

        [Fact]
        public void BundledDependencies_AreEmbedded()
        {
            // Если этот тест упал — зависимости перестали вшиваться и exe снова неполный
            Assert.True(BundledTools.Has(BundledTools.P12UtilityResource), "p12utility не вшит в сборку");
            Assert.True(BundledTools.Has(BundledTools.RtComLiteResource), "rtCOMLite не вшит в сборку");
        }

        [Fact]
        public void BundledDependencies_ExtractOnceAndReuse()
        {
            string first = BundledTools.P12Utility();
            Assert.NotNull(first);
            Assert.True(File.Exists(first));
            long size = new FileInfo(first).Length;

            string second = BundledTools.P12Utility();
            Assert.Equal(first, second);
            Assert.Equal(size, new FileInfo(second).Length);
            Assert.StartsWith(BundledTools.CacheDir, first, StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public void BundledDependencies_AreX86()
        {
            // Разрядность критична: 32-битный rtCOMLite грузится только в 32-битный процесс
            Assert.Equal(Architecture.X86, RegFreeCom.ReadMachine(BundledTools.P12Utility()));
            Assert.Equal(Architecture.X86, RegFreeCom.ReadMachine(BundledTools.RtComLite()));
        }

        [Fact]
        public void ReadMachine_ReturnsNullForNonPeFile()
        {
            string path = Path.Combine(Path.GetTempPath(), "cpx-not-a-pe-" + Guid.NewGuid().ToString("N") + ".txt");
            File.WriteAllText(path, "просто текст, не исполняемый файл");
            try { Assert.Null(RegFreeCom.ReadMachine(path)); }
            finally { File.Delete(path); }
        }

        [Fact]
        public void MatchesProcess_FollowsProcessArchitecture()
        {
            bool matches = RegFreeCom.MatchesProcess(BundledTools.RtComLite(), out string detail);
            Assert.Equal(RuntimeInformation.ProcessArchitecture == Architecture.X86, matches);
            Assert.Contains("x86", detail);
        }

        [Theory]
        [InlineData(unchecked((int)0x8010006C), "PIN")]
        [InlineData(unchecked((int)0x80090016), "контейнер")]
        [InlineData(unchecked((int)0x8009000B), "экспортируемым")]
        public void CryptoErrors_ExplainsKnownCodes(int code, string expectedFragment)
        {
            Assert.Contains(expectedFragment, CryptoErrors.Describe(code));
        }

        [Fact]
        public void CryptoErrors_ZeroIsOk() => Assert.Equal("OK", CryptoErrors.Describe(0));

        [Fact]
        public void CryptoErrors_UnknownHresultStillShowsCode()
        {
            Assert.Contains("0x87654321", CryptoErrors.Describe(unchecked((int)0x87654321)));
        }

        // Отчёт локализован, поэтому язык фиксируется явно: иначе тест зависел бы от
        // культуры машины и на англоязычном раннере CI искал бы русские подстроки.
        [Fact]
        public void Diagnostics_ReportCoversEveryDependency()
        {
            using var ru = Strings.Scope("ru");
            var report = Diagnostics.Report();
            Assert.Contains(report, l => l.StartsWith("Процесс:", StringComparison.Ordinal));

            // Вшитая зависимость в норме попадает в общую строку без путей, а отдельную строку
            // получает только при отклонении (внешняя копия, нет её, системная регистрация).
            Assert.Contains(report, l => l.StartsWith("Встроенные зависимости:", StringComparison.Ordinal)
                                      && l.Contains("p12utility", StringComparison.Ordinal)
                                      || l.StartsWith("p12utility:", StringComparison.Ordinal));
            Assert.Contains(report, l => l.StartsWith("Встроенные зависимости:", StringComparison.Ordinal)
                                      && l.Contains("rtCOMLite", StringComparison.Ordinal)
                                      || l.StartsWith("rtCOMLite:", StringComparison.Ordinal));

            Assert.Contains(report, l => l.StartsWith("Считыватели смарт-карт (PnP):", StringComparison.Ordinal) ||
                                         l.StartsWith("Считыватель смарт-карт ", StringComparison.Ordinal));
            Assert.Contains(report, l => l.StartsWith("PKCS#11:", StringComparison.Ordinal));
            Assert.Contains(report, l => l.StartsWith("КриптоПро CSP:", StringComparison.Ordinal));
        }

        [Fact]
        public void Diagnostics_SpellsOutProviderTypeInsteadOfBareNumber()
        {
            // «провайдеры 80, 81, 75» читателю лога ничего не говорят: рядом с типом обязано
            // стоять обозначение стандарта, иначе строка бесполезна.
            using var ru = Strings.Scope("ru");
            string csp = Diagnostics.Report().FirstOrDefault(
                l => l.StartsWith("КриптоПро CSP:", StringComparison.Ordinal));
            Assert.NotNull(csp);
            if (CertFromContainer.AvailableProviders().Count == 0) return;   // CSP не установлен

            Assert.Contains("ГОСТ Р 34.10", csp, StringComparison.Ordinal);
            Assert.DoesNotContain("провайдеры 80,", csp, StringComparison.Ordinal);
        }

        [Fact]
        public void ProviderAlgorithm_IsTranslatedLikeTheRestOfTheReport()
        {
            // Расшифровку пишем мы, а не вендор, поэтому она обязана переводиться: в английском
            // отчёте не должно оставаться русских «бит» (замечание Codex на PR #70).
            using (var ru = Strings.Scope("ru"))
                Assert.Equal("80 — ГОСТ Р 34.10-2012, 256 бит", CertFromContainer.DescribeProvider(80));

            using (var en = Strings.Scope("en"))
            {
                Assert.Equal("81 — GOST R 34.10-2012, 512 bit", CertFromContainer.DescribeProvider(81));
                Assert.Equal("75 — GOST R 34.10-2001", CertFromContainer.DescribeProvider(75));
            }

            // Неизвестный тип остаётся числом: алгоритм за него не выдумывается.
            Assert.Equal("99", CertFromContainer.ProviderAlgorithm(99));
        }

        [Fact]
        public void ProviderAlgorithm_CoversEveryKnownProviderType()
        {
            // Добавили провайдер в таблицу и забыли расшифровку — тип вернётся голым числом.
            using var ru = Strings.Scope("ru");
            Assert.All(CertFromContainer.Providers, p => Assert.NotEqual(
                p.type.ToString(System.Globalization.CultureInfo.InvariantCulture),
                CertFromContainer.ProviderAlgorithm(p.type)));
        }

        [Fact]
        public void Pkcs11Libraries_AreEmbeddedForEveryVendorWithASelfContainedModule()
        {
            // Библиотеки трёх вендоров вшиты, чтобы смарт-карточный носитель читался и без
            // установленных драйверов. Рутокен S сюда не входит намеренно: rtPKCS11.dll тянет
            // rtAPIi.dll/rtLib.dll из пакета драйверов (см. BundledTools).
            Assert.True(BundledTools.Has(BundledTools.ResourceName("rtPKCS11ECP.dll")), "Rutoken");
            Assert.True(BundledTools.Has(BundledTools.ResourceName("jcPKCS11-2.dll")), "JaCarta");
            Assert.True(BundledTools.Has(BundledTools.ResourceName("isbc_pkcs11_main.dll")), "ESMART");
            Assert.True(BundledTools.Has(BundledTools.ResourceName("isbc_esmart_token_mod.dll")),
                "ESMART backend");
            Assert.False(BundledTools.Has(BundledTools.ResourceName("rtPKCS11.dll")), "Rutoken S");
        }

        [Fact]
        public void Diagnostics_ReportIsTranslated()
        {
            using var en = Strings.Scope("en");
            var report = Diagnostics.Report();
            Assert.Contains(report, l => l.StartsWith("Process:", StringComparison.Ordinal));
            Assert.Contains(report, l => l.StartsWith("CryptoPro CSP:", StringComparison.Ordinal));
        }

        [Fact]
        public void Diagnostics_WarnsAboutBitnessOnlyOutsideX86()
        {
            // Вшитый rtCOMLite 32-битный: в x64/arm64 отчёт обязан предупредить, в x86 — молчать
            using var ru = Strings.Scope("ru");
            bool warned = Diagnostics.Report().Any(l => l.Contains("32-битная", StringComparison.Ordinal));
            Assert.Equal(RuntimeInformation.ProcessArchitecture != Architecture.X86, warned);
        }

        [Fact]
        public void Diagnostics_DetailedReportIsLonger()
        {
            Assert.True(Diagnostics.Report(detailed: true).Count > Diagnostics.Report().Count);
        }
    }
}
