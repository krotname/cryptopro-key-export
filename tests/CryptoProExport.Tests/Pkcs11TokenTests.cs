using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using Xunit;

namespace CryptoProExport.Tests
{
    /// <summary>
    /// Чистая логика поддержки токенов через PKCS#11: классификация модели,
    /// локализованные названия семейств и состояний PIN, поиск vendor libraries.
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
        [InlineData("JaCarta DS", RutokenKind.Unknown)]        // без отдельного свидетельства вендора
        [InlineData("JaCarta LT", RutokenKind.Unknown)]
        [InlineData("Datastore", RutokenKind.Unknown)]
        [InlineData("JaCarta GOST", RutokenKind.Other)]
        [InlineData("eToken PRO", RutokenKind.Other)]
        [InlineData("ESMART Token USB 64K", RutokenKind.Esmart)]
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
        public void Classify_RecognizesOnlyTheExactJaCartaProMetadataPair()
        {
            Assert.Equal(RutokenKind.Unknown, Pkcs11Token.Classify("PRO"));
            Assert.Equal(RutokenKind.JaCartaPro,
                Pkcs11Token.Classify("PRO", "Aladdin R.D."));
            Assert.Equal(RutokenKind.Other, Pkcs11Token.Classify("PRO", "Aladdin"));
            Assert.Equal(RutokenKind.Other, Pkcs11Token.Classify("PRO X", "Aladdin R.D."));
            Assert.Equal(RutokenKind.Esmart, Pkcs11Token.Classify("USB 64K", "ISBC"));
        }

        [Fact]
        public void Classify_RecognizesJaCartaLtOnlyWithVendorEvidence()
        {
            Assert.Equal(RutokenKind.JaCartaLt,
                Pkcs11Token.Classify("JaCarta DS", "Aladdin R.D."));
            Assert.Equal(RutokenKind.JaCartaLt,
                Pkcs11Token.Classify("Datastore", "Aladdin R.D."));
            Assert.Equal(RutokenKind.JaCartaLt,
                Pkcs11Token.Classify("JaCarta LT", "JaCarta"));
            Assert.Equal(RutokenKind.JaCartaLt,
                Pkcs11Token.Classify("Aladdin R.D. JaCarta LT 0"));
        }

        [Fact]
        public void Classify_DoesNotUseJaCartaModelNameAsVendorEvidence()
        {
            // Название модели без независимого производителя не доказывает, что перед нами LT.
            Assert.Equal(RutokenKind.Unknown, Pkcs11Token.Classify("JaCarta DS"));
            Assert.Equal(RutokenKind.Unknown, Pkcs11Token.Classify("JaCarta LT"));
            Assert.Equal(RutokenKind.Unknown, Pkcs11Token.Classify("Datastore"));

            // Чужой производитель не является достаточным свидетельством LT-вендора.
            Assert.Equal(RutokenKind.Unknown, Pkcs11Token.Classify("JaCarta DS", "Contoso"));
            Assert.Equal(RutokenKind.Unknown, Pkcs11Token.Classify("JaCarta LT", "Contoso"));
            Assert.Equal(RutokenKind.Unknown, Pkcs11Token.Classify("Datastore", "Contoso"));

            // 'DS' слишком коротко и встречается у несвязанных устройств. Производитель
            // позволяет определить чужого вендора, но не конкретную модель LT.
            Assert.Equal(RutokenKind.Unknown, Pkcs11Token.Classify("DS"));
            Assert.Equal(RutokenKind.Other, Pkcs11Token.Classify("DS", "Aladdin R.D."));
        }

        [Fact]
        public void TokenInfo_DefaultKindIsUnknown()
        {
            Assert.Equal(RutokenKind.Unknown, new Pkcs11TokenInfo().Kind);
        }

        [Fact]
        public void ResolveReaderKind_FallsBackForMissingOrIncompleteMetadata()
        {
            const string reader = "Aktiv Rutoken lite 0";

            Assert.Equal(RutokenKind.RutokenLite,
                Pkcs11Token.ResolveReaderKind(reader, metadata: null));

            var incomplete = new Pkcs11TokenInfo { Reader = reader };
            Assert.Equal(RutokenKind.Unknown, incomplete.Kind);
            Assert.Equal(RutokenKind.RutokenLite,
                Pkcs11Token.ResolveReaderKind(reader, incomplete));
        }

        [Theory]
        [InlineData("Aktiv Rutoken lite 0", null)]
        [InlineData("Rutoken Lite 0", null)]
        [InlineData("Foo Lite 0", "Aktiv Co.")]
        public void ResolveReaderKind_AllowsLiteFallbackWithRutokenVendorEvidence(
            string reader, string manufacturer)
        {
            var metadata = manufacturer == null
                ? null
                : new Pkcs11TokenInfo { Reader = reader, Manufacturer = manufacturer };

            Assert.Equal(RutokenKind.RutokenLite,
                Pkcs11Token.ResolveReaderKind(reader, metadata));
        }

        [Theory]
        [InlineData("Foo Lite 0", RutokenKind.Unknown)]
        [InlineData("JaCarta Lite 0", RutokenKind.Other)]
        [InlineData("ESMART Lite 0", RutokenKind.Esmart)]
        [InlineData("Aktiv ESMART Lite 0", RutokenKind.Esmart)]
        public void ResolveReaderKind_BlocksGenericAndForeignLiteReaders(
            string reader, RutokenKind expected)
        {
            Assert.Equal(expected, Pkcs11Token.ResolveReaderKind(reader, metadata: null));
            Assert.NotEqual(RutokenKind.RutokenLite,
                Pkcs11Token.ResolveReaderKind(reader, metadata: null));
        }

        [Fact]
        public void ResolveReaderKind_ForeignManufacturerBlocksConflictingRutokenReader()
        {
            var incomplete = new Pkcs11TokenInfo
            {
                Reader = "Aktiv Rutoken lite 0",
                Manufacturer = "Aladdin R.D.",
            };

            Assert.Equal(RutokenKind.Other,
                Pkcs11Token.ResolveReaderKind(incomplete.Reader, incomplete));
        }

        [Fact]
        public void ResolveReaderKind_PrefersKnownMetadataOverMisleadingReaderName()
        {
            var metadata = new Pkcs11TokenInfo
            {
                Reader = "Aktiv Rutoken lite 0",
                Model = "JaCarta GOST",
                Manufacturer = "Aladdin R.D.",
                Kind = RutokenKind.Other,
            };

            Assert.Equal(RutokenKind.Other,
                Pkcs11Token.ResolveReaderKind(metadata.Reader, metadata));
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
        [InlineData(RutokenKind.JaCartaLt)]
        [InlineData(RutokenKind.JaCartaPro)]
        [InlineData(RutokenKind.Esmart)]
        [InlineData(RutokenKind.Other)]
        [InlineData(RutokenKind.Unknown)]
        public void KindName_IsLocalizedForEveryFamily(RutokenKind kind)
        {
            string name = Pkcs11Token.KindName(kind);
            Assert.False(string.IsNullOrWhiteSpace(name));
            Assert.DoesNotContain(Strings.MissingMarkerStart, name, StringComparison.Ordinal);
        }

        [Fact]
        public void KindName_UsesProductNamesForDirectForeignBackends()
        {
            Assert.Equal("JaCarta LT", Pkcs11Token.KindName(RutokenKind.JaCartaLt));
            Assert.Equal("eToken PRO (Java) / PRO",
                Pkcs11Token.KindName(RutokenKind.JaCartaPro));
            Assert.Equal("ESMART", Pkcs11Token.KindName(RutokenKind.Esmart));
        }

        [Fact]
        public void ConfirmedJaCartaPro_RequiresAllIndependentExactSignals()
        {
            var token = new Pkcs11TokenInfo
            {
                Kind = RutokenKind.JaCartaPro,
                Reader = "Aladdin Token JC 0",
                Model = "PRO",
                Manufacturer = "Aladdin R.D.",
                Atr = JaCartaProApdu.ExactAtr,
            };

            Assert.True(Pkcs11Token.IsConfirmedJaCartaPro(token));
            Assert.True(JaCartaProApdu.IsExactLiveReader(token, new[]
            {
                new PcscReader
                {
                    Name = token.Reader,
                    CardPresent = true,
                    Atr = JaCartaProApdu.ExactAtr,
                },
            }));

            foreach (Action<Pkcs11TokenInfo> mutate in new Action<Pkcs11TokenInfo>[]
            {
                value => value.Kind = RutokenKind.Other,
                value => value.Reader = "Aladdin Token JC clone 0",
                value => value.Model = "PRO X",
                value => value.Manufacturer = "Aladdin R.D. clone",
                value => value.Atr = "3B 00",
            })
            {
                var lookalike = new Pkcs11TokenInfo
                {
                    Kind = token.Kind,
                    Reader = token.Reader,
                    Model = token.Model,
                    Manufacturer = token.Manufacturer,
                    Atr = token.Atr,
                };
                mutate(lookalike);
                Assert.False(Pkcs11Token.IsConfirmedJaCartaPro(lookalike));
            }

            Assert.False(JaCartaProApdu.IsExactLiveReader(token, new[]
            {
                new PcscReader { Name = token.Reader, CardPresent = true, Atr = "3B 00" },
            }));
        }

        [Fact]
        public void AttachPcscAtr_MatchesByReaderNameAndRequiresPresentCard()
        {
            var exact = new Pkcs11TokenInfo { Reader = "Aladdin Token JC 0" };
            var absent = new Pkcs11TokenInfo { Reader = "Reader absent 0" };

            Pkcs11Token.AttachPcscAtr(new[] { exact, absent }, new[]
            {
                new PcscReader
                {
                    Name = "aladdin token jc 0",
                    CardPresent = true,
                    Atr = JaCartaProApdu.ExactAtr,
                },
                new PcscReader
                {
                    Name = absent.Reader,
                    CardPresent = false,
                    Atr = "3B 00",
                },
            });

            Assert.Equal(JaCartaProApdu.ExactAtr, exact.Atr);
            Assert.Null(absent.Atr);
        }

        [Fact]
        public void IsConfirmedEsmart_RequiresVendorAndValidatedReaderTogether()
        {
            Assert.True(Pkcs11Token.IsConfirmedEsmart(new Pkcs11TokenInfo
            {
                Kind = RutokenKind.Esmart,
                Reader = "ESMART Token USB 64K 0",
                Manufacturer = "ISBC",
            }));
            Assert.True(Pkcs11Token.IsConfirmedEsmart(new Pkcs11TokenInfo
            {
                Kind = RutokenKind.Esmart,
                Reader = "ISBC ESMART Token 3",
                Manufacturer = "ISBC CORP.",
            }));
            Assert.False(Pkcs11Token.IsConfirmedEsmart(new Pkcs11TokenInfo
            {
                Kind = RutokenKind.Esmart,
                Reader = "ESMART-looking reader",
                Manufacturer = "ISBC",
            }));
            Assert.False(Pkcs11Token.IsConfirmedEsmart(new Pkcs11TokenInfo
            {
                Kind = RutokenKind.Esmart,
                Reader = "ISBC ESMART Token Pro 0",
                Model = "ESMART Token Pro",
                Manufacturer = "ISBC",
            }));
            Assert.False(Pkcs11Token.IsConfirmedEsmart(new Pkcs11TokenInfo
            {
                Kind = RutokenKind.Esmart,
                Reader = "ESMART Token USB 64K 0",
                Manufacturer = "Contoso",
            }));
            Assert.False(Pkcs11Token.IsConfirmedEsmart(new Pkcs11TokenInfo
            {
                Kind = RutokenKind.Other,
                Reader = "ESMART Token USB 64K 0",
                Manufacturer = "ISBC",
            }));
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

        [Theory]
        [InlineData(false, 2048, false, false, true, RutokenCapabilityProfile.Unknown)]
        [InlineData(true, 2048, false, false, true, RutokenCapabilityProfile.Ecp2Capabilities)]
        [InlineData(true, 4096, false, false, true, RutokenCapabilityProfile.Ecp3Capable)]
        [InlineData(true, 2048, true, true, true, RutokenCapabilityProfile.Ecp3Capable)]
        [InlineData(true, 0, false, false, true, RutokenCapabilityProfile.Unknown)]
        [InlineData(true, 2048, false, false, false, RutokenCapabilityProfile.Unknown)]
        public void ClassifyCapabilities_UsesMechanismsNotNames(bool known, int rsa, bool ecdsa,
            bool ecMechanismPresent, bool gost, RutokenCapabilityProfile expected)
        {
            Assert.Equal(expected,
                Pkcs11Token.ClassifyCapabilities(known, rsa, ecdsa, ecMechanismPresent, gost));
        }

        [Fact]
        public void ClassifyCapabilities_SoftwareEcdsaPresent_IsUnknown()
        {
            Assert.Equal(RutokenCapabilityProfile.Unknown,
                Pkcs11Token.ClassifyCapabilities(capabilitiesKnown: true,
                    hardwareRsaMaxBits: 2048, hardwareEcdsa: false,
                    ecMechanismPresent: true, hardwareGost: true));
        }

        [Fact]
        public void CapabilitySummary_ReportsReadOnlyHardwareProfile()
        {
            using var scope = Strings.Scope("en");
            var info = new Pkcs11TokenInfo
            {
                Hardware = "20.05",
                MechanismCount = 45,
                HardwareRsaMaxBits = 2048,
                HardwareEcdsa = false,
                HardwareGost = true,
                CapabilitiesKnown = true,
                CapabilityProfile = RutokenCapabilityProfile.Ecp2Capabilities,
            };

            string summary = Pkcs11Token.CapabilitySummary(info);

            Assert.Contains("20.05", summary, StringComparison.Ordinal);
            Assert.Contains("45", summary, StringComparison.Ordinal);
            Assert.Contains("2048", summary, StringComparison.Ordinal);
            Assert.Contains(Pkcs11Token.CapabilityProfileName(
                RutokenCapabilityProfile.Ecp2Capabilities), summary, StringComparison.Ordinal);
            Assert.DoesNotContain(Strings.MissingMarkerStart, summary, StringComparison.Ordinal);
        }

        [Fact]
        public void CapabilitySummary_UnreadCapabilitiesUseUnknownMarkers()
        {
            using var scope = Strings.Scope("en");
            var info = new Pkcs11TokenInfo
            {
                Hardware = "20.05",
                MechanismCount = 45,
                CapabilitiesKnown = false,
                CapabilityProfile = RutokenCapabilityProfile.Unknown,
            };

            string summary = Pkcs11Token.CapabilitySummary(info);

            Assert.Contains("RSA HW keygen up to ? bit", summary, StringComparison.Ordinal);
            Assert.Contains("ECDSA HW ?", summary, StringComparison.Ordinal);
            Assert.Contains("GOST HW ?", summary, StringComparison.Ordinal);
            Assert.DoesNotContain("ECDSA HW −", summary, StringComparison.Ordinal);
            Assert.DoesNotContain("GOST HW −", summary, StringComparison.Ordinal);
        }

        [Theory]
        [InlineData(RutokenCapabilityProfile.Unknown)]
        [InlineData(RutokenCapabilityProfile.Ecp2Capabilities)]
        [InlineData(RutokenCapabilityProfile.Ecp3Capable)]
        public void CapabilityProfileName_IsLocalized(RutokenCapabilityProfile profile)
        {
            string name = Pkcs11Token.CapabilityProfileName(profile);
            Assert.False(string.IsNullOrWhiteSpace(name));
            Assert.DoesNotContain(Strings.MissingMarkerStart, name, StringComparison.Ordinal);
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
                new Pkcs11TokenInfo { Reader = "Aladdin R.D. JaCarta LT 0", Kind = RutokenKind.JaCartaLt },
                new Pkcs11TokenInfo { Reader = "Aladdin Token JC 0", Kind = RutokenKind.JaCartaPro },
                new Pkcs11TokenInfo { Reader = "ESMART Token USB 64K 0", Kind = RutokenKind.Esmart },
                new Pkcs11TokenInfo { Reader = "Aktiv ruToken 0", Kind = RutokenKind.RutokenS },
                new Pkcs11TokenInfo { Reader = null, Kind = RutokenKind.RutokenEcp },
                null,
            };

            var set = Pkcs11Token.SmartCardReaders(tokens);

            Assert.Equal(6, set.Count);
            Assert.Contains("Aktiv Rutoken ECP 0", set);
            Assert.Contains("Aktiv Rutoken lite 0", set);
            Assert.Contains("Aladdin R.D. JaCarta LT 0", set);
            Assert.Contains("Aladdin Token JC 0", set);
            Assert.Contains("ESMART Token USB 64K 0", set);
            Assert.Contains("Aktiv ruToken 0", set);
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
        public void SmartCardReaders_MixedInventoryProtectsEcpAndForeignReaders()
        {
            // Регрессия для одновременного присутствия разных носителей: ни один уже
            // опознанный считыватель не уходит в нативный rtCOMLite-обход. Для Rutoken S
            // после аппаратной проверки используется отдельный безопасный APDU-бэкенд.
            var tokens = new List<Pkcs11TokenInfo>
            {
                new Pkcs11TokenInfo { Reader = "Aktiv Rutoken ECP 0", Kind = RutokenKind.RutokenEcp },
                new Pkcs11TokenInfo { Reader = "Aladdin Token JC 0", Kind = RutokenKind.Other },
                new Pkcs11TokenInfo { Reader = "ESMART USB64K 0", Kind = RutokenKind.Esmart },
                new Pkcs11TokenInfo { Reader = "Aktiv ruToken 0", Kind = RutokenKind.RutokenS },
            };

            var skip = Pkcs11Token.SmartCardReaders(tokens);

            Assert.False(RutokenExporter.ShouldWalk("Aktiv Rutoken ECP 0", skip));
            Assert.False(RutokenExporter.ShouldWalk("Aladdin Token JC 0", skip));
            Assert.False(RutokenExporter.ShouldWalk("ESMART USB64K 0", skip));
            Assert.False(RutokenExporter.ShouldWalk("Aktiv ruToken 0", skip));
        }

        [Theory]
        [InlineData("JaCarta DS", null)]
        [InlineData("JaCarta LT", "Contoso")]
        [InlineData("Datastore", "")]
        public void SmartCardReaders_FailClosedForUnverifiedLtModelUnderFacelessReader(
            string model, string manufacturer)
        {
            const string reader = "ACS ACR38U 0";
            RutokenKind kind = Pkcs11Token.Classify(model, manufacturer);
            Assert.Equal(RutokenKind.Unknown, kind); // без vendor evidence не называем JaCarta LT

            var tokens = new List<Pkcs11TokenInfo>
            {
                new Pkcs11TokenInfo
                {
                    Reader = reader,
                    Model = model,
                    Manufacturer = manufacturer,
                    Kind = kind,
                },
            };

            var set = Pkcs11Token.SmartCardReaders(tokens);

            Assert.Contains(reader, set);
            Assert.False(RutokenExporter.ShouldWalk(reader, set));
        }

        [Fact]
        public void SmartCardReaders_RoutesConfirmedRutokenSAwayFromCrashingRtComWalk()
        {
            const string reader = "Aktiv ruToken 0";
            RutokenKind kind = Pkcs11Token.Classify("Rutoken S", "Aktiv Co.");
            Assert.Equal(RutokenKind.RutokenS, kind);

            var set = Pkcs11Token.SmartCardReaders(new[]
            {
                new Pkcs11TokenInfo
                {
                    Reader = reader,
                    Model = "Rutoken S",
                    Manufacturer = "Aktiv Co.",
                    Kind = kind,
                },
            });

            Assert.Contains(reader, set);
            Assert.False(RutokenExporter.ShouldWalk(reader, set));
        }

        // ---------- дедупликация считывателей между библиотеками разных вендоров ----------

        [Fact]
        public void Place_LetsASuccessfulReadReplaceAFailedOne()
        {
            // Первая библиотека сорвалась на считывателе, вторая его прочитала: в списке должна
            // остаться одна строка — удачная, и на прежнем месте (замечание Codex, PR #25).
            var result = new List<Pkcs11TokenInfo>();
            var seen = new Dictionary<string, Pkcs11ReadState>(StringComparer.OrdinalIgnoreCase);

            Pkcs11Token.Place(result, seen, new Pkcs11TokenInfo { Reader = "JC 0" },
                capabilitiesRead: false, containersRead: false);
            Pkcs11Token.Place(result, seen, new Pkcs11TokenInfo { Reader = "Другой 0", Serial = "a" },
                capabilitiesRead: true, containersRead: true);
            Assert.False(Pkcs11Token.AlreadyRead(seen, "JC 0", readContainers: true));

            Assert.True(Pkcs11Token.Place(result, seen, new Pkcs11TokenInfo { Reader = "JC 0", Serial = "b" },
                capabilitiesRead: true, containersRead: true));

            Assert.Equal(2, result.Count);
            Assert.Equal("b", result[0].Serial);       // заменена на месте, порядок не прыгнул
            Assert.Equal("a", result[1].Serial);
            Assert.True(Pkcs11Token.AlreadyRead(seen, "JC 0", readContainers: true));
        }

        [Fact]
        public void IncompleteCapabilities_LetLaterLibraryRetryWhenContainersAreSkipped()
        {
            // Первая библиотека знает считыватель, но не дочитала механизмы. Даже в режиме без
            // объектов это не должно ставить AlreadyRead и блокировать полную вторую библиотеку.
            var result = new List<Pkcs11TokenInfo>();
            var seen = new Dictionary<string, Pkcs11ReadState>(StringComparer.OrdinalIgnoreCase);
            var incomplete = new Pkcs11TokenInfo
            {
                Reader = "Shared reader 0",
                CapabilitiesKnown = false,
                CapabilityProfile = RutokenCapabilityProfile.Unknown,
            };

            Assert.True(Pkcs11Token.Place(result, seen, incomplete,
                capabilitiesRead: false, containersRead: false));
            Assert.False(Pkcs11Token.AlreadyRead(seen, incomplete.Reader, readContainers: false));

            var complete = new Pkcs11TokenInfo
            {
                Reader = incomplete.Reader,
                CapabilitiesKnown = true,
                CapabilityProfile = RutokenCapabilityProfile.Ecp2Capabilities,
            };
            Assert.True(Pkcs11Token.Place(result, seen, complete,
                capabilitiesRead: true, containersRead: false));
            Assert.Single(result);
            Assert.Same(complete, result[0]);
            Assert.True(result[0].CapabilitiesKnown);
            Assert.Equal(RutokenCapabilityProfile.Ecp2Capabilities, result[0].CapabilityProfile);
            Assert.True(Pkcs11Token.AlreadyRead(seen, complete.Reader, readContainers: false));
        }

        [Fact]
        public void Place_MergesCapabilitiesThenContainersAcrossLibraries()
        {
            var result = new List<Pkcs11TokenInfo>();
            var seen = new Dictionary<string, Pkcs11ReadState>(StringComparer.OrdinalIgnoreCase);
            var capabilities = new Pkcs11TokenInfo
            {
                Reader = "Shared reader 0",
                MechanismCount = 45,
                HardwareRsaMaxBits = 2048,
                HardwareGost = true,
                CapabilitiesKnown = true,
                CapabilityProfile = RutokenCapabilityProfile.Ecp2Capabilities,
            };

            Assert.True(Pkcs11Token.Place(result, seen, capabilities,
                capabilitiesRead: true, containersRead: false));
            Assert.False(Pkcs11Token.AlreadyRead(seen, capabilities.Reader, readContainers: true));

            var container = new Pkcs11Container();
            var containers = new Pkcs11TokenInfo
            {
                Reader = capabilities.Reader,
                Containers = new List<Pkcs11Container> { container },
                CapabilitiesKnown = false,
                CapabilityProfile = RutokenCapabilityProfile.Unknown,
            };
            Assert.True(Pkcs11Token.Place(result, seen, containers,
                capabilitiesRead: false, containersRead: true));

            Assert.Single(result);
            Assert.Same(capabilities, result[0]);
            Assert.True(result[0].CapabilitiesKnown);
            Assert.Equal(45, result[0].MechanismCount);
            Assert.Equal(RutokenCapabilityProfile.Ecp2Capabilities, result[0].CapabilityProfile);
            Assert.Same(container, Assert.Single(result[0].Containers));
            Assert.True(Pkcs11Token.AlreadyRead(seen, capabilities.Reader, readContainers: true));
        }

        [Fact]
        public void Place_MergesContainersThenCapabilitiesAcrossLibraries()
        {
            var result = new List<Pkcs11TokenInfo>();
            var seen = new Dictionary<string, Pkcs11ReadState>(StringComparer.OrdinalIgnoreCase);
            var container = new Pkcs11Container();
            var containers = new Pkcs11TokenInfo
            {
                Reader = "Shared reader 0",
                Containers = new List<Pkcs11Container> { container },
                CapabilitiesKnown = false,
                CapabilityProfile = RutokenCapabilityProfile.Unknown,
            };

            Assert.True(Pkcs11Token.Place(result, seen, containers,
                capabilitiesRead: false, containersRead: true));
            Assert.False(Pkcs11Token.AlreadyRead(seen, containers.Reader, readContainers: true));
            Assert.False(result[0].CapabilitiesKnown);
            Assert.Equal(RutokenCapabilityProfile.Unknown, result[0].CapabilityProfile);

            var capabilities = new Pkcs11TokenInfo
            {
                Reader = containers.Reader,
                MechanismCount = 48,
                HardwareEcdsa = true,
                CapabilitiesKnown = true,
                CapabilityProfile = RutokenCapabilityProfile.Ecp3Capable,
            };
            Assert.True(Pkcs11Token.Place(result, seen, capabilities,
                capabilitiesRead: true, containersRead: false));

            Assert.Single(result);
            Assert.Same(containers, result[0]);
            Assert.True(result[0].CapabilitiesKnown);
            Assert.Equal(48, result[0].MechanismCount);
            Assert.Equal(RutokenCapabilityProfile.Ecp3Capable, result[0].CapabilityProfile);
            Assert.Same(container, Assert.Single(result[0].Containers));
            Assert.True(Pkcs11Token.AlreadyRead(seen, containers.Reader, readContainers: true));
        }

        [Fact]
        public void Place_KeepsOneRowPerReader()
        {
            var result = new List<Pkcs11TokenInfo>();
            var seen = new Dictionary<string, Pkcs11ReadState>(StringComparer.OrdinalIgnoreCase);

            Pkcs11Token.Place(result, seen, new Pkcs11TokenInfo { Reader = "JC 0", Serial = "ok" },
                capabilitiesRead: true, containersRead: true);
            // Прочитанный удачно второй раз не кладётся, и неудачная попытка его не портит.
            Assert.False(Pkcs11Token.Place(result, seen, new Pkcs11TokenInfo { Reader = "jc 0", Serial = "x" },
                capabilitiesRead: true, containersRead: true));
            Assert.False(Pkcs11Token.Place(result, seen, new Pkcs11TokenInfo { Reader = "JC 0", Serial = "y" },
                capabilitiesRead: false, containersRead: false));

            Assert.Single(result);
            Assert.Equal("ok", result[0].Serial);
        }

        [Fact]
        public void Place_DoesNotStackTwoFailuresForOneReader()
        {
            var result = new List<Pkcs11TokenInfo>();
            var seen = new Dictionary<string, Pkcs11ReadState>(StringComparer.OrdinalIgnoreCase);

            Pkcs11Token.Place(result, seen, new Pkcs11TokenInfo { Reader = "JC 0", Serial = "first" },
                capabilitiesRead: false, containersRead: false);
            Assert.False(Pkcs11Token.Place(result, seen, new Pkcs11TokenInfo { Reader = "JC 0", Serial = "second" },
                capabilitiesRead: false, containersRead: false));

            Assert.Single(result);
            Assert.Equal("first", result[0].Serial);
        }

        [Fact]
        public void Place_AddsReadersWithoutNameAsIs()
        {
            // Имени нет — дедуплицировать нечем; терять такой токен нельзя.
            var result = new List<Pkcs11TokenInfo>();
            var seen = new Dictionary<string, Pkcs11ReadState>(StringComparer.OrdinalIgnoreCase);

            Assert.True(Pkcs11Token.Place(result, seen, new Pkcs11TokenInfo { Reader = null },
                capabilitiesRead: true, containersRead: true));
            Assert.True(Pkcs11Token.Place(result, seen, new Pkcs11TokenInfo { Reader = "" },
                capabilitiesRead: false, containersRead: false));

            Assert.Equal(2, result.Count);
            Assert.Empty(seen);
            Assert.False(Pkcs11Token.AlreadyRead(seen, null, readContainers: true));
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
            Assert.Contains(candidates, c => c.EndsWith("rtPKCS11.dll", StringComparison.OrdinalIgnoreCase));
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
            Assert.Contains(candidates, c => c.EndsWith("isbc_pkcs11_main.dll", StringComparison.OrdinalIgnoreCase));
        }

        [Theory]
        [InlineData("jcPKCS11-2.dll")]
        [InlineData("isbc_pkcs11_main.dll")]
        public void LibraryCandidates_ForSingleDllMentionOnlyThatDll(string dll)
        {
            var candidates = Pkcs11Token.LibraryCandidates(dll).ToArray();
            Assert.NotEmpty(candidates);
            Assert.All(candidates, c => Assert.EndsWith(dll, c, StringComparison.OrdinalIgnoreCase));
        }

        [Fact]
        public void KnownLibraries_ContainsFourUniqueConfirmedVendorModules()
        {
            Assert.Collection(Pkcs11Token.KnownLibraries,
                lib => Assert.Equal(("Rutoken", "rtPKCS11ECP.dll"), lib),
                lib => Assert.Equal(("Rutoken S", "rtPKCS11.dll"), lib),
                lib => Assert.Equal(("JaCarta", "jcPKCS11-2.dll"), lib),
                lib => Assert.Equal(("ESMART", "isbc_pkcs11_main.dll"), lib));
            Assert.Equal(Pkcs11Token.KnownLibraries.Count,
                Pkcs11Token.KnownLibraries.Select(lib => lib.Dll)
                    .Distinct(StringComparer.OrdinalIgnoreCase).Count());
        }

        [Fact]
        public void LibraryCandidates_EsmartHasNoUnverifiedProgramFilesFallback()
        {
            var candidates = Pkcs11Token.LibraryCandidates("isbc_pkcs11_main.dll").ToArray();
            string windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows)
                .TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
            // Кэш вшитых зависимостей — не «случайная прикладная копия»: этот файл положили в
            // сборку мы сами, и он распакован нами же. Всё остальное вне %WINDIR% запрещено.
            string bundled = BundledTools.CacheDir.TrimEnd(Path.DirectorySeparatorChar)
                + Path.DirectorySeparatorChar;

            Assert.NotEmpty(candidates);
            Assert.All(candidates, candidate => Assert.True(
                candidate.StartsWith(windows, StringComparison.OrdinalIgnoreCase)
                || candidate.StartsWith(bundled, StringComparison.OrdinalIgnoreCase), candidate));
        }

        [Fact]
        public void BundledCandidate_IsAbsentForTheVendorModuleThatNeedsItsDriverPackage()
        {
            // Рутокен S не вшит намеренно: rtPKCS11.dll импортирует rtAPIi.dll/rtLib.dll из
            // пакета драйверов, а сам носитель без драйвера Aktiv не появляется и в PC/SC.
            Assert.Null(Pkcs11Token.BundledCandidate("rtPKCS11.dll"));
        }

        [Fact]
        public void BundledCandidate_UnpacksEsmartBackendNextToItsEntryModule()
        {
            // Один isbc_pkcs11_main.dll без backend-модуля рядом не даёт рабочей диагностики,
            // поэтому пара обязана распаковываться целиком — независимо от разрядности процесса
            // (сам кандидат в x64 отбрасывается, но файлы на месте должны быть оба).
            Pkcs11Token.BundledCandidate("isbc_pkcs11_main.dll");

            Assert.True(File.Exists(Path.Combine(BundledTools.CacheDir, "isbc_pkcs11_main.dll")));
            Assert.True(File.Exists(Path.Combine(BundledTools.CacheDir, "isbc_esmart_token_mod.dll")));
        }

        [Fact]
        public void BundledCandidate_IsRejectedWhenItsBitnessDoesNotMatchTheProcess()
        {
            // Вшитые копии 32-битные: в x64-процессе они кандидатами быть не должны, иначе
            // перечисление уходило бы в заведомо провальную загрузку библиотеки.
            string candidate = Pkcs11Token.BundledCandidate("rtPKCS11ECP.dll");
            if (RuntimeInformation.ProcessArchitecture == Architecture.X86)
                Assert.NotNull(candidate);
            else
                Assert.Null(candidate);
        }

        [Theory]
        [InlineData(0xFFFFFFFFUL)]                  // CK_UNAVAILABLE_INFORMATION, CK_ULONG 32 бита
        [InlineData(0xFFFFFFFFFFFFFFFFUL)]          // тот же маркер там, где CK_ULONG 64-битный
        public void Memory_TreatsUnavailableInformationAsUnknown(ulong raw)
        {
            Assert.Equal(-1, Pkcs11Token.Memory(raw));
        }

        [Fact]
        public void Memory_KeepsRealValue()
        {
            Assert.Equal(131072, Pkcs11Token.Memory(131072));
        }

        [Fact]
        public void MemorySummary_ReportsSharedPoolOnce()
        {
            // Рутокен ЭЦП отдаёт одинаковые пары public/private — это один пул, и складывать
            // их нельзя: 128 КБ превратились бы в 256 КБ. Числа сняты с живого носителя.
            using var language = Strings.Scope("ru");
            string line = Pkcs11Token.MemorySummary(new Pkcs11TokenInfo
            {
                PublicMemoryTotal = 131072, PublicMemoryFree = 86720,
                PrivateMemoryTotal = 131072, PrivateMemoryFree = 86720,
            });

            Assert.Equal("память 128 КБ, свободно 85 КБ", line);
        }

        [Fact]
        public void MemorySummary_ShowsBothCountersWhenTheyDiffer()
        {
            // Складывать счётчики нельзя: PKCS#11 не сообщает, один это пул или два, и сумма
            // завысила бы объём общего пула (замечание Codex на PR #70). Показываем как есть.
            using var language = Strings.Scope("en");
            string line = Pkcs11Token.MemorySummary(new Pkcs11TokenInfo
            {
                PublicMemoryTotal = 32768, PublicMemoryFree = 16384,
                PrivateMemoryTotal = 65536, PrivateMemoryFree = 32768,
            });

            Assert.Equal("memory: public 32 KB (free 16), private 64 KB (free 32)", line);
        }

        [Fact]
        public void MemorySummary_DoesNotHalveTwoEquallySizedPools()
        {
            // Равные счётчики печатаются одной парой тех же чисел — это не заявление о том,
            // что пул один, и ничего не теряет.
            using var language = Strings.Scope("en");
            string line = Pkcs11Token.MemorySummary(new Pkcs11TokenInfo
            {
                PublicMemoryTotal = 65536, PublicMemoryFree = 32768,
                PrivateMemoryTotal = 65536, PrivateMemoryFree = 32768,
            });

            Assert.Equal("memory 64 KB, free 32 KB", line);
        }

        [Fact]
        public void MemorySummary_ShowsWhatIsKnownWhenOnlyOneCounterIsDeclared()
        {
            using var language = Strings.Scope("en");
            string line = Pkcs11Token.MemorySummary(new Pkcs11TokenInfo
            {
                PublicMemoryTotal = 65536, PublicMemoryFree = 32768,
            });

            Assert.Equal("memory: public 64 KB (free 32), private ? KB (free ?)", line);
        }

        [Fact]
        public void MemorySummary_IsSilentWhenTheTokenDoesNotDeclareIt()
        {
            using var language = Strings.Scope("ru");
            Assert.Null(Pkcs11Token.MemorySummary(new Pkcs11TokenInfo()));
        }

        [Fact]
        public void MemorySummary_ShowsQuestionMarkForUndeclaredFreeSpace()
        {
            using var language = Strings.Scope("ru");
            string line = Pkcs11Token.MemorySummary(new Pkcs11TokenInfo
            {
                PublicMemoryTotal = 65536, PrivateMemoryTotal = 65536,
            });

            Assert.Equal("память 64 КБ, свободно ? КБ", line);
        }

        [Fact]
        public void CapabilitySummary_AppendsMemoryOnlyWhenKnown()
        {
            using var language = Strings.Scope("ru");
            var withMemory = new Pkcs11TokenInfo
            {
                Hardware = "67.04", MechanismCount = 70, CapabilitiesKnown = true,
                PublicMemoryTotal = 131072, PublicMemoryFree = 86720,
                PrivateMemoryTotal = 131072, PrivateMemoryFree = 86720,
            };

            Assert.EndsWith("; память 128 КБ, свободно 85 КБ",
                Pkcs11Token.CapabilitySummary(withMemory), StringComparison.Ordinal);
            Assert.DoesNotContain("память",
                Pkcs11Token.CapabilitySummary(new Pkcs11TokenInfo { Hardware = "20.05" }),
                StringComparison.Ordinal);
        }

        [Fact]
        public void IsLibraryComplete_EsmartRequiresMainAndCompanionTogether()
        {
            string dir = Path.Combine(Path.GetTempPath(), "cpx-esmart-libs-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dir);
            string main = Path.Combine(dir, "isbc_pkcs11_main.dll");
            string companion = Path.Combine(dir, "isbc_esmart_token_mod.dll");
            try
            {
                WritePeStub(main, RuntimeInformation.ProcessArchitecture);
                Assert.False(Pkcs11Token.IsLibraryComplete("isbc_pkcs11_main.dll", main));

                File.Delete(main);
                WritePeStub(companion, RuntimeInformation.ProcessArchitecture);
                Assert.False(Pkcs11Token.IsLibraryComplete("isbc_pkcs11_main.dll", main));

                WritePeStub(main, RuntimeInformation.ProcessArchitecture);
                Assert.True(Pkcs11Token.IsLibraryComplete("isbc_pkcs11_main.dll", main));

                Architecture otherArchitecture = RuntimeInformation.ProcessArchitecture == Architecture.X86
                    ? Architecture.X64
                    : Architecture.X86;
                WritePeStub(companion, otherArchitecture);
                Assert.False(Pkcs11Token.IsLibraryComplete("isbc_pkcs11_main.dll", main));
            }
            finally
            {
                Directory.Delete(dir, recursive: true);
            }
        }

        [Theory]
        [InlineData("rtPKCS11ECP.dll")]
        [InlineData("rtPKCS11.dll")]
        [InlineData("jcPKCS11-2.dll")]
        public void IsLibraryComplete_StandaloneVendorsRequireOnlyMain(string dll)
        {
            string dir = Path.Combine(Path.GetTempPath(), "cpx-standalone-lib-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dir);
            string main = Path.Combine(dir, dll);
            try
            {
                Assert.False(Pkcs11Token.IsLibraryComplete(dll, main));
                File.WriteAllBytes(main, Array.Empty<byte>());
                Assert.True(Pkcs11Token.IsLibraryComplete(dll, main));
            }
            finally
            {
                Directory.Delete(dir, recursive: true);
            }
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
        public void UniqueCertPath_DoesNotOverwriteFileFromPreviousRun()
        {
            string dir = Path.Combine(Path.GetTempPath(), "cpx-cert-path-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dir);
            string existing = Path.Combine(dir, "Ivanov_aaa.cer");
            File.WriteAllBytes(existing, new byte[] { 1 });
            try
            {
                string next = Pkcs11Token.UniqueCertPath(dir, "Ivanov", "aaa",
                    new HashSet<string>(StringComparer.OrdinalIgnoreCase));

                Assert.Equal(Path.Combine(dir, "Ivanov_aaa(2).cer"), next);
                Assert.Equal(new byte[] { 1 }, File.ReadAllBytes(existing));
            }
            finally { Directory.Delete(dir, recursive: true); }
        }

        [Fact]
        public void LibraryCandidates_HasNoDuplicates()
        {
            var candidates = Pkcs11Token.LibraryCandidates().ToArray();
            Assert.Equal(candidates.Length, candidates.Distinct(StringComparer.OrdinalIgnoreCase).Count());
        }

        private static void WritePeStub(string path, Architecture architecture)
        {
            ushort machine = architecture switch
            {
                Architecture.X86 => 0x014c,
                Architecture.X64 => 0x8664,
                Architecture.Arm64 => 0xAA64,
                _ => throw new ArgumentOutOfRangeException(nameof(architecture)),
            };
            var bytes = new byte[0x86];
            bytes[0x3c] = 0x80;
            bytes[0x80] = (byte)'P';
            bytes[0x81] = (byte)'E';
            bytes[0x84] = (byte)(machine & 0xff);
            bytes[0x85] = (byte)(machine >> 8);
            File.WriteAllBytes(path, bytes);
        }
    }
}
