using System;
using System.Collections.Generic;
using System.Runtime.Versioning;

namespace CryptoProExport
{
    /// <summary>Компонент, без которого операция физически не выполнится.</summary>
    public enum RequiredComponent
    {
        /// <summary>КриптоПро CSP — единственная внешняя зависимость, вшить её нельзя.</summary>
        CryptoProCsp,
        /// <summary>p12utility: внешняя копия или вшитая, распакованная в кэш.</summary>
        P12Utility,
        /// <summary>rtCOMLite: вшитая копия без регистрации или зарегистрированный в системе компонент.</summary>
        RtComLite,
        /// <summary>Хотя бы одна библиотека PKCS#11 (системная или вшитая).</summary>
        Pkcs11,
    }

    /// <summary>
    /// Операцию нельзя начинать: нужного компонента нет.
    ///
    /// Отдельный тип нужен, чтобы отказ был отличим от прикладной ошибки: раньше отсутствие
    /// p12utility приходило как <see cref="System.IO.FileNotFoundException"/>, неотличимый от
    /// «не найден файл контейнера», а отсутствие rtCOMLite — как безымянный
    /// <see cref="InvalidOperationException"/>. Текст сообщения — локализованный и уже содержит
    /// то, что нужно поставить.
    /// </summary>
    public sealed class ComponentMissingException : InvalidOperationException
    {
        public ComponentMissingException(RequiredComponent component)
            : base(ComponentCheck.Explain(component))
        {
            Component = component;
        }

        /// <summary>Какого именно компонента не хватило.</summary>
        public RequiredComponent Component { get; }
    }

    /// <summary>
    /// Проверка наличия компонентов перед операцией — «под капотом», без строк в журнале.
    ///
    /// Раньше приложение при запуске отчитывалось, что зависимости вшиты и ставить ничего не
    /// нужно. Такая строка ничего не проверяла и ни на что не влияла: в норме она была шумом,
    /// а в единственном случае, когда она была бы важна (компонента нет), её вовсе не печатали.
    /// Теперь наличие проверяется там, где компонент реально нужен, и отсутствие превращается в
    /// <see cref="ComponentMissingException"/> с готовым объяснением вместо невнятного отказа
    /// изнутри COM или запущенного процесса. Отчёт о зависимостях (<c>deps</c> и журнал при
    /// запуске) остаётся единственным местом, где о них рассказывают, и печатает только
    /// отклонения.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public static class ComponentCheck
    {
        /// <summary>Есть ли компонент. Никогда не бросает: недоступность — это <c>false</c>.</summary>
        public static bool IsPresent(RequiredComponent component)
        {
            try
            {
                switch (component)
                {
                    case RequiredComponent.CryptoProCsp:
                        return CertFromContainer.AvailableProviders().Count > 0;
                    case RequiredComponent.P12Utility:
                        return P12Utility.Resolve() != null;
                    case RequiredComponent.RtComLite:
                        return RutokenExporter.UsesBundledCopy()
                            || Type.GetTypeFromProgID(RutokenExporter.ProgId, throwOnError: false) != null;
                    case RequiredComponent.Pkcs11:
                        return Pkcs11Token.IsAvailable;
                    default:
                        return false;
                }
            }
            catch
            {
                // Сбой самой проверки — это «компонента нет», а не авария операции: вызывающий
                // получит понятный ComponentMissingException вместо чужого исключения.
                return false;
            }
        }

        /// <summary>Отсутствующие компоненты из перечисленных, в том же порядке.</summary>
        public static List<RequiredComponent> Missing(params RequiredComponent[] components)
        {
            var missing = new List<RequiredComponent>();
            foreach (RequiredComponent component in components ?? Array.Empty<RequiredComponent>())
                if (!IsPresent(component)) missing.Add(component);
            return missing;
        }

        /// <summary>Проверить и остановить операцию, если компонента нет.</summary>
        /// <exception cref="ComponentMissingException">Компонент отсутствует.</exception>
        public static void Require(RequiredComponent component)
        {
            if (!IsPresent(component)) throw new ComponentMissingException(component);
        }

        /// <summary>
        /// Локализованное объяснение, чего не хватает и что с этим делать. Тексты те же, что
        /// показывает отчёт о зависимостях, — второй формулировки одного и того же не заводим.
        /// </summary>
        public static string Explain(RequiredComponent component) => Strings.Get(component switch
        {
            RequiredComponent.CryptoProCsp => "diag.csp.missing",
            RequiredComponent.P12Utility => "err.p12.unavailable",
            RequiredComponent.RtComLite => "token.rtcom.unavailable",
            RequiredComponent.Pkcs11 => "pkcs11.nolib",
            _ => "diag.notfound",
        });
    }
}
