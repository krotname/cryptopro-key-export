namespace CryptoProExport
{
    /// <summary>
    /// Тип выделенной в списке окна строки. Это единственное, от чего зависит доступность
    /// действий: строки списка приходят из разных источников (CSP, PKCS#11, прямой APDU,
    /// rtCOMLite, просто устройство), и половина кнопок работает не с каждым из них.
    /// </summary>
    public enum SelectedRow
    {
        /// <summary>Ничего не выделено.</summary>
        None,
        /// <summary>Контейнер, видимый КриптоПро CSP (в том числе HDIMAGE-копия).</summary>
        Csp,
        /// <summary>Строка PKCS#11: контейнер носителя, сертификат прочитан.</summary>
        TokenWithCert,
        /// <summary>Строка PKCS#11: контейнер носителя, сертификата в нём нет.</summary>
        TokenWithoutCert,
        /// <summary>
        /// Строка PKCS#11: сертификат-сирота без парного <c>CKO_DATA</c>. Контейнера за такой
        /// строкой нет вовсе (AGENTS п. 30), поэтому её имя нельзя отдавать ни CryptoAPI, ни
        /// certmgr: они разрешили бы его в посторонний одноимённый контейнер CSP.
        /// </summary>
        TokenCertificateOnly,
        /// <summary>Контейнер, читаемый прямым APDU (Rutoken S/Lite, JaCarta LT/PRO, ESMART).</summary>
        Apdu,
        /// <summary>Контейнер, найденный legacy-путём rtCOMLite.</summary>
        Direct,
        /// <summary>Только устройство: считыватель или носитель без единого контейнера в строке.</summary>
        Device,
    }

    /// <summary>Действие окна, доступность которого зависит от выделенной строки.</summary>
    public enum RowAction
    {
        /// <summary>«Экспорт с токена» — снять файлы контейнера с носителя.</summary>
        Export,
        /// <summary>«Сделать экспортируемым» — снять контейнер и убрать запрет на экспорт ключа.</summary>
        MakeExportable,
        /// <summary>«Извлечь сертификат» — сохранить .cer выделенного контейнера.</summary>
        ExtractCert,
        /// <summary>«Посмотреть контейнер» — показать права обоих ключей.</summary>
        ViewContainer,
        /// <summary>«Экспорт в PFX» — выгрузить выделенный контейнер через certmgr.</summary>
        ExportPfx,
    }

    /// <summary>
    /// Можно ли выполнить действие по такой строке — и если нельзя, то почему.
    ///
    /// Раньше все кнопки были включены всегда, а несовпадение строки и действия выяснялось
    /// уже после нажатия, строкой в журнале. Здесь то же знание получено заранее: кнопка
    /// гасится, а причина уходит в её собственную подсказку (ROADMAP, P2, п. 2).
    ///
    /// Таблица намеренно отвечает только на то, что видно по типу строки. Всё, что требует
    /// обращения к носителю или к CSP (есть ли ключ, снят ли запрет, видит ли certmgr имя),
    /// по-прежнему проверяется самой операцией: гасить кнопку по догадке хуже, чем показать
    /// точный результат попытки.
    /// </summary>
    public static class ActionAvailability
    {
        /// <summary>
        /// Ключ строки с причиной отказа или <c>null</c>, если действие доступно.
        /// Возвращается именно ключ: причина показывается на языке интерфейса.
        /// </summary>
        public static string ReasonKey(RowAction action, SelectedRow row)
        {
            // Строка «только устройство» не годится ни одному действию: контейнера в ней нет.
            if (row == SelectedRow.Device) return "hint.row.device";

            switch (action)
            {
                // Снятие с носителя идёт мимо CSP и умеет ровно два источника: прямой APDU и
                // legacy rtCOMLite. Без выделения обе операции обходят все поддерживаемые
                // носители — это рабочий сценарий, поэтому пустой список кнопку не гасит.
                case RowAction.Export:
                case RowAction.MakeExportable:
                    return row switch
                    {
                        SelectedRow.None or SelectedRow.Apdu or SelectedRow.Direct => null,
                        SelectedRow.Csp => "hint.row.csp",
                        _ => "hint.row.pkcs11",
                    };

                // Сертификат достаётся из самой строки (PKCS#11) или через CryptoAPI (остальные).
                // Отсутствие сертификата в строке PKCS#11 видно заранее — это не попытка.
                // Сертификат-сирота извлекается как раз этим действием: он для того и в списке.
                case RowAction.ExtractCert:
                    return row switch
                    {
                        SelectedRow.None => "hint.need.row",
                        SelectedRow.TokenWithoutCert => "hint.cert.none",
                        _ => null,
                    };

                // Остальным действиям нужен ровно один выделенный контейнер — любого источника.
                // За строкой сертификата-сироты контейнера нет, и адресовать по её имени нечего.
                default:
                    return row switch
                    {
                        SelectedRow.None => "hint.need.row",
                        SelectedRow.TokenCertificateOnly => "hint.row.certonly",
                        _ => null,
                    };
            }
        }

        /// <summary>Действие доступно по такой строке.</summary>
        public static bool IsAllowed(RowAction action, SelectedRow row) => ReasonKey(action, row) == null;
    }
}
