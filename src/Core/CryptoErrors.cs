using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace CryptoProExport
{
    /// <summary>
    /// Расшифровка кодов ошибок CryptoAPI/КриптоПро/смарт-карт в человекочитаемый текст.
    /// Без неё пользователь видит только «0x8010006C» и не понимает, что дело в PIN.
    /// </summary>
    public static class CryptoErrors
    {
        private static readonly Dictionary<uint, string> Known = new Dictionary<uint, string>
        {
            // CryptoAPI / CSP
            [0x80090008] = "NTE_BAD_ALGID: провайдер не поддерживает запрошенный алгоритм",
            [0x8009000B] = "NTE_BAD_KEY_STATE: ключ не в том состоянии — обычно закрытый ключ не помечен экспортируемым",
            [0x8009000D] = "NTE_NO_KEY: в контейнере нет ключа запрошенного типа",
            [0x8009000F] = "NTE_EXISTS: объект с таким именем уже существует",
            [0x80090010] = "NTE_PERM: операция запрещена — ключ неэкспортируемый либо нет прав",
            [0x80090011] = "NTE_NOT_FOUND: объект не найден",
            [0x80090016] = "NTE_BAD_KEYSET: контейнер не найден или недоступен (вынут носитель? другое имя?)",
            [0x8009001D] = "NTE_PROVIDER_DLL_FAIL: не удалось загрузить библиотеку провайдера",
            [0x80090020] = "NTE_FAIL: внутренняя ошибка провайдера",
            [0x80090022] = "NTE_SILENT_CONTEXT: нужен диалог с пользователем, а контекст открыт в тихом режиме",
            [0x8009001F] = "NTE_BAD_KEYSET_PARAM: неверный параметр контейнера",
            [0x80090029] = "NTE_NOT_SUPPORTED: операция не поддерживается провайдером",

            // Смарт-карты / токены
            [0x8010000C] = "SCARD_E_NOT_TRANSACTED: не удалось выполнить транзакцию с картой",
            [0x8010001E] = "SCARD_E_CANCELLED: операция отменена",
            [0x80100017] = "SCARD_E_READER_UNAVAILABLE: считыватель недоступен",
            [0x8010002E] = "SCARD_E_NO_READERS_AVAILABLE: не найдено ни одного считывателя смарт-карт",
            [0x8010000B] = "SCARD_E_SHARING_VIOLATION: карта занята другим приложением",
            // Нумерация SCARD_W_* сверена с winerror.h и системными сообщениями Windows
            // (31.08.2026): прежняя таблица была сдвинута и называла заблокированный PIN
            // «неверным», а неверный — «нет авторизации».
            [0x80100065] = "SCARD_W_UNSUPPORTED_CARD: носитель не поддерживается — его ATR не описан в списке известных карт (у КриптоПро это «конфликт настройки ATR»)",
            [0x80100066] = "SCARD_W_UNRESPONSIVE_CARD: карта не отвечает",
            [0x80100067] = "SCARD_W_UNPOWERED_CARD: на карту не подано питание",
            [0x80100068] = "SCARD_W_RESET_CARD: карта была сброшена — сессию нужно открыть заново",
            [0x80100069] = "SCARD_W_REMOVED_CARD: носитель извлечён",
            [0x8010006A] = "SCARD_W_SECURITY_VIOLATION: карта отказала в доступе",
            [0x8010006B] = "SCARD_W_WRONG_CHV: неверный PIN-код",
            [0x8010006C] = "SCARD_W_CHV_BLOCKED: PIN-код заблокирован, нужен разблокирующий код",
            [0x8010006D] = "SCARD_W_EOF: достигнут конец файла на карте",
            [0x8010006E] = "SCARD_W_CANCELLED_BY_USER: операцию отменил пользователь (закрыт диалог выбора носителя или ввода PIN)",
            [0x8010006F] = "SCARD_W_CARD_NOT_AUTHENTICATED: не выполнена авторизация на носителе",

            // Общие
            [0x800704C7] = "Операция отменена пользователем",
            [0x80040154] = "REGDB_E_CLASSNOTREG: COM-класс не зарегистрирован в системе",
            [0x800700C1] = "Неверный формат исполняемого файла — скорее всего, несовпадение разрядности",
        };

        /// <summary>Описание кода ошибки. Понимает и HRESULT, и обычные коды Win32/возврата процесса.</summary>
        public static string Describe(int code)
        {
            if (code == 0) return "OK";
            uint u = unchecked((uint)code);
            if (Known.TryGetValue(u, out string text)) return $"0x{u:X8} — {text}";

            // Win32-код, обёрнутый в HRESULT (FACILITY_WIN32)
            if ((u & 0xFFFF0000) == 0x80070000)
                return $"0x{u:X8} — {SystemMessage(unchecked((int)(u & 0xFFFF)))}";

            if (u >= 0x80000000)
                return $"0x{u:X8} — неизвестная ошибка CryptoAPI/COM";

            return $"код {code} — {SystemMessage(code)}";
        }

        /// <summary>Описание последней ошибки Win32 (после неудачного P/Invoke).</summary>
        public static string DescribeLastError() => Describe(Marshal.GetLastWin32Error());

        private static string SystemMessage(int win32Code)
        {
            try { return new Win32Exception(win32Code).Message; }
            catch (Exception) { return "нет системного описания"; }
        }
    }
}
