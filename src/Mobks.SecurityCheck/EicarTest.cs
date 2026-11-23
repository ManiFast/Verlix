using System;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace Mobks.SecurityCheck
{
    internal static class EicarTest
    {
        private const int ObservationMilliseconds = 10000;
        private const string EicarSha256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

        internal static Task<EicarTestResult> RunAsync(string sourcePath, CancellationToken cancellation, TechnicalLog trace)
        {
            return Task.Run(() => RunCoreAsync(sourcePath, cancellation, trace));
        }

        private static async Task<EicarTestResult> RunCoreAsync(string sourcePath, CancellationToken cancellation, TechnicalLog trace)
        {
            var result = new EicarTestResult { Started = DateTimeOffset.Now };
            string folder = null;
            bool written = false, readable = false, disappeared = false;
            try
            {
                cancellation.ThrowIfCancellationRequested();
                if (string.IsNullOrWhiteSpace(sourcePath))
                {
                    result.Outcome = EicarOutcome.NoFile;
                    result.Description = "Файл EICAR не выбран. Нажмите «Файл…» и укажите подготовленный TXT.";
                    trace.Write("EICAR", "Тест пропущен: исходный файл не выбран. Образец не создавался.");
                    return result;
                }
                result.SourcePath = Path.GetFullPath(sourcePath);
                byte[] content = ReadPreparedSample(result.SourcePath, trace);
                if (content == null)
                {
                    result.Outcome = EicarOutcome.InvalidFile;
                    result.Description = "Выбранный файл не соответствует EICAR. Проверьте строку и кодировку без BOM.";
                    return result;
                }
                cancellation.ThrowIfCancellationRequested();
                trace.Write("EICAR", "CALL Environment.GetFolderPath(LocalApplicationData)");
                string dataFolder = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
                trace.Write("EICAR", "RETURN LocalApplicationData=" + dataFolder);
                if (string.IsNullOrWhiteSpace(dataFolder))
                    throw new DirectoryNotFoundException("Не удалось определить папку данных пользователя.");
                folder = Path.Combine(dataFolder, "Velrix", "Tests", "EICAR-" + Guid.NewGuid().ToString("N"));
                result.FilePath = Path.Combine(folder, "eicar.com.txt");
                trace.Write("EICAR", "CALL Directory.CreateDirectory(\"" + folder + "\")");
                Directory.CreateDirectory(folder);
                trace.Write("EICAR", "RETURN Directory.CreateDirectory: завершён без исключения.");
                try
                {
                    // Рабочая копия содержит байты выбранного файла; тестовая строка не генерируется.
                    trace.Write("EICAR", "Копирование проверенного образца: Source=" + result.SourcePath +
                        "; Destination=" + result.FilePath + "; Length=" + content.Length);
                    trace.Write("EICAR", "CALL FileStream(\"" + result.FilePath +
                        "\", CreateNew, Write, Share=Read|Delete); Write(count=" + content.Length + ")");
                    using (var file = new FileStream(result.FilePath, FileMode.CreateNew, FileAccess.Write,
                        FileShare.Read | FileShare.Delete))
                        file.Write(content, 0, content.Length);
                    written = true;
                    trace.Write("EICAR", "RETURN Write/Dispose: рабочая копия записана; " + content.Length + " байт.");
                }
                catch (Exception error) when (error is IOException || error is UnauthorizedAccessException)
                {
                    trace.Error("EICAR", error);
                    if (RecordAntivirusBlock(error, result, trace)) return result;
                    result.TechnicalNote = "Запись файла: " + error.Message;
                }

                bool logAvailable = true;
                Stopwatch observation = Stopwatch.StartNew();
                trace.Write("EICAR", "Начало наблюдения: лимит=" + ObservationMilliseconds + " мс; пауза между проверками до 500 мс.");
                while (true)
                {
                    cancellation.ThrowIfCancellationRequested();
                    if (written)
                    {
                        try
                        {
                            trace.Write("EICAR", "CALL File.ReadAllBytes(\"" + result.FilePath + "\")");
                            byte[] actual = File.ReadAllBytes(result.FilePath);
                            readable = actual.SequenceEqual(content);
                            trace.Write("EICAR", "RETURN Length=" + actual.Length + "; EqualsExpected=" + readable);
                            if (!readable) result.TechnicalNote = "Содержимое тестового файла изменилось.";
                        }
                        catch (FileNotFoundException error)
                        { trace.Error("EICAR", error); disappeared = true; readable = false; }
                        catch (DirectoryNotFoundException error)
                        { trace.Error("EICAR", error); disappeared = true; readable = false; }
                        catch (Exception error) when (error is IOException || error is UnauthorizedAccessException)
                        {
                            trace.Error("EICAR", error);
                            if (RecordAntivirusBlock(error, result, trace)) return result;
                            readable = false;
                            result.TechnicalNote = "Чтение файла: " + error.Message;
                        }
                    }
                    if (logAvailable)
                    {
                        try
                        {
                            string evidence = FindDefenderDetection(result, cancellation, trace);
                            if (evidence != null)
                            {
                                result.Outcome = EicarOutcome.Detected;
                                result.Description = "Microsoft Defender обнаружил EICAR.";
                                result.Evidence = evidence;
                                return result;
                            }
                        }
                        catch (OperationCanceledException) { throw; }
                        catch (Exception error)
                        {
                            trace.Error("DEFENDER LOG", error);
                            logAvailable = false;
                            result.LogNote = "Журнал Microsoft Defender недоступен: " + error.Message;
                        }
                    }
                    int remaining = ObservationMilliseconds - (int)observation.ElapsedMilliseconds;
                    if (remaining <= 0) break;
                    await Task.Delay(Math.Min(500, remaining), cancellation).ConfigureAwait(false);
                }
                trace.Write("EICAR", "Итог наблюдения: Elapsed=" + observation.ElapsedMilliseconds +
                    " ms; Written=" + written + "; Readable=" + readable + "; Disappeared=" + disappeared +
                    "; LogAvailable=" + logAvailable + "; подтверждения обнаружения нет.");
                if (written && readable && !disappeared)
                {
                    result.Outcome = EicarOutcome.NoReaction;
                    result.Description = "За 10 с обнаружение не подтверждено; тестовый файл оставался доступен.";
                }
                else
                {
                    result.Description = disappeared ?
                        "Тестовый файл исчез, но реакция антивируса автоматически не подтверждена." :
                        "Не удалось подтвердить реакцию антивируса. Подробности есть в отчёте.";
                }
            }
            catch (OperationCanceledException error)
            {
                trace.Error("EICAR", error);
                result.Outcome = EicarOutcome.Cancelled;
                result.Description = "Тест остановлен пользователем.";
            }
            catch (Exception error)
            {
                trace.Error("EICAR", error);
                result.Description = "Не удалось выполнить тест. Подробности есть в отчёте.";
                result.TechnicalNote = error.Message;
            }
            finally
            {
                await CleanUpAsync(result, folder, trace).ConfigureAwait(false);
                result.Completed = DateTimeOffset.Now;
                trace.Write("EICAR", "RETURN Outcome=" + result.Outcome + "; CleanupSucceeded=" + result.CleanupSucceeded);
            }
            return result;
        }

        private static byte[] ReadPreparedSample(string path, TechnicalLog trace)
        {
            trace.Write("EICAR SOURCE", "CALL FileStream(\"" + path + "\", Open, Read, Share=Read)");
            using (var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                trace.Write("EICAR SOURCE", "RETURN Length=" + file.Length);
                if (file.Length < 68 || file.Length > 128) return null;
                byte[] data = new byte[(int)file.Length];
                int offset = 0;
                while (offset < data.Length)
                {
                    int read = file.Read(data, offset, data.Length - offset);
                    trace.Write("EICAR SOURCE", "RETURN Read: Count=" + read);
                    if (read == 0) return null;
                    offset += read;
                }
                string checksum;
                using (SHA256 hash = SHA256.Create())
                    checksum = BitConverter.ToString(hash.ComputeHash(data, 0, 68)).Replace("-", "").ToLowerInvariant();
                bool trailingWhitespace = data.Skip(68).All(value =>
                    value == 32 || value == 9 || value == 10 || value == 13 || value == 26);
                bool valid = checksum == EicarSha256 && trailingWhitespace;
                trace.Write("EICAR SOURCE", "RETURN First68Bytes.SHA256=" + checksum +
                    "; AllowedTrailingWhitespace=" + trailingWhitespace + "; ValidEicar=" + valid);
                return valid ? data : null;
            }
        }

        private static bool RecordAntivirusBlock(Exception error, EicarTestResult result, TechnicalLog trace)
        {
            uint code = unchecked((uint)error.HResult);
            if (code != 0x800700E1u && code != 0x800700E2u) return false;
            result.Outcome = EicarOutcome.Blocked;
            result.Description = "Windows сообщила об антивирусной блокировке тестового файла.";
            result.Evidence = "HRESULT 0x" + code.ToString("X8") + (code == 0x800700E1u ?
                " — ERROR_VIRUS_INFECTED (225)." : " — ERROR_VIRUS_DELETED (226).");
            trace.Write("EICAR", "Подтверждение: " + result.Evidence);
            return true;
        }

        private static string FindDefenderDetection(EicarTestResult result, CancellationToken cancellation, TechnicalLog trace)
        {
            string since = result.Started.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture);
            string xpath = "*[System[(EventID=1116) and TimeCreated[@SystemTime >= '" + since + "']]]";
            trace.Write("DEFENDER LOG", "CALL EventLogReader\r\nChannel=Microsoft-Windows-Windows Defender/Operational" +
                "\r\nXPath=" + xpath + "; ReverseDirection=True; ReadTimeout=250 ms; MaxRecords=64");
            var query = new EventLogQuery("Microsoft-Windows-Windows Defender/Operational", PathType.LogName, xpath)
            { ReverseDirection = true };
            int scanned = 0;
            using (var reader = new EventLogReader(query))
            {
                for (int i = 0; i < 64; i++)
                {
                    cancellation.ThrowIfCancellationRequested();
                    using (EventRecord record = reader.ReadEvent(TimeSpan.FromMilliseconds(250)))
                    {
                        if (record == null) break;
                        scanned++;
                        if (record.ProviderName != "Microsoft-Windows-Windows Defender" ||
                            !record.TimeCreated.HasValue || record.TimeCreated.Value.ToUniversalTime() < result.Started.UtcDateTime)
                            continue;
                        string[] values = record.Properties.Select(property =>
                            Convert.ToString(property.Value, CultureInfo.InvariantCulture)).ToArray();
                        // Новое событие обнаружения должно содержать полный уникальный путь этого запуска.
                        if (values.Any(value => value.IndexOf(result.FilePath, StringComparison.OrdinalIgnoreCase) >= 0))
                        {
                            trace.Write("DEFENDER LOG", "RETURN Совпал тестовый путь; RecordId=" + record.RecordId);
                            try { trace.Write("DEFENDER LOG", "EventRecord.ToXml():\r\n" + record.ToXml()); }
                            catch (Exception error) { trace.Error("DEFENDER XML", error); }
                            return "Microsoft Defender: событие 1116, запись " + record.RecordId + ", " +
                                record.TimeCreated.Value.ToString("dd.MM.yyyy HH:mm:ss") + ". Совпал полный путь тестового файла.";
                        }
                    }
                }
            }
            trace.Write("DEFENDER LOG", "RETURN RecordsRead=" + scanned + "; Match=False; LimitReached=" + (scanned == 64));
            return null;
        }

        private static async Task CleanUpAsync(EicarTestResult result, string folder, TechnicalLog trace)
        {
            if (folder == null) return;
            for (int attempt = 0; attempt < 5; attempt++)
            {
                result.CleanupNote = "";
                try
                {
                    trace.Write("CLEANUP", "CALL File.Delete(\"" + result.FilePath + "\"); попытка=" + (attempt + 1));
                    File.Delete(result.FilePath);
                    trace.Write("CLEANUP", "RETURN File.Delete: завершён без исключения.");
                }
                catch (DirectoryNotFoundException error) { trace.Error("CLEANUP", error); }
                catch (Exception error)
                { trace.Error("CLEANUP", error); result.CleanupNote = "Удаление файла: " + error.Message; }
                try
                {
                    // Только собственная папка и без рекурсивного удаления посторонних файлов.
                    trace.Write("CLEANUP", "CALL Directory.Delete(\"" + folder + "\", recursive=False)");
                    Directory.Delete(folder, false);
                    trace.Write("CLEANUP", "RETURN Directory.Delete: завершён без исключения.");
                    result.CleanupNote = "";
                    return;
                }
                catch (DirectoryNotFoundException error)
                { trace.Error("CLEANUP", error); result.CleanupNote = ""; return; }
                catch (Exception error)
                { trace.Error("CLEANUP", error); result.CleanupNote += " Удаление папки: " + error.Message; }
                if (attempt < 4) await Task.Delay(200).ConfigureAwait(false);
            }
            result.CleanupSucceeded = false;
        }
    }

    internal enum EicarOutcome { Unknown, Blocked, Detected, NoReaction, Cancelled, NoFile, InvalidFile }

    internal sealed class EicarTestResult
    {
        internal EicarOutcome Outcome;
        internal DateTimeOffset Started, Completed;
        internal string FilePath = "";
        internal string SourcePath = "";
        internal string Description = "";
        internal string Evidence = "";
        internal string TechnicalNote = "";
        internal string LogNote = "";
        internal string CleanupNote = "";
        internal bool CleanupSucceeded = true;
        internal bool ReactionConfirmed
        {
            get { return Outcome == EicarOutcome.Blocked || Outcome == EicarOutcome.Detected; }
        }
        internal string Status
        {
            get
            {
                switch (Outcome)
                {
                    case EicarOutcome.Blocked: return "Заблокирован";
                    case EicarOutcome.Detected: return "Обнаружен";
                    case EicarOutcome.NoReaction: return "Не подтверждено";
                    case EicarOutcome.Cancelled: return "Остановлено";
                    case EicarOutcome.NoFile: return "Файл не выбран";
                    case EicarOutcome.InvalidFile: return "Не EICAR";
                    default: return "Нет подтверждения";
                }
            }
        }
    }
}


