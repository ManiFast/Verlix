using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Mobks.SecurityCheck
{
    internal static class FirewallTest
    {
        private const int Port = 443;
        private const int NetworkTimeout = 3500;

        internal static Task<FirewallTestResult> RunAsync(string[] hosts, CancellationToken cancellation,
            TechnicalLog trace, IProgress<string> progress)
        {
            return Task.Run(() => RunCoreAsync(hosts, cancellation, trace, progress));
        }

        private static async Task<FirewallTestResult> RunCoreAsync(string[] hosts, CancellationToken cancellation,
            TechnicalLog trace, IProgress<string> progress)
        {
            var result = new FirewallTestResult { Started = DateTimeOffset.Now };
            object policy = null, rules = null, rule = null;
            IPAddress address = null;
            bool addAttempted = false;
            int profiles = 0;
            try
            {
                cancellation.ThrowIfCancellationRequested();
                using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
                    result.IsAdministrator = new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
                trace.Write("FW TEST", "WindowsPrincipal.IsInRole(Administrator)=" + result.IsAdministrator);
                if (!result.IsAdministrator)
                {
                    result.Outcome = FirewallTestOutcome.NeedsAdministrator;
                    result.Note = "Для временного правила запустите Velrix от имени администратора.";
                    return result;
                }
                using (Process process = Process.GetCurrentProcess()) result.ProgramPath = process.MainModule.FileName;
                policy = CreateCom("HNetCfg.FwPolicy2", trace);
                profiles = ReadPolicy(policy, trace);
                if (profiles == 0)
                {
                    result.Note = "Не подтверждены включённые активные профили или доступность локальных правил Windows.";
                    return result;
                }

                progress.Report("Исходное соединение…");
                foreach (string host in hosts.Distinct().Take(2))
                {
                    foreach (IPAddress candidate in await ResolveAsync(host, cancellation, trace).ConfigureAwait(false))
                    {
                        cancellation.ThrowIfCancellationRequested();
                        TcpAttempt attempt = await ConnectAsync(candidate, cancellation, trace, "До правила").ConfigureAwait(false);
                        if (attempt.Outcome == TcpOutcome.Cancelled) cancellation.ThrowIfCancellationRequested();
                        if (attempt.Outcome != TcpOutcome.Connected) continue;
                        address = candidate;
                        result.Host = host;
                        result.Address = address.ToString();
                        result.Before = attempt;
                        break;
                    }
                    if (address != null) break;
                }
                if (address == null)
                {
                    result.Note = "Исходное прямое TCP-соединение не установлено. Проверить блокировку пока нельзя.";
                    return result;
                }
                if (ReadPolicy(policy, trace) != profiles)
                {
                    result.Note = "Профиль сети изменился до создания правила.";
                    return result;
                }
                rules = Get(policy, "Rules", trace);
                result.RuleName = "Velrix-Test-" + Guid.NewGuid().ToString("N");
                object existing = FindRule(rules, result.RuleName, trace);
                if (existing != null)
                {
                    Release(existing);
                    result.Note = "Имя временного правила уже занято. Существующее правило не изменялось.";
                    return result;
                }
                rule = CreateCom("HNetCfg.FWRule", trace);
                Set(rule, "Name", result.RuleName, trace);
                Set(rule, "Description", "Velrix: временный тест исходящего TCP-соединения", trace);
                Set(rule, "Grouping", "Velrix.Tests", trace);
                Set(rule, "ApplicationName", result.ProgramPath, trace);
                Set(rule, "Protocol", 6, trace); // TCP; протокол задаётся раньше номера порта.
                Set(rule, "RemotePorts", Port.ToString(), trace);
                Set(rule, "RemoteAddresses", result.Address, trace);
                Set(rule, "Direction", 2, trace); // OUT
                Set(rule, "Profiles", profiles, trace);
                Set(rule, "Action", 0, trace); // BLOCK
                Set(rule, "Enabled", true, trace);

                WriteRecoveryNote(result, trace);
                cancellation.ThrowIfCancellationRequested();
                progress.Report("Временное правило…");
                // Даже если Add выбросит исключение после частичного изменения, finally проверит и удалит правило.
                addAttempted = true;
                result.CleanupConfirmed = false;
                Call(rules, "Add", trace, rule);
                result.RuleVerified = VerifyRule(rules, result, profiles, trace);
                if (!result.RuleVerified)
                {
                    result.Note = "Параметры добавленного правила не совпали с параметрами теста.";
                    return result;
                }
                await Task.Delay(250, cancellation).ConfigureAwait(false);
                cancellation.ThrowIfCancellationRequested();
                progress.Report("Проверка блокировки…");
                result.During = await ConnectAsync(address, cancellation, trace, "С правилом").ConfigureAwait(false);
                cancellation.ThrowIfCancellationRequested();
                // Положительный результат невозможен при смене профиля или изменении самого правила.
                result.ControlCompleted = ReadPolicy(policy, trace) == profiles && VerifyRule(rules, result, profiles, trace);
                if (!result.ControlCompleted) result.Note = "Во время теста изменились параметры правила или профиля сети.";
            }
            catch (OperationCanceledException error)
            {
                trace.Error("FW TEST", error);
                result.Outcome = FirewallTestOutcome.Cancelled;
                result.Note = "Тест остановлен пользователем.";
            }
            catch (Exception error)
            {
                trace.Error("FW TEST", error);
                result.Note = "Не удалось завершить тест. Технические сведения сохранены в отчёте.";
                result.Error = error.GetBaseException().Message;
            }
            finally
            {
                if (addAttempted)
                {
                    progress.Report("Удаление правила…");
                    result.CleanupConfirmed = await RemoveOwnRuleAsync(rules, result.RuleName, trace).ConfigureAwait(false);
                    if (result.CleanupConfirmed && address != null)
                    {
                        progress.Report("Проверка восстановления…");
                        await Task.Delay(250).ConfigureAwait(false);
                        // Очистку и проверку восстановления завершаем также после пользовательской отмены.
                        try
                        {
                            result.After = await ConnectAsync(address, CancellationToken.None, trace, "После удаления").ConfigureAwait(false);
                            result.ProfileUnchanged = ReadPolicy(policy, trace) == profiles;
                        }
                        catch (Exception error) { trace.Error("FW TEST", error); result.Error = error.GetBaseException().Message; }
                    }
                }
                if (result.CleanupConfirmed && !string.IsNullOrWhiteSpace(result.RecoveryFile))
                {
                    try { File.Delete(result.RecoveryFile); }
                    catch (Exception error) { trace.Error("FW RECOVERY", error); }
                }
                Release(rule); Release(rules); Release(policy);
                if (cancellation.IsCancellationRequested && result.CleanupConfirmed)
                    result.Outcome = FirewallTestOutcome.Cancelled;
                Assess(result);
                result.Completed = DateTimeOffset.Now;
                trace.Write("FW TEST", "RETURN Outcome=" + result.Outcome + "; CleanupConfirmed=" + result.CleanupConfirmed);
            }
            return result;
        }

        private static int ReadPolicy(object policy, TechnicalLog trace)
        {
            int profiles = Convert.ToInt32(Get(policy, "CurrentProfileTypes", trace));
            if (profiles == 0 || (profiles & ~7) != 0) return 0;
            foreach (int profile in new[] { 1, 2, 4 })
                if ((profiles & profile) != 0 && !(bool)Get(policy, "FirewallEnabled", trace, profile)) return 0;
            return Convert.ToInt32(Get(policy, "LocalPolicyModifyState", trace)) == 0 ? profiles : 0;
        }

        private static async Task<IPAddress[]> ResolveAsync(string host, CancellationToken cancellation, TechnicalLog trace)
        {
            cancellation.ThrowIfCancellationRequested();
            try
            {
                trace.Write("FW DNS", "CALL Dns.GetHostAddressesAsync(\"" + host + "\")");
                Task<IPAddress[]> pending = Dns.GetHostAddressesAsync(host);
                using (var delay = CancellationTokenSource.CreateLinkedTokenSource(cancellation))
                {
                    if (await Task.WhenAny(pending, Task.Delay(NetworkTimeout, delay.Token)).ConfigureAwait(false) != pending)
                    {
                        _ = ObserveAsync(pending);
                        cancellation.ThrowIfCancellationRequested();
                        trace.Write("FW DNS", "RETURN Тайм-аут " + NetworkTimeout + " мс.");
                        return new IPAddress[0];
                    }
                    delay.Cancel();
                    IPAddress[] addresses = await pending.ConfigureAwait(false);
                    trace.Write("FW DNS", "RETURN " + string.Join(", ", addresses.Select(value => value.ToString())));
                    return addresses.Where(IsExternalIpv4).Distinct().Take(2).ToArray();
                }
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception error) { trace.Error("FW DNS", error); return new IPAddress[0]; }
        }

        private static bool IsExternalIpv4(IPAddress address)
        {
            if (address.AddressFamily != AddressFamily.InterNetwork || IPAddress.IsLoopback(address)) return false;
            byte[] a = address.GetAddressBytes();
            return !(a[0] == 0 || a[0] == 10 || a[0] == 127 || a[0] >= 224 ||
                (a[0] == 169 && a[1] == 254) || (a[0] == 172 && a[1] >= 16 && a[1] <= 31) ||
                (a[0] == 192 && a[1] == 168) || (a[0] == 100 && a[1] >= 64 && a[1] <= 127));
        }

        private static async Task<TcpAttempt> ConnectAsync(IPAddress address, CancellationToken cancellation,
            TechnicalLog trace, string stage)
        {
            var result = new TcpAttempt();
            Stopwatch clock = Stopwatch.StartNew();
            using (var client = new TcpClient(AddressFamily.InterNetwork))
            {
                try
                {
                    cancellation.ThrowIfCancellationRequested();
                    trace.Write("FW TCP", "CALL " + stage + ": новый TcpClient.ConnectAsync(" + address + ", " + Port + ")");
                    using (cancellation.Register(client.Close))
                    using (var delay = CancellationTokenSource.CreateLinkedTokenSource(cancellation))
                    {
                        Task pending = client.ConnectAsync(address, Port);
                        if (await Task.WhenAny(pending, Task.Delay(NetworkTimeout, delay.Token)).ConfigureAwait(false) != pending)
                        {
                            client.Close();
                            _ = ObserveAsync(pending);
                            result.Outcome = cancellation.IsCancellationRequested ? TcpOutcome.Cancelled : TcpOutcome.Timeout;
                        }
                        else
                        {
                            delay.Cancel();
                            await pending.ConfigureAwait(false);
                            result.Outcome = TcpOutcome.Connected;
                        }
                    }
                }
                catch (SocketException error)
                {
                    trace.Error("FW TCP", error);
                    result.SocketError = error.SocketErrorCode;
                    result.Outcome = cancellation.IsCancellationRequested ? TcpOutcome.Cancelled :
                        error.SocketErrorCode == System.Net.Sockets.SocketError.AccessDenied ? TcpOutcome.Denied : TcpOutcome.Error;
                    result.Detail = error.Message;
                }
                catch (Exception error)
                {
                    trace.Error("FW TCP", error);
                    result.Outcome = cancellation.IsCancellationRequested ? TcpOutcome.Cancelled : TcpOutcome.Error;
                    result.Detail = error.Message;
                }
            }
            result.ElapsedMilliseconds = clock.ElapsedMilliseconds;
            trace.Write("FW TCP", "RETURN " + stage + ": Outcome=" + result.Outcome + "; SocketError=" +
                result.SocketError + "; Elapsed=" + result.ElapsedMilliseconds + " ms");
            return result;
        }

        private static bool VerifyRule(object rules, FirewallTestResult result, int profiles, TechnicalLog trace)
        {
            object found = FindRule(rules, result.RuleName, trace);
            if (found == null) return false;
            try
            {
                string remote = (string)Get(found, "RemoteAddresses", trace);
                bool addressMatches = remote == result.Address || remote == result.Address + "/32" ||
                    remote == result.Address + "/255.255.255.255";
                return string.Equals((string)Get(found, "ApplicationName", trace), result.ProgramPath, StringComparison.OrdinalIgnoreCase) &&
                    Convert.ToInt32(Get(found, "Protocol", trace)) == 6 && (string)Get(found, "RemotePorts", trace) == Port.ToString() &&
                    addressMatches && Convert.ToInt32(Get(found, "Direction", trace)) == 2 &&
                    Convert.ToInt32(Get(found, "Profiles", trace)) == profiles && Convert.ToInt32(Get(found, "Action", trace)) == 0 &&
                    (bool)Get(found, "Enabled", trace);
            }
            finally { Release(found); }
        }

        private static async Task<bool> RemoveOwnRuleAsync(object rules, string name, TechnicalLog trace)
        {
            for (int attempt = 0; attempt < 3; attempt++)
            {
                try
                {
                    Call(rules, "Remove", trace, name);
                    object remaining = FindRule(rules, name, trace);
                    if (remaining == null) return true;
                    Release(remaining);
                }
                catch (Exception error) { trace.Error("FW CLEANUP", error); }
                if (attempt < 2) await Task.Delay(200).ConfigureAwait(false);
            }
            return false;
        }

        private static object FindRule(object rules, string name, TechnicalLog trace)
        {
            try { return Call(rules, "Item", trace, name); }
            catch (Exception error)
            {
                if (unchecked((uint)error.GetBaseException().HResult) != 0x80070002u) throw;
                trace.Write("FW COM", "RETURN Item: правило отсутствует; HRESULT=0x80070002.");
                return null;
            }
        }

        private static void WriteRecoveryNote(FirewallTestResult result, TechnicalLog trace)
        {
            string dataFolder = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            if (string.IsNullOrWhiteSpace(dataFolder)) throw new DirectoryNotFoundException("Папка данных пользователя недоступна.");
            string folder = Path.Combine(dataFolder, "Velrix", "FirewallRecovery");
            Directory.CreateDirectory(folder);
            result.RecoveryFile = Path.Combine(folder, result.RuleName + ".txt");
            result.RecoveryCommand = "netsh advfirewall firewall delete rule name=\"" + result.RuleName + "\"";
            using (var file = new FileStream(result.RecoveryFile, FileMode.CreateNew, FileAccess.Write, FileShare.Read))
            using (var writer = new StreamWriter(file, new UTF8Encoding(true)))
            {
                writer.WriteLine("Служебная памятка Velrix. При нормальном завершении правило удаляется автоматически.");
                writer.WriteLine("Правило: " + result.RuleName);
                writer.WriteLine("Программа: " + result.ProgramPath);
                writer.WriteLine("Назначение: " + result.Address + ":" + Port + ", TCP, только исходящие соединения этой программы.");
                writer.WriteLine("Если процесс завершился аварийно, удалите именно это правило командой от имени администратора:");
                writer.WriteLine(result.RecoveryCommand);
            }
            trace.Write("FW RECOVERY", "Записана памятка: " + result.RecoveryFile);
        }

        private static void Assess(FirewallTestResult result)
        {
            if (!result.CleanupConfirmed)
            {
                result.Outcome = FirewallTestOutcome.CleanupNeeded;
                result.Note = "Удаление временного правила не подтверждено. Команда удаления есть в отчёте и служебной памятке.";
            }
            else if (result.Outcome == FirewallTestOutcome.Cancelled)
                result.Note = "Тест остановлен; временное правило отсутствует.";
            else if (result.ControlCompleted && result.ProfileUnchanged && result.After != null && result.After.Outcome == TcpOutcome.Connected)
            {
                if (result.During.Outcome == TcpOutcome.Denied)
                {
                    result.Outcome = FirewallTestOutcome.Passed;
                    result.Note = "До правила соединение прошло, с правилом получен отказ 10013, после удаления соединение восстановлено.";
                }
                else if (result.During.Outcome == TcpOutcome.Connected)
                {
                    result.Outcome = FirewallTestOutcome.NotBlocked;
                    result.Note = "Соединение прошло и при установленном правиле. Блокировка не подтверждена.";
                }
                else result.Note = "Получена сетевая ошибка или тайм-аут. Этого недостаточно для подтверждения блокировки.";
            }
            else if (result.ControlCompleted && result.After != null && result.After.Outcome != TcpOutcome.Connected)
                result.Note = "Правило удалено, но повторное соединение не установлено. Восстановление доступа не подтверждено.";
            else if (result.ControlCompleted && !result.ProfileUnchanged)
                result.Note = "Правило удалено, но исходное состояние сетевого профиля не подтверждено.";
        }

        private static object CreateCom(string progId, TechnicalLog trace)
        {
            trace.Write("FW COM", "CALL Activator.CreateInstance(" + progId + ")");
            return Activator.CreateInstance(Type.GetTypeFromProgID(progId, true));
        }
        private static object Get(object value, string property, TechnicalLog trace, params object[] index)
        {
            trace.Write("FW COM", "CALL Get " + property + "(" + string.Join(", ", index.Select(item => Convert.ToString(item))) + ")");
            object result = value.GetType().InvokeMember(property, BindingFlags.GetProperty, null, value, index);
            trace.Write("FW COM", "RETURN " + property + "=" + result);
            return result;
        }
        private static void Set(object value, string property, object data, TechnicalLog trace)
        {
            trace.Write("FW COM", "CALL Set " + property + "=" + data);
            value.GetType().InvokeMember(property, BindingFlags.SetProperty, null, value, new[] { data });
        }
        private static object Call(object value, string method, TechnicalLog trace, params object[] args)
        {
            trace.Write("FW COM", "CALL " + method + "(" + string.Join(", ", args.Select(item => Convert.ToString(item))) + ")");
            object result = value.GetType().InvokeMember(method, BindingFlags.InvokeMethod, null, value, args);
            trace.Write("FW COM", "RETURN " + method + ": завершён без исключения.");
            return result;
        }
        private static void Release(object value)
        {
            if (value == null || !Marshal.IsComObject(value)) return;
            try { Marshal.FinalReleaseComObject(value); }
            catch (Exception error) { Debug.WriteLine(error.Message); }
        }
        private static async Task ObserveAsync(Task task)
        {
            try { await task.ConfigureAwait(false); }
            catch (Exception error) { Debug.WriteLine(error.Message); }
        }
    }

    internal enum TcpOutcome { Connected, Denied, Timeout, Error, Cancelled }
    internal sealed class TcpAttempt
    {
        internal TcpOutcome Outcome;
        internal SocketError? SocketError;
        internal long ElapsedMilliseconds;
        internal string Detail;
        public override string ToString()
        {
            return Outcome + "; SocketError=" + SocketError + "; " + ElapsedMilliseconds + " мс" +
                (string.IsNullOrWhiteSpace(Detail) ? "" : "; " + Detail);
        }
    }
    internal enum FirewallTestOutcome { Unknown, Passed, NeedsAdministrator, NotBlocked, Cancelled, CleanupNeeded }
    internal sealed class FirewallTestResult
    {
        internal FirewallTestOutcome Outcome;
        internal DateTimeOffset Started, Completed;
        internal string ProgramPath, Host, Address, RuleName, RecoveryFile, RecoveryCommand, Error;
        internal string Note = "Результат не подтверждён.";
        internal bool IsAdministrator, RuleVerified, ControlCompleted, ProfileUnchanged;
        internal bool CleanupConfirmed = true;
        internal TcpAttempt Before, During, After;
        internal string Status
        {
            get
            {
                switch (Outcome)
                {
                    case FirewallTestOutcome.Passed: return "Пройден";
                    case FirewallTestOutcome.NeedsAdministrator: return "Нужны права";
                    case FirewallTestOutcome.NotBlocked: return "Не заблокировано";
                    case FirewallTestOutcome.Cancelled: return "Остановлено";
                    case FirewallTestOutcome.CleanupNeeded: return "Нужна очистка";
                    default: return "Не подтверждено";
                }
            }
        }
    }
}
