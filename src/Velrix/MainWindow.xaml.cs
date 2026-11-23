using System;
using System.Diagnostics;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Cache;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Threading;
using Microsoft.Win32;

namespace Mobks.SecurityCheck
{
    public partial class MainWindow : Window
    {
        private const int TimeoutMilliseconds = 8000;
        private static readonly string AppVersion = typeof(MainWindow).Assembly.GetName().Version.ToString(3);
        private const string ProjectUrl = "https://github.com/ManiFast/Verlix";
        private static readonly ProbeTarget[] Targets =
        {
            new ProbeTarget("Россия", "Россия", "https://storage.yandexcloud.net/"),
            new ProbeTarget("СНГ", "Казахстан", "https://storage.yandexcloud.kz/"),
            new ProbeTarget("США", "США, Северная Виргиния", "https://s3.us-east-1.amazonaws.com/"),
            new ProbeTarget("Азия", "Япония, Токио", "https://s3.ap-northeast-1.amazonaws.com/")
        };

        private CancellationTokenSource _runCancellation;
        private CheckRun _lastRun;
        private bool _busy;
        private bool _closing;
        private bool _closeAfterRun;
        private string _eicarSourcePath;
        private TechnicalLog _activeTrace;
        private int _traceCursor;
        private readonly DispatcherTimer _traceTimer;
        private Task<AntivirusResult> _antivirusWork;
        private Task<FirewallResult> _firewallWork;
        private double _journalHeight = 220;
        private double _journalCollapsedHeight;
        private double _journalAutoHeight;

        public MainWindow()
        {
            InitializeComponent();
            VersionButton.Content = "v" + AppVersion;
            VersionButton.Click += delegate
            {
                try { Process.Start(new ProcessStartInfo(ProjectUrl) { UseShellExecute = true }); }
                catch (Exception error) { MessageBox.Show(this, "Не удалось открыть GitHub.\n" + error.Message, "Velrix"); }
            };
            _traceTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(150) };
            _traceTimer.Tick += delegate { FlushTechnicalOutput(); };
            RunChecksButton.Click += RunChecksButton_Click;
            JournalExpander.Expanded += delegate { SetJournalVisible(true); };
            JournalExpander.Collapsed += delegate { SetJournalVisible(false); };
            SaveReportButton.Click += delegate { SaveReport(); };
            SelectEicarFileButton.Click += delegate { SelectEicarFile(); };
            Closing += (sender, e) =>
            {
                if (!_busy) return;
                // При обычном закрытии дожидаемся очистки тестового файла и временного правила.
                e.Cancel = true;
                _closeAfterRun = true;
                if (_activeTrace != null) _activeTrace.Write("RUN", "Запрошено закрытие окна; отмена и очистка.");
                if (_runCancellation != null) _runCancellation.Cancel();
                RunChecksButton.IsEnabled = false;
                RunButtonText.Text = "Завершение…";
            };
            Closed += delegate
            {
                _closing = true;
                _traceTimer.Stop();
                if (_runCancellation != null) _runCancellation.Cancel();
            };
            CommandBindings.Add(new CommandBinding(ApplicationCommands.Save,
                delegate { SaveReport(); },
                delegate(object sender, CanExecuteRoutedEventArgs e)
                {
                    e.CanExecute = _lastRun != null && !_busy;
                }));
            InputBindings.Add(new KeyBinding(ApplicationCommands.Save,
                new KeyGesture(Key.S, ModifierKeys.Control)));
        }

        private void SetJournalVisible(bool visible)
        {
            if (!visible && JournalRow.ActualHeight > 0) _journalHeight = JournalRow.ActualHeight;
            JournalPane.Visibility = visible ? Visibility.Visible : Visibility.Collapsed;
            JournalSplitter.Visibility = visible ? Visibility.Visible : Visibility.Collapsed;
            JournalRow.MinHeight = visible ? 140 : 0;
            JournalRow.Height = new GridLength(visible ? _journalHeight : 0);

            if (visible && WindowState == WindowState.Normal)
            {
                Rect workArea = SystemParameters.WorkArea;
                // Автоматически расширяем окно только в пределах основного рабочего экрана.
                if (workArea.Contains(new Point(Left + Width / 2, Top + Height / 2)))
                {
                    double target = Math.Min(Height + Math.Min(_journalHeight, 220), workArea.Height - 24);
                    if (target > Height)
                    {
                        _journalCollapsedHeight = Height;
                        _journalAutoHeight = target;
                        Height = target;
                        if (Top + Height > workArea.Bottom) Top = Math.Max(workArea.Top, workArea.Bottom - Height);
                    }
                }
            }
            else if (!visible)
            {
                // Ручное изменение размеров сохраняем; после обычного сворачивания возвращаем прежнюю высоту.
                if (WindowState == WindowState.Normal && _journalCollapsedHeight > 0 &&
                    Math.Abs(Height - _journalAutoHeight) < 2) Height = _journalCollapsedHeight;
                _journalCollapsedHeight = 0;
                _journalAutoHeight = 0;
            }
        }

        private void AppendJournal(string message)
        {
            DetailsTextBox.AppendText(DateTime.Now.ToString("HH:mm:ss") + "  " + message + Environment.NewLine);
            DetailsTextBox.ScrollToEnd();
        }

        private void FlushTechnicalOutput()
        {
            if (_closing || _activeTrace == null) return;
            string added = _activeTrace.ReadFrom(_traceCursor);
            if (added.Length == 0) return;
            bool atBottom = TechnicalOutputTextBox.VerticalOffset + TechnicalOutputTextBox.ViewportHeight >=
                TechnicalOutputTextBox.ExtentHeight - 2;
            TechnicalOutputTextBox.AppendText(added);
            _traceCursor += added.Length;
            if (atBottom) TechnicalOutputTextBox.ScrollToEnd();
        }

        private void SelectEicarFile()
        {
            if (_busy) return;
            var dialog = new OpenFileDialog
            {
                Title = "Выберите подготовленный файл EICAR",
                Filter = "Текстовый файл (*.txt)|*.txt|Все файлы (*.*)|*.*",
                FileName = "EICAR.txt",
                CheckFileExists = true,
                Multiselect = false
            };
            if (dialog.ShowDialog(this) != true) return;
            _eicarSourcePath = dialog.FileName;
            AntivirusTestHintText.Text = Path.GetFileName(_eicarSourcePath);
            AntivirusTestHintText.ToolTip = _eicarSourcePath;
            AntivirusTestStatus.Text = "Готов к тесту";
            AntivirusTestStatus.Foreground = (Brush)FindResource("MutedBrush");
        }

        private async void RunChecksButton_Click(object sender, RoutedEventArgs e)
        {
            if (_busy)
            {
                if (_activeTrace != null) _activeTrace.Write("RUN", "Пользователь запросил отмену.");
                if (_runCancellation != null) _runCancellation.Cancel();
                RunButtonText.Text = "Остановка…";
                RunChecksButton.IsEnabled = false;
                return;
            }

            _busy = true;
            _lastRun = null;
            _runCancellation = new CancellationTokenSource();
            CancellationToken token = _runCancellation.Token;
            DateTimeOffset started = DateTimeOffset.Now;
            Stopwatch elapsed = Stopwatch.StartNew();
            RunButtonText.Text = "Остановить";
            SelectEicarFileButton.IsEnabled = false;
            SaveReportButton.IsEnabled = false;
            SaveReportButton.Tag = null;
            InternetStatus.Text = "Проверка…";
            AntivirusStatus.Text = "Проверка…";
            FirewallStatus.Text = "Проверка…";
            AntivirusTestStatus.Text = "Проверка…";
            FirewallTestStatus.Text = "Ожидание…";
            InternetStatus.Foreground = AntivirusStatus.Foreground = FirewallStatus.Foreground =
                AntivirusTestStatus.Foreground = FirewallTestStatus.Foreground = (Brush)FindResource("AccentBrush");
            InternetHintText.Text = "Россия, СНГ, США, Азия";
            AntivirusHintText.Text = "Получение сведений Windows";
            FirewallHintText.Text = "Получение сведений Windows";
            FirewallTestHintText.Text = "После остальных проверок";
            AntivirusTestHintText.Text = string.IsNullOrWhiteSpace(_eicarSourcePath) ?
                "Выберите файл EICAR" : Path.GetFileName(_eicarSourcePath);
            OverallIndicator.Fill = (Brush)FindResource("AccentBrush");
            if (SystemParameters.ClientAreaAnimation)
                OverallIndicator.BeginAnimation(UIElement.OpacityProperty,
                    new DoubleAnimation(0.45, 1, TimeSpan.FromSeconds(0.8))
                    { AutoReverse = true, RepeatBehavior = RepeatBehavior.Forever });
            SummaryText.Text = "Выполняется проверка";
            LastRunText.Text = "Начало: " + started.ToString("dd.MM.yyyy HH:mm:ss");
            FooterHintText.Text = "Проверки выполняются";
            DetailsTextBox.Clear();
            TechnicalOutputTextBox.Clear();
            var trace = new TechnicalLog();
            _activeTrace = trace;
            _traceCursor = 0;
            _traceTimer.Start();
            trace.Write("RUN", "Начало: " + started.ToString("dd.MM.yyyy HH:mm:ss.fff zzz") +
                "; ОС=" + Environment.OSVersion + "; CLR=" + Environment.Version +
                "; 64-bit process=" + Environment.Is64BitProcess);
            trace.Write("RUN", "Используются C# и Windows API. Команды cmd/PowerShell не запускаются.\r\n" +
                "CALL — начало операции с параметрами; RETURN — полученное значение.\r\n" +
                "Заголовки HTTP показаны в представлении HttpWebResponse; это не захват сетевых пакетов.");
            AppendJournal("Начало проверки.");

            int completed = 0;
            var progress = new Progress<ProbeResult>(result =>
            {
                if (_closing || _activeTrace != trace || !_busy) return;
                completed++;
                AppendJournal(ReadableProbe(result));
                FooterHintText.Text = "Сеть: обработано " + completed + " из " + Targets.Length;
            });

            try
            {
                Task<ProbeResult[]> networkTask = CheckNetworkAndDisplayAsync(token, progress, trace);
                Task<AntivirusResult> antivirusTask = CheckAntivirusAndDisplayAsync(token, trace);
                Task<FirewallResult> firewallTask = CheckFirewallAndDisplayAsync(token, trace);
                Task<EicarTestResult> eicarTask = CheckEicarAndDisplayAsync(token, trace);
                await Task.WhenAll(networkTask, antivirusTask, firewallTask, eicarTask);
                ProbeResult[] results = networkTask.Result;
                // Временное правило не должно повлиять на обычные сетевые пробы текущего запуска.
                string[] hosts = results.Where(result => result.Outcome == ProbeOutcome.Reply && result.HttpCode < 500)
                    .Select(result => new Uri(result.Target.Address).Host).ToArray();
                FirewallTestResult firewallTest = await CheckFirewallTestAndDisplayAsync(hosts, token, trace);
                elapsed.Stop();
                if (_closing) return;
                AntivirusResult antivirus = antivirusTask.Result;
                _lastRun = new CheckRun
                {
                    Started = started,
                    Completed = DateTimeOffset.Now,
                    DurationMilliseconds = elapsed.ElapsedMilliseconds,
                    Results = results,
                    Antivirus = antivirus,
                    Firewall = firewallTask.Result,
                    AntivirusTest = eicarTask.Result,
                    FirewallTest = firewallTest
                };
                bool cancelled = token.IsCancellationRequested || results.Any(result => result.Outcome == ProbeOutcome.Cancelled) ||
                    antivirus.Level == CheckLevel.Cancelled || firewallTask.Result.Level == CheckLevel.Cancelled ||
                    eicarTask.Result.Outcome == EicarOutcome.Cancelled || firewallTest.Outcome == FirewallTestOutcome.Cancelled;
                bool needsCleanup = !firewallTest.CleanupConfirmed || !eicarTask.Result.CleanupSucceeded;
                bool allPassed = results.All(result => result.Outcome == ProbeOutcome.Reply && result.HttpCode < 500) &&
                    antivirus.Level == CheckLevel.Good && firewallTask.Result.Level == CheckLevel.Good &&
                    eicarTask.Result.ReactionConfirmed && eicarTask.Result.CleanupSucceeded &&
                    firewallTest.Outcome == FirewallTestOutcome.Passed && !cancelled;
                SummaryText.Text = needsCleanup ? "Требуется очистка тестовых объектов" : cancelled ? "Проверка остановлена" :
                    allPassed ? "Проверки пройдены" : "Проверка завершена";
                LastRunText.Text = _lastRun.Completed.ToString("dd.MM.yyyy HH:mm:ss");
                OverallIndicator.Fill = new SolidColorBrush(needsCleanup ? Color.FromRgb(235, 148, 148) :
                    allPassed ? Color.FromRgb(126, 201, 145) : cancelled ? Color.FromRgb(180, 180, 180) : Color.FromRgb(221, 188, 112));
                FooterHintText.Text = "Отчёт не сохранён";
                SaveReportButton.IsEnabled = true;
                SaveReportButton.Tag = "Unsaved";
                AppendJournal(cancelled ? "Проверка остановлена. Полученные результаты можно сохранить." :
                    "Готово. Результаты можно сохранить.");
            }
            catch (Exception error)
            {
                trace.Error("RUN", error);
                if (!_closing)
                {
                    SummaryText.Text = "Не удалось завершить проверку";
                    OverallIndicator.Fill = (Brush)FindResource("MutedBrush");
                    FooterHintText.Text = "Сведения об ошибке — в журнале";
                    AppendJournal("Ошибка: " + error.Message);
                }
            }
            finally
            {
                OverallIndicator.BeginAnimation(UIElement.OpacityProperty, null);
                trace.Write("RUN", "Завершение: CancelRequested=" + token.IsCancellationRequested);
                string technicalOutput = trace.Finish();
                if (_lastRun != null) _lastRun.TechnicalOutput = technicalOutput;
                _traceTimer.Stop();
                FlushTechnicalOutput();
                _busy = false;
                _runCancellation.Dispose();
                _runCancellation = null;
                if (!_closing)
                {
                    RunButtonText.Text = "Запустить проверки";
                    RunChecksButton.IsEnabled = true;
                    SelectEicarFileButton.IsEnabled = true;
                    CommandManager.InvalidateRequerySuggested();
                    if (_closeAfterRun) Close();
                }
            }
        }

        private async Task<ProbeResult[]> CheckNetworkAndDisplayAsync(CancellationToken token,
            IProgress<ProbeResult> progress, TechnicalLog trace)
        {
            var tasks = Targets.Select(target => Task.Run(() =>
                ProbeAndReportAsync(target, token, progress, trace))).ToArray();
            ProbeResult[] results = await Task.WhenAll(tasks);
            if (_closing) return results;
            bool cancelled = results.Any(result => result.Outcome == ProbeOutcome.Cancelled);
            int replies = results.Count(result => result.Outcome == ProbeOutcome.Reply);
            bool allReplied = replies == Targets.Length && results.All(result => result.HttpCode < 500);
            InternetStatus.Text = cancelled ? "Остановлено" : "Ответили " + replies + " из " + Targets.Length;
            InternetStatus.Foreground = new SolidColorBrush(allReplied ?
                Color.FromRgb(126, 201, 145) : Color.FromRgb(221, 188, 112));
            InternetHintText.Text = string.Join(" | ", results.Select(result =>
                result.Target.Label + ": " + ShortResult(result)));
            return results;
        }

        private async Task<AntivirusResult> CheckAntivirusAndDisplayAsync(CancellationToken token, TechnicalLog trace)
        {
            AntivirusResult result;
            if (_antivirusWork != null && !_antivirusWork.IsCompleted)
            {
                result = AntivirusResult.Unconfirmed("Windows ещё завершает предыдущий запрос.");
                trace.Write("WSC", "Предыдущий COM-запрос ещё выполняется; новый не создан.");
            }
            else
            {
                _antivirusWork = Task.Run(() => ReadAntivirus(token, trace));
                result = await WaitForWindowsAsync(_antivirusWork, token, AntivirusResult.Cancelled,
                    () => AntivirusResult.Unconfirmed("Центр безопасности Windows не ответил за 8 с."), trace, "WSC");
            }
            if (_closing) return result;
            AntivirusStatus.Text = result.Status;
            AntivirusHintText.Text = result.Hint;
            Color color = result.Level == CheckLevel.Good ? Color.FromRgb(126, 201, 145) :
                result.Level == CheckLevel.Bad ? Color.FromRgb(235, 148, 148) :
                result.Level == CheckLevel.Cancelled ? Color.FromRgb(180, 180, 180) : Color.FromRgb(221, 188, 112);
            AntivirusStatus.Foreground = new SolidColorBrush(color);
            if (result.Products.Count == 0)
            {
                AppendJournal("Антивирус: " + result.Note);
            }
            else
            {
                foreach (AntivirusProduct product in result.Products)
                    AppendJournal(product.Name + ": " + ProductStateText(product.State) + ".");
                if (result.Errors.Count > 0)
                    AppendJournal("Часть сведений об антивирусе недоступна. Подробности сохранены в отчёте.");
            }
            return result;
        }

        private async Task<FirewallResult> CheckFirewallAndDisplayAsync(CancellationToken token, TechnicalLog trace)
        {
            FirewallResult result;
            if (_firewallWork != null && !_firewallWork.IsCompleted)
            {
                result = FirewallResult.Unconfirmed("Windows ещё завершает предыдущий запрос.");
                trace.Write("FIREWALL", "Предыдущий COM-запрос ещё выполняется; новый не создан.");
            }
            else
            {
                _firewallWork = Task.Run(() => ReadFirewall(token, trace));
                result = await WaitForWindowsAsync(_firewallWork, token, FirewallResult.Cancelled,
                    () => FirewallResult.Unconfirmed("Брандмауэр Windows не ответил за 8 с."), trace, "FIREWALL");
            }
            if (_closing) return result;
            FirewallStatus.Text = result.Status;
            FirewallHintText.Text = result.Hint + (result.Profiles.Count == 0 ? "" :
                "\nВключено профилей: " + result.Profiles.Count(profile => profile.Enabled == true) + " из " + result.Profiles.Count +
                (result.Profiles.Any(profile => !profile.Enabled.HasValue) ?
                    "; нет данных: " + result.Profiles.Count(profile => !profile.Enabled.HasValue) : ""));
            FirewallHintText.ToolTip = string.Join("\n", result.Profiles.Select(profile => profile.Name + ": " +
                FirewallStateText(profile.Enabled) + (profile.Active ? " (активна)" : "")));
            FirewallStatus.Foreground = new SolidColorBrush(result.Level == CheckLevel.Good ?
                Color.FromRgb(126, 201, 145) : result.Level == CheckLevel.Cancelled ?
                Color.FromRgb(180, 180, 180) : Color.FromRgb(221, 188, 112));
            FirewallProfile[] active = result.Profiles.Where(profile => profile.Active).ToArray();
            if (active.Length == 0)
                AppendJournal("Брандмауэр Windows: " + result.Note);
            else
                foreach (FirewallProfile profile in active)
                    AppendJournal("Брандмауэр Windows / " + profile.Name + ": " +
                        FirewallStateText(profile.Enabled) + ".");
            return result;
        }

        private async Task<EicarTestResult> CheckEicarAndDisplayAsync(CancellationToken token, TechnicalLog trace)
        {
            EicarTestResult result = await EicarTest.RunAsync(_eicarSourcePath, token, trace);
            if (_closing) return result;
            AntivirusTestStatus.Text = result.Status;
            AntivirusTestHintText.Text = !result.CleanupSucceeded ? "Не удалось удалить тестовую копию" :
                result.Outcome == EicarOutcome.NoFile ? "Выберите файл EICAR" :
                result.Outcome == EicarOutcome.InvalidFile ? "Проверьте строку и кодировку файла" :
                result.ReactionConfirmed ? (Path.GetFileName(result.SourcePath) ?? "Файл EICAR") :
                result.Outcome == EicarOutcome.NoReaction ? "За 10 секунд блокировка не подтверждена" :
                result.Outcome == EicarOutcome.Cancelled ? "Тест остановлен" : "Подробности в журнале";
            AntivirusTestHintText.ToolTip = "Исходный файл: " + (result.SourcePath ?? _eicarSourcePath ?? "не выбран") +
                "\n" + result.Description;
            AntivirusTestStatus.Foreground = new SolidColorBrush(result.ReactionConfirmed && result.CleanupSucceeded ?
                Color.FromRgb(126, 201, 145) : result.Outcome == EicarOutcome.Cancelled && result.CleanupSucceeded ?
                Color.FromRgb(180, 180, 180) : Color.FromRgb(221, 188, 112));
            AppendJournal("EICAR: " + result.Description);
            if (!result.CleanupSucceeded)
                AppendJournal("Осталась тестовая папка: " + Path.GetDirectoryName(result.FilePath));
            return result;
        }

        private async Task<FirewallTestResult> CheckFirewallTestAndDisplayAsync(string[] hosts,
            CancellationToken token, TechnicalLog trace)
        {
            FirewallTestStatus.Text = "Проверка…";
            var progress = new Progress<string>(stage =>
            {
                if (!_closing && _busy && _activeTrace == trace) FirewallTestHintText.Text = stage;
            });
            FirewallTestResult result = await FirewallTest.RunAsync(hosts, token, trace, progress);
            if (_closing) return result;
            FirewallTestStatus.Text = result.Status;
            FirewallTestHintText.Text = result.Outcome == FirewallTestOutcome.NeedsAdministrator ?
                "Для временного правила нужны права администратора" : !result.CleanupConfirmed ?
                "Не подтверждено удаление тестового правила" : result.Outcome == FirewallTestOutcome.Passed ?
                result.Address + ":443 (TCP)\nБлокировка сработала. Правило удалено, доступ восстановлен." : result.Outcome == FirewallTestOutcome.NotBlocked ?
                "Правило не остановило соединение" : result.Outcome == FirewallTestOutcome.Cancelled ?
                "Тест остановлен" : "Подробности в журнале";
            FirewallTestHintText.ToolTip = result.Note + (string.IsNullOrWhiteSpace(result.Address) ? "" :
                "\nСервер: " + result.Host + "\nАдрес: " + result.Address + ":443 (TCP)");
            FirewallTestStatus.Foreground = new SolidColorBrush(result.Outcome == FirewallTestOutcome.Passed ?
                Color.FromRgb(126, 201, 145) : !result.CleanupConfirmed ? Color.FromRgb(235, 148, 148) :
                result.Outcome == FirewallTestOutcome.Cancelled ? Color.FromRgb(180, 180, 180) : Color.FromRgb(221, 188, 112));
            AppendJournal("Тест брандмауэра: " + result.Note);
            if (!result.CleanupConfirmed) AppendJournal("Памятка удаления: " + result.RecoveryFile);
            return result;
        }

        private static async Task<T> WaitForWindowsAsync<T>(Task<T> work, CancellationToken token,
            Func<T> cancelled, Func<T> timedOut, TechnicalLog trace, string source)
        {
            using (var timeoutCancellation = CancellationTokenSource.CreateLinkedTokenSource(token))
            {
                Task timeout = Task.Delay(TimeoutMilliseconds, timeoutCancellation.Token);
                if (await Task.WhenAny(work, timeout) == work)
                {
                    timeoutCancellation.Cancel();
                    return await work;
                }
                // COM-вызов нельзя прервать; поздний ответ не применяется к окну или отчёту.
                _ = ObserveWindowsWorkAsync(work);
                trace.Write(source, "Ожидание завершено: CancelRequested=" + token.IsCancellationRequested +
                    "; лимит=" + TimeoutMilliseconds + " мс. Поздний ответ не применяется к результату проверки.");
                return token.IsCancellationRequested ? cancelled() : timedOut();
            }
        }

        private static async Task ObserveWindowsWorkAsync(Task work)
        {
            try { await work.ConfigureAwait(false); }
            catch (Exception error) { Debug.WriteLine("Завершение запроса Windows: " + error.Message); }
        }

        private static string ReadableProbe(ProbeResult result)
        {
            string prefix = "Интернет / " + result.Target.Label + ": ";
            if (result.Outcome == ProbeOutcome.Reply)
                return prefix + "есть ответ, " + result.ElapsedMilliseconds + " мс" +
                    (result.HttpCode >= 500 ? "; сервер сообщил HTTP " + result.HttpCode : "") + ".";
            if (result.Outcome == ProbeOutcome.Timeout) return prefix + "нет ответа за 8 с.";
            if (result.Outcome == ProbeOutcome.Cancelled) return prefix + "проверка остановлена.";
            if (result.HttpCode == 407) return prefix + "прокси требует авторизацию.";
            string reason;
            switch (result.NetworkError)
            {
                case WebExceptionStatus.NameResolutionFailure: reason = "не удалось определить адрес сервера"; break;
                case WebExceptionStatus.ProxyNameResolutionFailure: reason = "не найден сервер прокси"; break;
                case WebExceptionStatus.ConnectFailure: reason = "не удалось подключиться"; break;
                case WebExceptionStatus.TrustFailure: reason = "не удалось проверить сертификат сервера"; break;
                case WebExceptionStatus.SecureChannelFailure: reason = "ошибка защищённого соединения"; break;
                default: reason = "ошибка соединения; технические сведения есть в отчёте"; break;
            }
            return prefix + reason + ".";
        }

        private static async Task<ProbeResult> ProbeAndReportAsync(ProbeTarget target,
            CancellationToken cancellation, IProgress<ProbeResult> progress, TechnicalLog trace)
        {
            ProbeResult result = await ProbeAsync(target, cancellation, trace).ConfigureAwait(false);
            progress.Report(result);
            return result;
        }

        private static async Task<ProbeResult> ProbeAsync(ProbeTarget target, CancellationToken cancellation, TechnicalLog trace)
        {
            Stopwatch timer = Stopwatch.StartNew();
            var result = new ProbeResult { Target = target };
            string source = "HTTP " + target.Label;
            try
            {
                cancellation.ThrowIfCancellationRequested();
                var request = (HttpWebRequest)WebRequest.Create(target.Address);
                request.Method = "HEAD";
                // Региональный адрес должен ответить сам; переходы на другие сайты не выполняются.
                request.AllowAutoRedirect = false;
                request.KeepAlive = false;
                request.ConnectionGroupName = "Velrix-" + Guid.NewGuid().ToString("N");
                request.Timeout = TimeoutMilliseconds;
                request.ReadWriteTimeout = TimeoutMilliseconds;
                request.UseDefaultCredentials = false;
                request.UserAgent = "Velrix/" + AppVersion;
                request.CachePolicy = new RequestCachePolicy(RequestCacheLevel.NoCacheNoStore);
                trace.Write(source, "CALL HttpWebRequest.GetResponseAsync()\r\n" +
                    "Method=" + request.Method + "; URI=" + request.RequestUri +
                    "\r\nAllowAutoRedirect=" + request.AllowAutoRedirect + "; KeepAlive=" + request.KeepAlive +
                    "; Timeout=" + request.Timeout + "; ReadWriteTimeout=" + request.ReadWriteTimeout +
                    "\r\nUseDefaultCredentials=" + request.UseDefaultCredentials + "; UserAgent=" + request.UserAgent);

                using (cancellation.Register(request.Abort))
                {
                    Task<WebResponse> pending = Task.Run(async () =>
                        await request.GetResponseAsync().ConfigureAwait(false));
                    using (var timeoutCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellation))
                    {
                        Task timeout = Task.Delay(TimeoutMilliseconds, timeoutCancellation.Token);
                        Task winner = await Task.WhenAny(pending, timeout).ConfigureAwait(false);
                        if (winner != pending)
                        {
                            request.Abort();
                            // Убираем поздний ответ и наблюдаем исключение даже после тайм-аута.
                            _ = DisposeLateResponseAsync(pending);
                            result.Outcome = cancellation.IsCancellationRequested ?
                                ProbeOutcome.Cancelled : ProbeOutcome.Timeout;
                            result.Detail = cancellation.IsCancellationRequested ? "Остановлено пользователем" :
                                "Нет ответа за " + TimeoutMilliseconds / 1000 + " с";
                            return result;
                        }
                        timeoutCancellation.Cancel();
                        using (var response = (HttpWebResponse)await pending.ConfigureAwait(false))
                        {
                            ReadHttpResponse(result, response, trace);
                        }
                    }
                }
            }
            catch (OperationCanceledException error)
            {
                trace.Error(source, error);
                result.Outcome = ProbeOutcome.Cancelled;
                result.Detail = "Остановлено пользователем";
            }
            catch (WebException error)
            {
                trace.Error(source, error);
                result.NetworkError = error.Status;
                using (var response = error.Response as HttpWebResponse)
                {
                    if (cancellation.IsCancellationRequested)
                    {
                        result.Outcome = ProbeOutcome.Cancelled;
                        result.Detail = "Остановлено пользователем";
                    }
                    else if (response != null)
                    {
                        ReadHttpResponse(result, response, trace);
                    }
                    else
                    {
                        result.Outcome = error.Status == WebExceptionStatus.Timeout ?
                            ProbeOutcome.Timeout : ProbeOutcome.Error;
                        result.Detail = error.Status + ": " + error.Message;
                    }
                }
            }
            catch (Exception error)
            {
                trace.Error(source, error);
                result.Outcome = cancellation.IsCancellationRequested ? ProbeOutcome.Cancelled : ProbeOutcome.Error;
                result.Detail = cancellation.IsCancellationRequested ? "Остановлено пользователем" : error.Message;
            }
            finally
            {
                timer.Stop();
                result.ElapsedMilliseconds = timer.ElapsedMilliseconds;
                trace.Write(source, "RETURN Outcome=" + result.Outcome + "; HttpCode=" + result.HttpCode +
                    "; Elapsed=" + result.ElapsedMilliseconds + " ms; Detail=" + result.Detail);
            }
            return result;
        }

        private static void ReadHttpResponse(ProbeResult result, HttpWebResponse response, TechnicalLog trace)
        {
            trace.Write("HTTP " + result.Target.Label, "RETURN HttpWebResponse\r\nHTTP/" + response.ProtocolVersion +
                " " + (int)response.StatusCode + " " + response.StatusDescription + "\r\n" +
                response.Headers + "ResponseUri=" + response.ResponseUri);
            result.HttpCode = (int)response.StatusCode;
            // HTTP 407 может исходить от прокси и не подтверждает ответ конечного узла.
            result.Outcome = result.HttpCode == 407 ? ProbeOutcome.Error : ProbeOutcome.Reply;
            result.Detail = result.HttpCode == 407 ? "Прокси требует авторизацию (HTTP 407)" :
                "Получен ответ HTTPS: HTTP " + result.HttpCode + " " + response.StatusDescription;
        }

        private static async Task DisposeLateResponseAsync(Task<WebResponse> pending)
        {
            try
            {
                using (WebResponse response = await pending.ConfigureAwait(false)) { }
            }
            catch (WebException error)
            {
                if (error.Response != null) error.Response.Dispose();
            }
            catch (Exception error)
            {
                Debug.WriteLine("Завершение сетевого запроса: " + error.Message);
            }
        }

        private static string ShortResult(ProbeResult result)
        {
            switch (result.Outcome)
            {
                case ProbeOutcome.Reply: return result.ElapsedMilliseconds + " мс";
                case ProbeOutcome.Timeout: return "тайм-аут";
                case ProbeOutcome.Cancelled: return "отмена";
                default: return "ошибка";
            }
        }

        private static string FormatProbe(ProbeResult result)
        {
            return result.Target.Label + " — " + result.Target.Location + "\r\n" +
                result.Target.Address + "\r\n" + result.Detail + "\r\n" +
                "Время HTTPS-запроса: " + result.ElapsedMilliseconds + " мс";
        }

        private void SaveReport()
        {
            if (_lastRun == null || _busy) return;
            var dialog = new SaveFileDialog
            {
                Title = "Сохранить отчёт Velrix",
                Filter = "Текстовый отчёт (*.txt)|*.txt",
                DefaultExt = ".txt",
                AddExtension = true,
                FileName = "Velrix_" + _lastRun.Completed.ToString("yyyy-MM-dd_HH-mm-ss") + ".txt"
            };
            if (dialog.ShowDialog(this) != true) return;
            try
            {
                File.WriteAllText(dialog.FileName, BuildReport(_lastRun), new UTF8Encoding(true));
                SaveReportButton.Tag = null;
                FooterHintText.Text = "Сохранено: " + Path.GetFileName(dialog.FileName);
            }
            catch (Exception error)
            {
                MessageBox.Show(this, "Не удалось сохранить отчёт.\n" + error.Message,
                    "Velrix", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }

        private static string BuildReport(CheckRun run)
        {
            var report = new StringBuilder();
            report.AppendLine("Velrix — результаты проверки");
            report.AppendLine("Версия: " + AppVersion);
            report.AppendLine("Начало: " + run.Started.ToString("dd.MM.yyyy HH:mm:ss zzz"));
            report.AppendLine("Завершение: " + run.Completed.ToString("dd.MM.yyyy HH:mm:ss zzz"));
            report.AppendLine("Длительность: " + run.DurationMilliseconds + " мс");
            report.AppendLine();
            report.AppendLine("1. Сеть: ответы выбранных HTTPS-адресов");
            foreach (ProbeResult result in run.Results)
            {
                report.AppendLine(FormatProbe(result));
                report.AppendLine();
            }
            report.AppendLine("2. Антивирус: " + run.Antivirus.Status);
            report.AppendLine("Источник: Центр безопасности Windows, IWSCProductList / IWscProduct.");
            foreach (AntivirusProduct product in run.Antivirus.Products)
            {
                report.AppendLine(product.Name + ": " + ProductStateText(product.State));
            }
            if (!string.IsNullOrWhiteSpace(run.Antivirus.Note)) report.AppendLine(run.Antivirus.Note);
            foreach (string error in run.Antivirus.Errors) report.AppendLine("Уточнение: " + error);
            report.AppendLine("Это сообщаемое состояние продукта. Результат теста EICAR приведён в пункте 3.");
            report.AppendLine();
            EicarTestResult test = run.AntivirusTest;
            report.AppendLine("3. Тест антивируса (EICAR): " + test.Status);
            report.AppendLine("Начало: " + test.Started.ToString("dd.MM.yyyy HH:mm:ss zzz"));
            report.AppendLine("Завершение, включая очистку: " + test.Completed.ToString("dd.MM.yyyy HH:mm:ss zzz"));
            report.AppendLine("Исходный файл: " + (string.IsNullOrWhiteSpace(test.SourcePath) ? "не выбран" : test.SourcePath));
            report.AppendLine("Рабочая копия: " + (string.IsNullOrWhiteSpace(test.FilePath) ? "не создавалась" : test.FilePath));
            report.AppendLine(test.Description);
            if (!string.IsNullOrWhiteSpace(test.Evidence)) report.AppendLine("Подтверждение: " + test.Evidence);
            if (!string.IsNullOrWhiteSpace(test.TechnicalNote)) report.AppendLine("Уточнение: " + test.TechnicalNote);
            if (!string.IsNullOrWhiteSpace(test.LogNote)) report.AppendLine(test.LogNote);
            report.AppendLine(test.CleanupSucceeded ? "Временный файл и папка убраны либо не создавались." :
                "Не удалось завершить очистку. Папка: " + Path.GetDirectoryName(test.FilePath) + ". " + test.CleanupNote);
            report.AppendLine("Методика, п. 3.4.5: подготовка TXT с тестовой строкой, ожидание и контроль наличия файла.");
            report.AppendLine("Пользователь выбирает подготовленный образец. Программа проверяет его содержимое по SHA256 первых 68 байтов,");
            report.AppendLine("копирует выбранные байты в собственную тестовую папку и наблюдает за реакцией до 10 с.");
            report.AppendLine("Допускаются завершающие пробельные символы стандарта EICAR при общей длине не более 128 байтов.");
            report.AppendLine("Строка EICAR не генерируется. Программа удаляет только свою рабочую копию и её папку.");
            report.AppendLine("Исходный выбранный файл программа не изменяет и не удаляет.");
            report.AppendLine("Образец не запускался. Исключения антивируса и настройки защиты не изменялись.");
            report.AppendLine("Подтверждение: антивирусные ошибки Windows 225/226 или новое событие Defender 1116 с путём этого образца.");
            report.AppendLine("Событие 1116 подтверждает обнаружение, но не доказывает помещение в карантин или блокировку.");
            report.AppendLine("Исчезновение файла или обычный отказ в доступе сами по себе не считаются обнаружением.");
            report.AppendLine("Для стороннего антивируса без ошибок 225/226 может потребоваться сверка с его журналом.");
            report.AppendLine("Отсутствие подтверждения за время наблюдения не доказывает неисправность антивируса.");
            report.AppendLine();
            report.AppendLine("4. Брандмауэр Windows: " + run.Firewall.Status);
            report.AppendLine("Источник: HNetCfg.FwPolicy2, CurrentProfileTypes / FirewallEnabled.");
            foreach (FirewallProfile profile in run.Firewall.Profiles)
            {
                report.AppendLine(profile.Name + (profile.Active ? " (активна): " : " (не используется): ") +
                    FirewallStateText(profile.Enabled));
                if (!string.IsNullOrWhiteSpace(profile.Error)) report.AppendLine("Уточнение: " + profile.Error);
            }
            if (!string.IsNullOrWhiteSpace(run.Firewall.Note)) report.AppendLine(run.Firewall.Note);
            if (!string.IsNullOrWhiteSpace(run.Firewall.Error)) report.AppendLine("Уточнение: " + run.Firewall.Error);
            report.AppendLine("Прочитаны локальные настройки; результат может отличаться из-за групповой политики.");
            report.AppendLine("Этот пункт не проверяет фактическую фильтрацию, исключённые интерфейсы или сторонние экраны.");
            report.AppendLine();
            FirewallTestResult firewallTest = run.FirewallTest;
            report.AppendLine("5. Тест брандмауэра Windows: " + firewallTest.Status);
            report.AppendLine("Начало: " + firewallTest.Started.ToString("dd.MM.yyyy HH:mm:ss zzz"));
            report.AppendLine("Завершение, включая удаление правила: " + firewallTest.Completed.ToString("dd.MM.yyyy HH:mm:ss zzz"));
            report.AppendLine("Повышенные права: " + firewallTest.IsAdministrator);
            report.AppendLine("Программа: " + firewallTest.ProgramPath);
            report.AppendLine("Узел: " + firewallTest.Host + "; IPv4: " + firewallTest.Address + "; TCP: 443");
            report.AppendLine("Временное правило: " + firewallTest.RuleName);
            report.AppendLine("Исходное соединение: " + (firewallTest.Before == null ? "не установлено" : firewallTest.Before.ToString()));
            report.AppendLine("С правилом: " + (firewallTest.During == null ? "не выполнялось" : firewallTest.During.ToString()));
            report.AppendLine("После удаления: " + (firewallTest.After == null ? "не выполнялось" : firewallTest.After.ToString()));
            report.AppendLine("Параметры правила подтверждены: " + firewallTest.RuleVerified);
            report.AppendLine("Контрольная последовательность завершена: " + firewallTest.ControlCompleted);
            report.AppendLine("Активные профили сохранены: " + firewallTest.ProfileUnchanged);
            report.AppendLine(firewallTest.CleanupConfirmed ? "Временное правило отсутствует либо не создавалось." :
                "Удаление правила не подтверждено. Памятка: " + firewallTest.RecoveryFile);
            report.AppendLine(firewallTest.Note);
            if (!string.IsNullOrWhiteSpace(firewallTest.Error)) report.AppendLine("Уточнение: " + firewallTest.Error);
            if (!firewallTest.CleanupConfirmed)
                report.AppendLine("Команда ручного удаления именно этого правила, от имени администратора: " + firewallTest.RecoveryCommand);
            report.AppendLine("Метод: новые прямые TCP-соединения с одним IPv4 и портом до, во время и после правила.");
            report.AppendLine("Блокировка подтверждается только отказом WSAEACCES/10013 при установленном правиле и последующим восстановлением.");
            report.AppendLine("Один тайм-аут или другая сетевая ошибка не считаются доказательством блокировки.");
            report.AppendLine("Правило ограничено этой программой, удалённым IPv4, портом 443 и активными профилями Windows.");
            report.AppendLine("Проверяется выбранное исходящее TCP-соединение; другие направления, порты и сторонние экраны не проверялись.");
            report.AppendLine("Прямое TCP-соединение не использует системный HTTP-прокси; при недоступности исходного соединения тест не подтверждается.");
            report.AppendLine();
            report.AppendLine("Методика сетевой проверки");
            report.AppendLine("HTTPS HEAD, без переходов, лимит ожидания 8 с на адрес.");
            report.AppendLine("Измерено полное время запроса, включая DNS, соединение и TLS; это не ping.");
            report.AppendLine("HTTP 3xx/4xx также означает ответ узла, но не разрешение доступа к его данным.");
            report.AppendLine("Ошибка одного адреса не доказывает отсутствие Интернета или недоступность региона.");
            report.AppendLine("Регионы взяты из документации провайдеров; маршрут и публичный IP не измерялись.");
            report.AppendLine("Используются сетевые настройки Windows, включая системный прокси при его наличии.");
            report.AppendLine("https://yandex.cloud/en/docs/overview/concepts/region");
            report.AppendLine("https://docs.aws.amazon.com/general/latest/gr/s3.html");
            report.AppendLine("https://learn.microsoft.com/en-us/windows/win32/api/netfw/nf-netfw-inetfwpolicy2-get_firewallenabled");
            report.AppendLine("https://www.eicar.org/download-anti-malware-testfile/");
            report.AppendLine("https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus");
            report.AppendLine("https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes--0-499-");
            report.AppendLine("https://learn.microsoft.com/en-us/windows/win32/api/netfw/nf-netfw-inetfwrules-item");
            report.AppendLine("https://learn.microsoft.com/en-us/windows/win32/api/netfw/nf-netfw-inetfwrules-add");
            report.AppendLine("https://learn.microsoft.com/en-us/windows/win32/api/netfw/nf-netfw-inetfwrules-remove");
            report.AppendLine();
            report.AppendLine("Технический вывод текущего запуска");
            report.AppendLine(run.TechnicalOutput);
            return report.ToString();
        }

        private static AntivirusResult ReadAntivirus(CancellationToken cancellation, TechnicalLog trace)
        {
            IWscProductList products = null;
            var result = new AntivirusResult();
            try
            {
                cancellation.ThrowIfCancellationRequested();
                trace.Write("WSC", "CALL Activator.CreateInstance(CLSID=17072F7B-9ABE-4A74-A261-1EB76B55107A)");
                Type type = Type.GetTypeFromCLSID(new Guid("17072F7B-9ABE-4A74-A261-1EB76B55107A"), true);
                products = (IWscProductList)Activator.CreateInstance(type);
                trace.Write("WSC", "CALL IWscProductList.Initialize(provider=4 / ANTIVIRUS)");
                products.Initialize(4); // Запрос антивирусов в центре безопасности Windows.
                trace.Write("WSC", "RETURN Initialize: завершён без исключения. CALL GetCount()");
                int count = products.GetCount();
                trace.Write("WSC", "RETURN GetCount=" + count);
                for (int i = 0; i < count; i++)
                {
                    cancellation.ThrowIfCancellationRequested();
                    IWscProduct product = null;
                    try
                    {
                        trace.Write("WSC", "CALL GetItem(index=" + i + ")");
                        product = products.GetItem((uint)i);
                        trace.Write("WSC", "RETURN GetItem: получен IWscProduct. CALL GetProductName()");
                        string name = product.GetProductName();
                        trace.Write("WSC", "RETURN GetProductName=" + (name == null ? "<null>" : name) +
                            ". CALL GetProductState()");
                        int state = product.GetProductState();
                        trace.Write("WSC", "RETURN GetProductState=" + state);
                        result.Products.Add(new AntivirusProduct
                        {
                            Name = name ?? "Название не получено",
                            State = state
                        });
                    }
                    catch (COMException error)
                    {
                        trace.Error("WSC", error);
                        result.Errors.Add("Запись " + (i + 1) + ": " + error.Message);
                    }
                    finally { ReleaseOwnedComObject(product); }
                }
                AssessAntivirus(result);
                return result;
            }
            catch (OperationCanceledException error) { trace.Error("WSC", error); return AntivirusResult.Cancelled(); }
            catch (Exception error)
            {
                trace.Error("WSC", error);
                return AntivirusResult.Unconfirmed("Не удалось получить сведения Windows: " + error.Message);
            }
            finally { ReleaseOwnedComObject(products); }
        }

        private static void AssessAntivirus(AntivirusResult result)
        {
            if (result.Products.Count == 0)
            {
                result.Note = "Центр безопасности Windows не вернул сведения об антивирусах.";
                return; // Нет данных — это не доказательство отсутствия антивируса.
            }
            AntivirusProduct[] active = result.Products.Where(product => product.State == 0).ToArray();
            result.Hint = string.Join(", ", (active.Length > 0 ? active : result.Products.ToArray())
                .Select(product => string.IsNullOrWhiteSpace(product.Name) ? "Название не получено" : product.Name));
            if (active.Length > 0)
            {
                result.Status = "Включён";
                result.Level = result.Errors.Count == 0 ? CheckLevel.Good : CheckLevel.Warning;
            }
            else if (result.Errors.Count == 0 && result.Products.All(product => product.State >= 1 && product.State <= 3))
            {
                result.Status = "Неактивен";
                result.Level = CheckLevel.Bad;
            }
            result.Note = "Состояние сообщено центром безопасности Windows.";
        }

        private static string ProductStateText(int state)
        {
            if (state == 0) return "защита включена";
            if (state >= 1 && state <= 3) return "защита неактивна";
            return "состояние не получено";
        }

        private static FirewallResult ReadFirewall(CancellationToken cancellation, TechnicalLog trace)
        {
            object policy = null;
            var result = new FirewallResult();
            try
            {
                cancellation.ThrowIfCancellationRequested();
                trace.Write("FIREWALL", "CALL Activator.CreateInstance(ProgID=HNetCfg.FwPolicy2)");
                Type type = Type.GetTypeFromProgID("HNetCfg.FwPolicy2", true);
                policy = Activator.CreateInstance(type);
                trace.Write("FIREWALL", "CALL CurrentProfileTypes.get");
                int activeTypes = (int)GetComProperty(policy, "CurrentProfileTypes");
                trace.Write("FIREWALL", "RETURN CurrentProfileTypes=" + activeTypes + " (1=Domain, 2=Private, 4=Public)");
                int[] types = { 1, 2, 4 }; // Доменная, частная и общедоступная сети.
                string[] names = { "Доменная сеть", "Частная сеть", "Общедоступная сеть" };
                for (int i = 0; i < types.Length; i++)
                {
                    cancellation.ThrowIfCancellationRequested();
                    var profile = new FirewallProfile
                    {
                        Name = names[i], Active = (activeTypes & types[i]) != 0
                    };
                    try
                    {
                        trace.Write("FIREWALL", "CALL FirewallEnabled.get(profileType=" + types[i] + ")");
                        profile.Enabled = (bool)GetComProperty(policy, "FirewallEnabled", types[i]);
                        trace.Write("FIREWALL", "RETURN FirewallEnabled(" + types[i] + ")=" + profile.Enabled +
                            "; Active=" + profile.Active);
                    }
                    catch (Exception error)
                    {
                        trace.Error("FIREWALL", error);
                        profile.Error = error.GetBaseException().Message;
                    }
                    result.Profiles.Add(profile);
                }
                cancellation.ThrowIfCancellationRequested();
                AssessFirewall(result, activeTypes);
                return result;
            }
            catch (OperationCanceledException error) { trace.Error("FIREWALL", error); return FirewallResult.Cancelled(); }
            catch (Exception error)
            {
                trace.Error("FIREWALL", error);
                var failure = FirewallResult.Unconfirmed("Настройки недоступны. Подробности сохранены в отчёте.");
                failure.Error = error.GetBaseException().Message;
                return failure;
            }
            finally { ReleaseOwnedComObject(policy); }
        }

        private static object GetComProperty(object value, string name, params object[] index)
        {
            // Читаем системное COM-свойство без подключения дополнительных библиотек.
            return value.GetType().InvokeMember(name, BindingFlags.GetProperty, null, value, index);
        }

        private static void AssessFirewall(FirewallResult result, int activeTypes)
        {
            FirewallProfile[] active = result.Profiles.Where(profile => profile.Active).ToArray();
            if (active.Length == 0 || (activeTypes & ~7) != 0)
            {
                result.Hint = "Активный сетевой профиль не определён";
                result.Note = "Windows не сообщила известный активный профиль сети.";
                return;
            }
            result.Hint = string.Join(", ", active.Select(profile => profile.Name));
            if (active.Any(profile => profile.Enabled == false))
            {
                result.Status = active.All(profile => profile.Enabled == false) ? "Выключен" : "Есть отключённые";
                result.Level = CheckLevel.Warning;
            }
            else if (active.All(profile => profile.Enabled == true))
            {
                result.Status = "Включён";
                result.Level = CheckLevel.Good;
            }
            result.Note = "Состояние относится к брандмауэру Windows в активных профилях.";
        }

        private static string FirewallStateText(bool? enabled)
        {
            return !enabled.HasValue ? "нет данных" : enabled.Value ? "включён" : "выключен";
        }

        private static void ReleaseOwnedComObject(object value)
        {
            if (value == null || !Marshal.IsComObject(value)) return;
            try { Marshal.FinalReleaseComObject(value); }
            catch (Exception error) { Debug.WriteLine("Освобождение COM: " + error.Message); }
        }

        private enum CheckLevel { Good, Warning, Bad, Unknown, Cancelled }

        private sealed class AntivirusProduct
        {
            public string Name;
            public int State;
        }

        private sealed class AntivirusResult
        {
            public string Status = "Нет данных";
            public string Hint = "Сведения Windows недоступны";
            public string Note = "";
            public CheckLevel Level = CheckLevel.Unknown;
            public readonly List<AntivirusProduct> Products = new List<AntivirusProduct>();
            public readonly List<string> Errors = new List<string>();

            public static AntivirusResult Unconfirmed(string message)
            {
                return new AntivirusResult { Note = message };
            }
            public static AntivirusResult Cancelled()
            {
                return new AntivirusResult
                {
                    Status = "Остановлено", Hint = "Проверка остановлена",
                    Note = "Получение сведений об антивирусе остановлено пользователем.", Level = CheckLevel.Cancelled
                };
            }
        }

        private sealed class FirewallProfile
        {
            public string Name;
            public bool Active;
            public bool? Enabled;
            public string Error;
        }

        private sealed class FirewallResult
        {
            public string Status = "Нет данных";
            public string Hint = "Сведения Windows недоступны";
            public string Note = "";
            public string Error;
            public CheckLevel Level = CheckLevel.Unknown;
            public readonly List<FirewallProfile> Profiles = new List<FirewallProfile>();

            public static FirewallResult Unconfirmed(string message)
            {
                return new FirewallResult { Note = message };
            }
            public static FirewallResult Cancelled()
            {
                return new FirewallResult
                {
                    Status = "Остановлено", Hint = "Проверка остановлена",
                    Note = "Получение сведений о брандмауэре остановлено пользователем.", Level = CheckLevel.Cancelled
                };
            }
        }

        // Системные интерфейсы Windows. Коды HRESULT автоматически превращаются
        // в исключения COMException, поэтому в основной логике нет ручных проверок кодов.
        [ComImport, Guid("722A338C-6E8E-4E72-AC27-1417FB0C81C2")]
        [InterfaceType(ComInterfaceType.InterfaceIsDual)]
        private interface IWscProductList
        {
            void Initialize(uint provider);
            int GetCount();
            [return: MarshalAs(UnmanagedType.Interface)]
            IWscProduct GetItem(uint index);
        }

        [ComImport, Guid("8C38232E-3A45-4A27-92B0-1A16A975F669")]
        [InterfaceType(ComInterfaceType.InterfaceIsDual)]
        private interface IWscProduct
        {
            [return: MarshalAs(UnmanagedType.BStr)]
            string GetProductName();
            int GetProductState();
        }

        protected override void OnSourceInitialized(EventArgs e)
        {
            base.OnSourceInitialized(e);
            try
            {
                IntPtr handle = new WindowInteropHelper(this).Handle;
                SetTitleBarAttribute(handle, 20, 1);
                SetTitleBarAttribute(handle, 35, 0x00202020);
                SetTitleBarAttribute(handle, 36, 0x00F2F2F2);
            }
            catch (DllNotFoundException) { Debug.WriteLine("DWM недоступен."); }
            catch (EntryPointNotFoundException) { Debug.WriteLine("Настройка DWM недоступна."); }
        }

        private static void SetTitleBarAttribute(IntPtr handle, int attribute, int value)
        {
            int result = DwmSetWindowAttribute(handle, attribute, ref value, sizeof(int));
            if (result < 0) Debug.WriteLine("DWM: HRESULT 0x" + result.ToString("X8"));
        }

        [DllImport("dwmapi.dll", ExactSpelling = true)]
        private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attribute, ref int value, int size);

        private enum ProbeOutcome { Reply, Error, Timeout, Cancelled }

        private sealed class ProbeTarget
        {
            public readonly string Label;
            public readonly string Location;
            public readonly string Address;
            public ProbeTarget(string label, string location, string address)
            {
                Label = label;
                Location = location;
                Address = address;
            }
        }

        private sealed class ProbeResult
        {
            public ProbeTarget Target;
            public ProbeOutcome Outcome;
            public int HttpCode;
            public long ElapsedMilliseconds;
            public string Detail;
            public WebExceptionStatus? NetworkError;
        }

        private sealed class CheckRun
        {
            public DateTimeOffset Started;
            public DateTimeOffset Completed;
            public long DurationMilliseconds;
            public ProbeResult[] Results;
            public AntivirusResult Antivirus;
            public FirewallResult Firewall;
            public EicarTestResult AntivirusTest;
            public FirewallTestResult FirewallTest;
            public string TechnicalOutput;
        }
    }
}
