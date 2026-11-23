using System;
using System.Text;

namespace Mobks.SecurityCheck
{
    // Отдельный экземпляр на запуск: ответы разных потоков не перемешиваются,
    // а поздний ответ старой проверки не попадает в следующий журнал.
    internal sealed class TechnicalLog
    {
        private readonly object _gate = new object();
        private readonly StringBuilder _text = new StringBuilder();
        private bool _finished;

        internal void Write(string source, string message)
        {
            lock (_gate)
            {
                if (_finished) return;
                _text.Append("[").Append(DateTimeOffset.Now.ToString("HH:mm:ss.fff zzz"))
                    .Append("] [").Append(source).Append("] ").AppendLine(message);
            }
        }

        internal void Error(string source, Exception error)
        {
            Write(source, "EXCEPTION HRESULT=0x" + error.HResult.ToString("X8") + Environment.NewLine + error);
        }

        internal string ReadFrom(int offset)
        {
            lock (_gate) return _text.ToString(offset, _text.Length - offset);
        }

        internal string Finish()
        {
            lock (_gate)
            {
                _finished = true;
                return _text.ToString();
            }
        }
    }
}
