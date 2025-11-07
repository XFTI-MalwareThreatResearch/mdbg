using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;

namespace Microsoft.Samples.Debugging.MdbgEngine
{
    internal class FunctionLog
    {
        private static string logPath;

        private static object _lock = new object();

        public static void Initialize(string path)
        {
            logPath = path;
        }

        public static bool IsInitialized()
        {
            return logPath != null;
        }

        public static void WriteString(string str)
        {
            lock(_lock)
            {
                if(logPath != null)
                {
                    File.AppendAllLines(logPath, new string[] { str });
                }
            }
        }
    }
}
