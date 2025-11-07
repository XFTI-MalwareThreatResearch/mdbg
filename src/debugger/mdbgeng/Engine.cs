//---------------------------------------------------------------------
//  This file is part of the CLR Managed Debugger (mdbg) Sample.
// 
//  Copyright (C) Microsoft Corporation.  All rights reserved.
//---------------------------------------------------------------------
using System;
using System.Text;
using System.Threading;
using System.Diagnostics;
using System.Collections;
using System.Collections.Generic;
using System.Security.Permissions;

using Microsoft.Samples.Debugging.CorDebug;
using Microsoft.Samples.Debugging.Native;
using Microsoft.Samples.Debugging.CorDebug.NativeApi;
using Microsoft.Samples.Debugging.CorMetadata;
using System.Runtime.InteropServices;
using mdbgeng;

namespace Microsoft.Samples.Debugging.MdbgEngine
{
    /// <summary>
    /// MDbgOptions class.  This controls when the debugger should stop.
    /// </summary>
    public sealed class MDbgOptions : MarshalByRefObject
    {
        /// <summary>
        /// Gets or sets if it should stop when modules are loaded.
        /// </summary>
        /// <value>true if it should stop, else false.</value>
        public bool StopOnModuleLoad
        {
            get
            {
                return m_StopOnModuleLoad;
            }
            set
            {
                m_StopOnModuleLoad = value;
            }
        }
        private bool m_StopOnModuleLoad;

        /// <summary>
        /// Gets or sets if it should stop when classes are loaded.
        /// </summary>
        /// <value>true if it should stop, else false.</value>
        public bool StopOnClassLoad
        {
            get
            {
                return m_StopOnClassLoad;
            }
            set
            {
                m_StopOnClassLoad = value;
            }
        }
        private bool m_StopOnClassLoad;

        public string FunctionLogMode
        {
            get
            {
                return m_FunctionLogMode;
            }

            set
            {
                m_FunctionLogMode = value;
            }
        }

        private string m_FunctionLogMode = null;

        /// <summary>
        /// Gets or sets if it should stop when assemblies are loaded.
        /// </summary>
        /// <value>true if it should stop, else false.</value>
        public bool StopOnAssemblyLoad
        {
            get
            {
                return m_StopOnAssemblyLoad;
            }
            set
            {
                m_StopOnAssemblyLoad = value;
            }
        }
        private bool m_StopOnAssemblyLoad;

        /// <summary>
        /// Gets or sets if it should stop when assemblies are unloaded.
        /// </summary>
        /// <value>true if it should stop, else false.</value>
        public bool StopOnAssemblyUnload
        {
            get
            {
                return m_StopOnAssemblyUnload;
            }
            set
            {
                m_StopOnAssemblyUnload = value;
            }
        }
        private bool m_StopOnAssemblyUnload;

        /// <summary>
        /// Gets or sets if it should stop when new threads are created.
        /// </summary>
        /// <value>true if it should stop, else false.</value>
        public bool StopOnNewThread
        {
            get
            {
                return m_StopOnNewThread;
            }
            set
            {
                m_StopOnNewThread = value;
            }
        }
        private bool m_StopOnNewThread;

        /// <summary>
        /// Gets or sets if it should stop on Exception callbacks.
        /// </summary>
        /// <value>true if it should stop, else false.</value>
        public bool StopOnException
        {
            get
            {
                return m_StopOnException;
            }
            set
            {
                m_StopOnException = value;
            }
        }
        private bool m_StopOnException;

        /// <summary>
        /// Gets or sets if it should stop on Exception callbacks.
        /// </summary>
        /// <value>true if it should stop, else false.</value>
        public bool StopOnUnhandledException
        {
            get
            {
                return m_StopOnUnhandledException;
            }
            set
            {
                m_StopOnUnhandledException = value;
            }
        }
        private bool m_StopOnUnhandledException = true; // default is on.

        /// <summary>
        /// Gets or sets if it should stop on Enhanced Exception callbacks.
        /// </summary>
        /// <value>true if it should stop, else false.</value>
        public bool StopOnExceptionEnhanced
        {
            get
            {
                return m_StopOnExceptionEnhanced;
            }
            set
            {
                m_StopOnExceptionEnhanced = value;
            }
        }
        private bool m_StopOnExceptionEnhanced;

        /// <summary>
        /// Gets or sets if it should stop when messages are logged.
        /// You must still enable log messages per process by calling CorProcess.EnableLogMessage(true)
        /// </summary>
        /// <value>true if it should stop, else false.</value>
        public bool StopOnLogMessage
        {
            get
            {
                return m_stopOnLogMessage;
            }
            set
            {
                m_stopOnLogMessage = value;
            }
        }
        private bool m_stopOnLogMessage;

        /// <summary>
        /// Gets or sets the Symbol path.
        /// </summary>
        /// <value>The Symbol path.</value>
        public string SymbolPath
        {
            get
            {
                return m_symbolPath;
            }
            set
            {
                m_symbolPath = value;
            }
        }
        private string m_symbolPath = null;

        /// <summary>
        /// Gets or sets if processes are created with a new console.
        /// </summary>
        /// <value>Default is false.</value>
        public bool CreateProcessWithNewConsole
        {
            get
            {
                return m_CreateProcessWithNewConsole;
            }
            set
            {
                m_CreateProcessWithNewConsole = value;
            }
        }
        private bool m_CreateProcessWithNewConsole;

        /// <summary>
        /// Gets or sets if memory addresses are displayed.
        /// Normally of little value in pure managed debugging, and causes
        /// unpredictable output for automated testing.
        /// </summary>
        /// <value>Default is false.</value>
        public bool ShowAddresses
        {
            get
            {
                return m_ShowAddresses;
            }
            set
            {
                m_ShowAddresses = value;
            }
        }
        private bool m_ShowAddresses = false;

        /// <summary>
        /// Gets or sets if full paths are displayed in stack traces.
        /// </summary>
        /// <value>Default is true.</value>
        public bool ShowFullPaths
        {
            get
            {
                return m_ShowFullPaths;
            }
            set
            {
                m_ShowFullPaths = value;
            }
        }
        private bool m_ShowFullPaths = true;

        public bool BreakOnModuleCctor
        {
            get
            {
                return m_BreakOnModuleCctor;
            }

            set
            {
                m_BreakOnModuleCctor = value;
            }
        }

        private bool m_HideManagedDebugger = false;

        public bool HideManagedDebugger
        {
            get
            {
                return m_HideManagedDebugger;
            }

            set
            {
                m_HideManagedDebugger = value;
            }
        }


        private bool m_BreakOnModuleCctor = false;

        public string LogFile
        {
            get
            {
                return m_logFile;
            }

            set
            {
                m_logFile = value;
            }
        }

        private string m_logFile = string.Empty;

        public string[] EntryPointCommands
        {
            get
            {
                return m_entryPointCommands;
            }

            set
            {
                m_entryPointCommands = value;
            }
        }

        private string[] m_entryPointCommands = null;

        public bool EntryPointPassed
        {
            get
            {
                return m_entryPointPassed;
            }

            set
            {
                m_entryPointPassed = value;
            }
        }
        private bool m_entryPointPassed = false;

        internal MDbgOptions()  // only one instance in mdbgeng
        {
        }
    }

    /// <summary>
    /// A default implementation of run/attach versioning policy
    /// </summary>
    public static class MdbgVersionPolicy
    {
        /// <summary>
        /// Given the full path to a binary, determines a default CLR runtime version which
        /// should be used to debug it.
        /// </summary>
        /// <param name="filePath">The full path to a binary.</param>
        /// <returns>The CLR version string to use for debugging; null if unknown.</returns>
        public static string GetDefaultLaunchVersion(string filePath)
        {
            string version = GetDefaultRuntimeForFile(filePath);
            if (version != null)
                return version;

            // If the binary doesn't bind to a clr then just debug it with the same
            // runtime this debugger is running in (a very arbitrary choice)
            return RuntimeEnvironment.GetSystemVersion();
        }

        /// <summary>
        /// Given the full path to a binary, finds the CLR runtime version which
        /// it will bind to.
        /// </summary>
        /// <param name="filePath">The full path to a binary.</param>
        /// <returns>The version string that the binary will bind to; null if unknown.</returns>
        /// <remarks>If ICLRMetaHostPolicy can be asked, it is used. Otherwise
        /// fall back to mscoree!GetRequestedRuntimeVersion.</remarks>
        public static String GetDefaultRuntimeForFile(String filePath)
        {
            String version = null;

            CLRMetaHostPolicy policy;
            try
            {
                policy = new CLRMetaHostPolicy();
            }
            catch (NotImplementedException)
            {
                policy = null;
            }
            catch (System.EntryPointNotFoundException)
            {
                policy = null;
            }

            if (policy != null)
            {
                // v4 codepath
                StringBuilder ver = new StringBuilder();
                StringBuilder imageVer = new StringBuilder();
                CLRRuntimeInfo rti = null;

                String configPath = null;
                if (System.IO.File.Exists(filePath + ".config"))
                {
                    configPath = filePath + ".config";
                }

                try
                {
                    rti = policy.GetRequestedRuntime(CLRMetaHostPolicy.MetaHostPolicyFlags.metaHostPolicyHighCompat,
                                                        filePath,
                                                        configPath,
                                                        ref ver,
                                                        ref imageVer);
                }
                catch (System.Runtime.InteropServices.COMException)
                {
                    Debug.Assert(rti == null);
                }

                if (rti != null)
                {
                    version = rti.GetVersionString();
                }
                else
                {
                    version = null;
                }
            }
            else
            {
                // v2 codepath
                try
                {
                    version = CorDebugger.GetDebuggerVersionFromFile(filePath);
                }
                catch (System.Runtime.InteropServices.COMException)
                {
                    // we could not retrieve dee version. 
                    // Leave version null;
                    Debug.Assert(version == null);
                }
            }

            return version;
        }

        /// <summary>
        /// Returns the version of the runtime to debug in a process
        /// we are attaching to, assuming we can only pick one
        /// </summary>
        /// <param name="processId">The process to attach to</param>
        /// <returns>The version of the runtime to debug, or null if the policy can't decide</returns>
        public static string GetDefaultAttachVersion(int processId)
        {
            try
            {
                CLRMetaHost mh = new CLRMetaHost();
                List<CLRRuntimeInfo> runtimes = new List<CLRRuntimeInfo>(mh.EnumerateLoadedRuntimes(processId));
                if (runtimes.Count > 1)
                {
                    // It is ambiguous so just give up
                    return null;
                }
                else if (runtimes.Count == 1)
                {
                    return runtimes[0].GetVersionString();
                }
            }
            catch (EntryPointNotFoundException)
            {
                try
                {
                    return CorDebugger.GetDebuggerVersionFromPid(processId);
                }
                catch (COMException) { }
            }

            // if we have neither failed nor detected a version at this point then there was no
            // CLR loaded. Now we try to determine what CLR the process will load by examining its
            // binary
            string binaryPath = GetBinaryPathFromPid(processId);
            if (binaryPath != null)
            {
                string version = GetDefaultRuntimeForFile(binaryPath);
                if (version != null)
                {
                    return version;
                }
            }

            // and if that doesn't work, return the version of the CLR the debugger is
            // running against (a very arbitrary choice)
            return Environment.Version.ToString();
        }

        /// <summary>
        /// Attempts to retrieve the path to the binary from a running process
        /// Returns null on failure
        /// </summary>
        /// <param name="processId">The process to get the binary for</param>
        /// <returns>The path to the primary executable or null if it could not be determined</returns>
        private static string GetBinaryPathFromPid(int processId)
        {
            string programBinary = null;
            try
            {
                CorPublish.CorPublish cp = new CorPublish.CorPublish();
                CorPublish.CorPublishProcess cpp = cp.GetProcess(processId);
                programBinary = cpp.DisplayName;
            }
            catch
            {
                // try an alternate method
                using (ProcessSafeHandle ph = CorDebug.NativeMethods.OpenProcess(
                        (int)(CorDebug.NativeMethods.ProcessAccessOptions.ProcessVMRead |
                              CorDebug.NativeMethods.ProcessAccessOptions.ProcessQueryInformation |
                              CorDebug.NativeMethods.ProcessAccessOptions.ProcessDupHandle |
                              CorDebug.NativeMethods.ProcessAccessOptions.Synchronize),
                        false, // inherit handle
                        processId))
                {
                    if (!ph.IsInvalid)
                    {
                        StringBuilder sb = new StringBuilder(CorDebug.NativeMethods.MAX_PATH);
                        int neededSize = sb.Capacity;
                        CorDebug.NativeMethods.QueryFullProcessImageName(ph, 0, sb, ref neededSize);
                        programBinary = sb.ToString();
                    }
                }
            }

            return programBinary;
        }
    }

    /// <summary>
    /// A delegate that returns a default implementation for stack walking frame factory.
    /// </summary>
    /// <returns>Frame factory used for newly created processes.</returns>
    public delegate IMDbgFrameFactory StackWalkingFrameFactoryProvider();

    /// <summary>
    /// The MDbgEngine class.
    /// </summary>
    public sealed class MDbgEngine : MarshalByRefObject
    {

        /// <summary>
        /// Initializes a new instance of the MDbgEngine class.
        /// </summary>
        public MDbgEngine()
        {
            m_processMgr = new MDbgProcessCollection(this);
        }

        /// <summary>
        /// Function that extensions can call to register a FrameFactory used for all new processes
        /// </summary>
        /// <param name="provider">A delegate that creates a new FrameFactory</param>
        /// <param name="updateExistingProcesses">If set, all currently debugged programs will be refreshed with new FrameFactory
        /// from the supplied provider.</param>
        public void RegisterDefaultStackWalkingFrameFactoryProvider(StackWalkingFrameFactoryProvider provider, bool updateExistingProcesses)
        {
            m_defaultStackWalkingFrameFactoryProvider = provider;
            if (updateExistingProcesses)
            {
                foreach (MDbgProcess p in Processes)
                {
                    // force reloading of new frame factories...
                    p.Threads.FrameFactory = null;
                }
            }
        }

        //////////////////////////////////////////////////////////////////////////////////
        //
        // Controlling Commands
        //
        //////////////////////////////////////////////////////////////////////////////////

        /// <summary>
        /// creates a new debugged process.
        /// </summary>
        /// <param name="commandLine">The command to run.</param>
        /// <param name="commandArguments">The arguments for the command.</param>
        /// <param name="debugMode">The debug mode to run with.</param>
        /// <param name="deeVersion">The version of debugging interfaces that should be used for
        ///   debugging of the started program. If this value is null, the default (latest) version
        ///   of interface is used.
        /// </param>
        /// <returns>The resulting MDbgProcess.</returns>
        public MDbgProcess CreateProcess(string commandLine, string commandArguments,
                                         DebugModeFlag debugMode, string deeVersion)
        {
            CorDebugger debugger;
            if (deeVersion == null)
            {
                debugger = new CorDebugger(CorDebugger.GetDefaultDebuggerVersion());
            }
            else
            {
                debugger = new CorDebugger(deeVersion);
            }
            MDbgProcess p = m_processMgr.CreateLocalProcess(debugger);
            p.DebugMode = debugMode;
            p.CreateProcess(commandLine, commandArguments);
            return p;
        }

        [DllImport("kernel32", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr GetProcAddress([In] IntPtr hModule, [In, MarshalAs(UnmanagedType.LPStr)] string lpProcName);

        [DllImport("kernel32", CharSet = CharSet.Ansi, SetLastError = true)]
        private static extern IntPtr LoadLibraryEx([In, MarshalAs(UnmanagedType.LPStr)] string lpFileName, IntPtr hFile, uint dwFlags);
        private const uint LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR = 0x00000100;
        private const uint LOAD_LIBRARY_SEARCH_DEFAULT_DIRS = 0x00001000;
        static T GetDelegate<T>(IntPtr handle, string funcName) where T : class
        {
            var addr = GetProcAddress(handle, funcName);
            if (addr == IntPtr.Zero)
                return null;
            return (T)(object)Marshal.GetDelegateForFunctionPointer(addr, typeof(T));
        }

        delegate int EnumerateCLRsType(uint debuggeePID, out IntPtr ppHandleArrayOut, out IntPtr ppStringArrayOut, out uint pdwArrayLengthOut);

        private EnumerateCLRsType EnumerateCLRs = null;

        // xor eax,eax / retn
        static readonly byte[] returnFalse_x86 = new byte[] { 0x33, 0xC0, 0xC3 };
        // push 1 / pop eax / retn
        static readonly byte[] returnTrue_x86 = new byte[] { 0x6A, 0x01, 0x58, 0xC3 };

        private void WriteReturnFalse(MDbgProcess prc, ulong addr)
        {
            prc.CorProcess.WriteMemory((long)addr, returnFalse_x86);
        }

        private void WriteReturnTrue(MDbgProcess prc, ulong addr)
        {
            prc.CorProcess.WriteMemory((long)addr, returnTrue_x86);
        }

        private static List<int> hiddenPids = new List<int>();

        public void ExecuteManagedDebuggerHideOperation(MDbgProcess prc)
        {
            if(prc == null)
            {
                //no active process, cant change.
                return;
            }

            if(hiddenPids.Contains(prc.CorProcess.Id))
            {
                return; //already hidden.
            }
            hiddenPids.Add(prc.CorProcess.Id);
            string clrPath = string.Empty;
            string clrFolder = string.Empty;
            string debuggeeVersion = string.Empty;


            CLRMetaHost mh = new CLRMetaHost();
            foreach (CLRRuntimeInfo info in mh.EnumerateLoadedRuntimes(Process.GetCurrentProcess().Id))
            {
                clrFolder = info.GetRuntimeDirectory();
                debuggeeVersion = info.GetVersionString();
                break;
            }
            Debug.Assert(clrFolder != String.Empty && debuggeeVersion != String.Empty);
            foreach (ProcessModule proc in Process.GetCurrentProcess().Modules)
            {
                if(proc.FileName.StartsWith(clrFolder))
                {
                    if (proc.ModuleName == "clr.dll") //TODO: theres some other possible names here.
                    {
                        clrPath = proc.FileName;
                        break;
                    }
                }
            }
            Debug.Assert(clrPath != String.Empty);
            ECallManager mgr = new ECallManager(prc.CorProcess.Id, clrPath);
            bool isClrV2OrOlder =
                debuggeeVersion != string.Empty &&
                (debuggeeVersion.StartsWith("v1.", StringComparison.OrdinalIgnoreCase) ||
                debuggeeVersion.StartsWith("v2.", StringComparison.OrdinalIgnoreCase));
            const string debuggerClassName = "System.Diagnostics.Debugger";
            bool b = mgr.FindFunc(debuggerClassName, "LaunchInternal", out ulong addr);
            if (b)
            {
                if (isClrV2OrOlder)
                    WriteReturnFalse(prc, addr);
                else
                    WriteReturnTrue(prc, addr);
            }

            b = mgr.FindFunc(debuggerClassName, "get_IsAttached", out addr);
            if (!b)
                b = mgr.FindFunc(debuggerClassName, "IsDebuggerAttached", out addr);
            if (b)
                WriteReturnFalse(prc, addr);

            b = mgr.FindFunc(debuggerClassName, "IsLogging", out addr);
            if (b)
                WriteReturnFalse(prc, addr);
        }


        /// <summary>
        /// OBSOLETE
        /// Attach to a process with the given Process ID
        /// </summary>
        /// <param name="processId">The Process ID to attach to.</param>
        /// <returns>The resulting MDbgProcess.</returns>
        [Obsolete("Use Attach(int, string)")]
        public MDbgProcess Attach(int processId)
        {
            string deeVersion = MdbgVersionPolicy.GetDefaultAttachVersion(processId);
            return Attach(processId, deeVersion);
        }


        /// <summary>
        /// Attach to a process with the given Process ID
        /// Only debug the specified CLR version; all others are ignored.
        /// </summary>
        /// <param name="processId">The Process ID to attach to.</param>
        /// <param name="version">The version string for the CLR instance to debug.</param>
        /// <returns>The resulting MDbgProcess.</returns>
        public MDbgProcess Attach(int processId, string version)
        {
            Debug.Assert(version != null);
            return Attach(processId, null, version);
        }

        /// <summary>
        /// Attach to a process with the given Process ID
        /// Only debug the specified CLR version; all others are ignored.
        /// </summary>
        /// <param name="processId">The Process ID to attach to.</param>
        /// <param name="attachContinuationEvent">A OS event handle which must be set to unblock the debuggee
        /// when first continuing from attach</param>
        /// <param name="version">The version string for the CLR instance to debug.</param>
        /// <returns>The resulting MDbgProcess.</returns>
        public MDbgProcess Attach(int processId,
            Microsoft.Samples.Debugging.Native.SafeWin32Handle attachContinuationEvent,
            string version)
        {
            Debug.Assert(version != null);
            MDbgProcess p = m_processMgr.CreateLocalProcess(new CorDebugger(version));
            p.Attach(processId, attachContinuationEvent);
            return p;
        }


        //////////////////////////////////////////////////////////////////////////////////
        //
        // Info about debugger process
        //
        //////////////////////////////////////////////////////////////////////////////////

        /// <summary>
        /// Gets the MDbgProcessCollection.
        /// </summary>
        /// <value>The MDbgProcessCollection.</value>
        public MDbgProcessCollection Processes
        {
            get
            {
                return m_processMgr;
            }
        }

        /// <summary>
        /// Gets the current MDbgOptions.
        /// </summary>
        /// <value>The MDbgOptions.</value>
        public MDbgOptions Options
        {
            get
            {
                return m_options;
            }
        }

        //////////////////////////////////////////////////////////////////////////////////
        //
        // Private Implementation Part
        //
        //////////////////////////////////////////////////////////////////////////////////

        //////////////////////////////////////////////////////////////////////////////////
        //
        // Local variables
        //
        //////////////////////////////////////////////////////////////////////////////////

        private MDbgProcessCollection m_processMgr;

        private MDbgOptions m_options = new MDbgOptions();

        internal StackWalkingFrameFactoryProvider m_defaultStackWalkingFrameFactoryProvider = null;
    }
}
