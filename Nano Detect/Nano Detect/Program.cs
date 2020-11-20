using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Net;
using System.Runtime.InteropServices;
using System.ServiceProcess;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Nano_Detect {
    class Program {
        /// <summary>
        /// Gets the PID of specifc services
        /// </summary>
        static uint getService(string serviceName) {
            uint processId = 0;
            string qry = "SELECT PROCESSID FROM WIN32_SERVICE WHERE NAME = '" + serviceName + "'";
            ManagementObjectSearcher searcher = new ManagementObjectSearcher(qry);
            foreach (System.Management.ManagementObject mngntObj in searcher.Get()) {
                processId = (uint) mngntObj["PROCESSID"];
            }
            return processId;
        }

        static void runCMD(string command) {
            Process cmd = new Process();
            cmd.StartInfo.FileName = "cmd.exe";
            cmd.StartInfo.RedirectStandardInput = true;
            cmd.StartInfo.RedirectStandardOutput = true;
            cmd.StartInfo.CreateNoWindow = true;
            cmd.StartInfo.UseShellExecute = false;
            cmd.Start();

            cmd.StandardInput.WriteLine(command);
            cmd.StandardInput.Flush();
            cmd.StandardInput.Close();
            cmd.WaitForExit();
        }

        //=============================================================================================================\\

        static WebClient wc = new WebClient();
        
        static string currentPath = AppDomain.CurrentDomain.BaseDirectory;

        static Dictionary<string, string> javawDetections = new Dictionary<string, string>();
        static Dictionary<string, string> dpsDetections = new Dictionary<string, string>();
        static Dictionary<string, string> dnsCacheDetections = new Dictionary<string, string>();

        static string[] serviceList = { "DPS", "DiagTrack", "Dnscache", "PcaSvc" };
        static string[] recordingSoftware = { "obs32", "obs64", "ShareX", "action", "amddvr", "amdow" };

        static string javawDump = "", dpsDump = "", dnsCacheDump = "";
        static bool recording = false;

        static void Main(string[] args) {
            Console.CursorVisible = false;

            string neededPath = Path.GetPathRoot(Environment.SystemDirectory);
            var selectedPath = System.IO.Path.GetDirectoryName(currentPath);

            if (selectedPath.Substring(0, 3) != neededPath) {
                Console.WriteLine($"You must run this program on your main drive. ({neededPath})");
                Console.ReadLine();
                Environment.Exit(0);
            }

            Stopwatch sw = new Stopwatch();
            sw.Start();

            // general setups
            setupAssets();
            setupDetections();

            // generic checks
            recodingChecker();
            serviceChecker();

            // process scanners
            scanJavaw();
            scanDPS();
            scanDnsCache();

            Console.WriteLine($"  -  Scan finished in {sw.ElapsedMilliseconds}ms.");
            Console.ReadLine();
        }

        /// <summary>
        /// Install whatever files are needed
        /// </summary>
        static void setupAssets() {
            try {
                Directory.CreateDirectory("assets");
                File.WriteAllBytes("assets//dumper.exe", Properties.Resources.s2);
            }
            catch { }
        }

        /// <summary>
        /// Install whatever files are needed
        /// </summary>
        static void setupDetections() {
            try {
                string javaw = wc.DownloadString("LINK JAVAW STRINGS HERE");
                string dps = wc.DownloadString("LINK DPS STRINGS HERE");
                string dnsCache = wc.DownloadString("LINK DNSCACHE STRINGS HERE");

                // parse javaw strings
                foreach (string line in javaw.Split('\n')) {
                    if (line.Length > 4) {
                        string[] parsed = line.Split('_');
                        javawDetections.Add(parsed.ElementAt(0), parsed.ElementAt(1).Substring(0, parsed.ElementAt(1).Length - 1));
                    }
                }

                // parse dps strings
                foreach (string line in dps.Split('\n')) {
                    if (line.Length > 4) {
                        string[] parsed = line.Split('_');
                        dpsDetections.Add(parsed.ElementAt(0), parsed.ElementAt(1).Substring(0, parsed.ElementAt(1).Length - 1));
                    }
                }

                // parse dnsCache strings
                foreach (string line in dnsCache.Split('\n')) {
                    if (line.Length > 4) {
                        string[] parsed = line.Split('_');
                        dnsCacheDetections.Add(parsed.ElementAt(0), parsed.ElementAt(1).Substring(0, parsed.ElementAt(1).Length - 1));
                    }
                }
            }
            catch { Console.WriteLine("error when setting up detections."); Console.ReadLine(); }
        }

        /// <summary>
        /// Alert user if any recording software is open
        /// </summary>
        static void recodingChecker() {
            try {
                Console.WriteLine(" [#] Recording sofrware check");

                string recordingProcesses = "";
                Process[] procList = Process.GetProcesses();
                foreach (Process p in procList) {
                    foreach (string program in recordingSoftware) {
                        if (p.ProcessName == program) {
                            recordingProcesses += program + ", ";
                            recording = true;
                        }
                    }
                }

                if (recording)
                    Console.WriteLine($"  -  Recoding software detected ({recordingProcesses.Substring(0, recordingProcesses.Length - 2)})");
            }
            catch { Console.WriteLine("error when checking recording software."); Console.ReadLine(); }
        }

        /// <summary>
        /// Checks if specific services were tampered with to prevent strings from being found.
        /// </summary>
        static void serviceChecker() {
            try {
                Console.WriteLine("\n [#] Scanning");

                foreach (string service in serviceList) {
                    ServiceController sc = new ServiceController(service);

                    if (sc.StartType == ServiceStartMode.Automatic && sc.Status != ServiceControllerStatus.Running)
                        Console.WriteLine($"  -  Important service tampered with ({service})");
                }
            }
            catch { Console.WriteLine("error when checking services."); Console.ReadLine(); }
        }

        /// <summary>
        /// Create a javaw dump using strings2 and search for strings
        /// </summary>
        static void scanJavaw() {
            try {
                // get process count
                int procCount = 0;
                foreach (var process in Process.GetProcessesByName("javaw"))
                    procCount++;

                // only scan if 1 process is open
                if (procCount == 1) {
                    foreach (var process in Process.GetProcessesByName("javaw")) {
                        // dump service with strings2
                        runCMD($"{currentPath}assets\\dumper.exe -pid {process.Id} -l 4 -nh -asm -raw > {currentPath}assets\\JAVAW");

                        // read dump
                        javawDump = File.ReadAllText("assets\\JAVAW");

                        // scan dump for strings
                        foreach (KeyValuePair<string, string> detection in javawDetections)
                            if (javawDump.Contains(detection.Key))
                                Console.WriteLine($"  -  {detection.Value} has been detected (In instance)");
                    }
                } else if (procCount > 1)
                    Console.WriteLine($"  -  More than one instance of minecraft is running");
            }
            catch { Console.WriteLine("error when scanning javaw."); Console.ReadLine(); }
        }

        /// <summary>
        /// Create a dps dump using strings2 and search for strings
        /// </summary>
        static void scanDPS() {
            try {
                // dump service with strings2
                runCMD($"{currentPath}assets\\dumper.exe -pid {getService("DPS")} -l 4 -nh > {currentPath}assets\\DPS");

                // read dump
                dpsDump = File.ReadAllText("assets\\DPS");

                // scan dump for strings
                foreach (KeyValuePair<string, string> detection in dpsDetections)
                    if (dpsDump.Contains(detection.Key))
                        Console.WriteLine($"  -  {detection.Value} has been detected (Out of instance)");
            }
            catch { Console.WriteLine("error when scanning dps."); Console.ReadLine(); }
        }

        /// <summary>
        /// Create a DnsCache dump using strings2 and search for strings
        /// </summary>
        static void scanDnsCache() {
            try {
                // dump service with strings2
                runCMD($"{currentPath}assets\\dumper.exe -pid {getService("Dnscache")} -l 4 -nh > {currentPath}assets\\DNSCACHE");

                // read dump
                dnsCacheDump = File.ReadAllText("assets\\DNSCACHE");

                // scan dump for strings
                foreach (KeyValuePair<string, string> detection in dnsCacheDetections)
                    if (dnsCacheDump.Contains(detection.Key))
                        Console.WriteLine($"  -  {detection.Value} has been detected (Out of instance)");
            }
            catch { Console.WriteLine("error when scanning dnscache."); Console.ReadLine(); }
        }
    }
}