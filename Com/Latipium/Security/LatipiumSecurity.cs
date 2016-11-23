// LatipiumSecurity.cs
//
// Copyright (c) 2016 Zach Deibert.
// All Rights Reserved.
using System;
using System.Collections.Generic;
using System.Linq;
using System.IO;
using System.Reflection;
using System.Runtime.Remoting;
using System.Security;
using System.Security.Permissions;
using System.Security.Policy;
using System.Text;
using log4net;
using Com.Latipium.Core;

namespace Com.Latipium.Security {
	/// <summary>
	/// The latipium security system interface.
	/// </summary>
	public static class LatipiumSecurity {
		private static StrongName GetStrongName(Assembly asm) {
			AssemblyName name = asm.GetName();
			return new StrongName(new StrongNamePublicKeyBlob(name.GetPublicKey()), name.Name, name.Version);
		}

		private static StrongName GetStrongName(Type type) {
			return GetStrongName(type.Assembly);
		}

		private static StrongName GetStrongName(string file) {
			return GetStrongName(Assembly.LoadFile(Path.GetFullPath(file)));
		}

		private static string FindModule(string name, string framework = "net35") {
			if ( File.Exists(string.Concat(name, ".dll")) ) {
				return string.Concat(name, ".dll");
			} else {
				Version latest = null;
				foreach ( string dir in Directory.GetDirectories(Environment.CurrentDirectory, string.Concat(name, ".*")) ) {
					Version ver = new Version(dir.Substring(name.Length + 1));
					if ( (latest == null || latest < ver) && File.Exists(Path.Combine(Path.Combine(Path.Combine(string.Concat(name, ".", ver.ToString()), "lib"), framework), string.Concat(name, ".dll"))) ) {
						latest = ver;
					}
				}
				if ( latest != null ) {
					return Path.Combine(Path.Combine(Path.Combine(string.Concat(name, ".", latest.ToString()), "lib"), framework), string.Concat(name, ".dll"));
				}
			}
			return null;
		}

		private static void FindTrustedAssemblies(List<StrongName> assemblies, ref string customIO) {
			// This assembly needs to be trusted so it can assert the sandbox when printing exceptions and to load the IO module
			assemblies.Add(GetStrongName(typeof(LatipiumSecurity)));
			// The IO module needs to be trusted so it can do IO
			if ( customIO == null || !File.Exists(customIO) ) {
				customIO = FindModule("Com.Latipium.Defaults.IO");
				assemblies.Add(GetStrongName(customIO));
			} else {
				assemblies.Add(GetStrongName(customIO));
			}
			// log4net needs to be trusted so it can do its logging
			assemblies.Add(GetStrongName(typeof(LogManager)));
		}

		private static void GetPermissions(PermissionSet permissions) {
			string core = Path.GetFullPath(FindModule("Com.Latipium.Core"));
			string log = Path.GetFullPath(FindModule("log4net", "net35-full"));
			permissions.AddPermission(new SecurityPermission(SecurityPermissionFlag.Execution));
			permissions.AddPermission(new FileIOPermission(FileIOPermissionAccess.Read | FileIOPermissionAccess.PathDiscovery, new string[] {
				core,
				log
			}));
		}

		private static void Sandbox(string startMod, string customIO) {
			Evidence evidence = new Evidence();
			AppDomainSetup setup = new AppDomainSetup();
			setup.ApplicationBase = Environment.CurrentDirectory;
			PermissionSet permissions = new PermissionSet(PermissionState.Unrestricted); // TODO Fix permissions
			GetPermissions(permissions);
			List<StrongName> fullTrust = new List<StrongName>();
			FindTrustedAssemblies(fullTrust, ref customIO);
			AppDomain domain = AppDomain.CreateDomain(string.Concat("Latipium sandbox in ", Path.GetFileName(typeof(StartObject).Assembly
				.CodeBase)), evidence, setup, permissions,
				fullTrust.ToArray());
			MethodInfo method = typeof(StartObject).GetMethod("Launch", new Type[] {
				typeof(string),
				typeof(string)
			});
			ObjectHandle handle = Activator.CreateInstanceFrom(domain, typeof(StartObject).Assembly
				.CodeBase,
				typeof(StartObject).FullName);
			try {
				method.Invoke(
					handle.Unwrap(), new object[] {
						startMod,
						customIO
					});
			} catch ( TargetInvocationException ex ) {
				new PermissionSet(PermissionState.Unrestricted).Assert();
				Console.WriteLine(ex);
				CodeAccessPermission.RevertAssert();
			}
		}

		private static void LoadCachedDll(string mod, string pubKey) {
			// Load the dll completely from memory so it can still be opened
			// inside the sandbox
			string path = Path.GetFullPath(FindModule(mod));
			Stream stream = new FileStream(path, FileMode.Open, FileAccess.Read);
			byte[] buffer = new byte[stream.Length];
			stream.Read(buffer, 0, buffer.Length);
			stream.Close();
			stream.Dispose();
			Assembly asm = Assembly.Load(buffer);
			byte[] key = Enumerable.Range(0, pubKey.Length)
				.Where(x => x % 2 == 0)
				.Select(x => Convert.ToByte(pubKey.Substring(x, 2), 16))
				.ToArray();
			if ( !asm.GetName()
				.GetPublicKeyToken()
				.SequenceEqual(key) ) {
				throw new SecurityException("Public key tokens did not match!");
			}
		}

		/// <summary>
		/// Initializes the security sandbox.
		/// </summary>
		/// <param name="startMod">The module to call Start() on inside the sandbox.</param>
		/// <param name="customIO">The path to the custom I/O module, or <c>null</c> to use the default I/O module.</param>
		public static void Initialize(string startMod, string customIO) {
			Console.InputEncoding = Console.OutputEncoding = Encoding.UTF8;
			LoadCachedDll("Com.Latipium.Core", "8532f4db378e684e");
			LoadCachedDll("log4net", "669e0ddf0bb1aa2a");
			Sandbox(startMod, customIO);
		}
	}
}

