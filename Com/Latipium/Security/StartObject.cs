// StartObject.cs
//
// Copyright (c) 2016 Zach Deibert.
// All Rights Reserved.
using System;
using System.IO;
using System.Reflection;
using System.Security;
using System.Security.Permissions;
using log4net;
using log4net.Config;
using Com.Latipium.Core;
using Com.Latipium.Core.Loading;

namespace Com.Latipium.Security {
	internal class StartObject : MarshalByRefObject {
		/// <summary>
		/// Launches Latipium once inside the sandbox.
		/// </summary>
		/// <param name="startMod">The module to call Start() on inside the sandbox.</param>
		/// <param name="customIO">The path to the custom I/O module, or <c>null</c> to use the default I/O module.</param>
        /// <param name="logConfig">The path to the configuration file for the logger</param>
        public void Launch(string startMod, string customIO, string logConfig) {
            new FileIOPermission(PermissionState.Unrestricted).Assert();
            XmlConfigurator.Configure(new FileInfo(logConfig));
            ILog Log = LogManager.GetLogger(typeof(StartObject));
            Log.Info("Sandbox started!");
			customIO = Path.GetFullPath(customIO);
			Assembly asm = Assembly.LoadFile(customIO);
			CodeAccessPermission.RevertAssert();
			AssemblyLoader.Init(asm);
			LatipiumModule mod = ModuleFactory.FindModule(startMod);
			if ( mod == null ) {
				Log.Error("Unable to find startup module.");
			} else {
				mod.InvokeProcedure("Start");
			}
		}
	}
}

