#region Copyright (c) 2007 Ryan Williams <drcforbin@gmail.com>
/// <copyright>
/// Copyright (c) 2007 Ryan Williams <drcforbin@gmail.com>
/// 
/// Permission is hereby granted, free of charge, to any person obtaining a copy
/// of this software and associated documentation files (the "Software"), to deal
/// in the Software without restriction, including without limitation the rights
/// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
/// copies of the Software, and to permit persons to whom the Software is
/// furnished to do so, subject to the following conditions:
/// 
/// The above copyright notice and this permission notice shall be included in
/// all copies or substantial portions of the Software.
/// 
/// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
/// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
/// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
/// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
/// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
/// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
/// THE SOFTWARE.
/// </copyright>
#endregion

using System;
using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml;
using System.Diagnostics;

using Mono.Cecil;
using Mono.Cecil.Cil;
using Mono.Security;
using System.Collections;

namespace Obfuscar
{
	class Obfuscator
	{
		Project project;

		ObfuscationMap map = new ObfuscationMap ();

		// Unique names for type and members
		int uniqueTypeNameIndex = 0;
		int uniqueMemberNameIndex = 0;

		/// <summary>
		/// Creates an obfuscator initialized from a project file.
		/// </summary>
		/// <param name="projfile">Path to project file.</param>
		public Obfuscator (string projfile)
		{
			// open XmlTextReader over xml string stream
			XmlReaderSettings settings = GetReaderSettings ();

			try {
				using(XmlReader reader = XmlTextReader.Create (System.IO.File.OpenRead (projfile), settings))
					LoadFromReader (reader);
			}
			catch(System.IO.IOException e) {
				throw new ApplicationException ("Unable to read specified project file:  " + projfile, e);
			}
		}

		/// <summary>
		/// Creates an obfuscator initialized from a project file.
		/// </summary>
		/// <param name="projfile">Reader for project file.</param>
		public Obfuscator (XmlReader reader)
		{
			LoadFromReader (reader);
		}

		public static Obfuscator CreateFromXml (string xml)
		{
			// open XmlTextReader over xml string stream
			XmlReaderSettings settings = GetReaderSettings ();

			using(XmlReader reader = XmlTextReader.Create (new System.IO.StringReader (xml), settings))
				return new Obfuscar.Obfuscator (reader);
		}

		static XmlReaderSettings GetReaderSettings ()
		{
			XmlReaderSettings settings = new XmlReaderSettings ();
			settings.IgnoreProcessingInstructions = true;
			settings.IgnoreWhitespace = true;
			settings.XmlResolver = null;
			settings.ProhibitDtd = false;
			return settings;
		}

		void LoadFromReader (XmlReader reader)
		{
			project = Project.FromXml (reader);

			// make sure everything looks good
			project.CheckSettings ();
            NameMaker.UseUnicodeChars = project.Settings.UseUnicodeNames;

			Console.Write ("Loading assemblies...");
			project.LoadAssemblies ();
		}

		/// <summary>
		/// Saves changes made to assemblies to the output path.
		/// </summary>
		public void SaveAssemblies ()
		{
			string outPath = project.Settings.OutPath;

			// save the modified assemblies
			foreach(AssemblyInfo info in project) {
				string outName = System.IO.Path.Combine (outPath,
					System.IO.Path.GetFileName (info.Filename));

				AssemblyFactory.SaveAssembly (info.Definition, outName);
				if(info.Definition.Name.HasPublicKey) {
					StrongName sn = new StrongName (project.KeyValue);
					sn.Sign (outName);
				}
			}
		}

		/// <summary>
		/// Saves the name mapping to the output path.
		/// </summary>
		public void SaveMapping ()
		{
			string filename = project.Settings.XmlMapping ?
				"Mapping.xml" : "Mapping.txt";

			string logPath = System.IO.Path.Combine (project.Settings.OutPath, filename);

            if (!String.IsNullOrEmpty(project.Settings.LogFilePath))
                logPath = project.Settings.LogFilePath;

			using(System.IO.TextWriter file = System.IO.File.CreateText (logPath))
				SaveMapping (file);
		}

		/// <summary>
		/// Saves the name mapping to a text writer.
		/// </summary>
		public void SaveMapping (System.IO.TextWriter writer)
		{
			IMapWriter mapWriter = project.Settings.XmlMapping ?
				(IMapWriter)new XmlMapWriter (writer) : (IMapWriter)new TextMapWriter (writer);

			mapWriter.WriteMap (map);
		}

		/// <summary>
		/// Returns the obfuscation map for the project.
		/// </summary>
		public ObfuscationMap Mapping
		{
			get { return map; }
		}

		/// <summary>
		/// Renames fields in the project.
		/// </summary>
		public void RenameFields ()
		{
			Dictionary<string, NameGroup> nameGroups = new Dictionary<string, NameGroup> ();

			foreach(AssemblyInfo info in project) {
				AssemblyDefinition library = info.Definition;

				// loop through the types
				foreach(TypeDefinition type in library.MainModule.Types) {
					if(type.FullName == "<Module>")
						continue;

					TypeKey typeKey = new TypeKey (type);

					if(ShouldRename (type)) {
						nameGroups.Clear ();

						// rename field, grouping according to signature
						bool isenum = type.IsEnum;

						foreach(FieldDefinition field in type.Fields) {
							string sig = field.FieldType.FullName;
							FieldKey fieldKey = new FieldKey (typeKey, sig, field.Name);

							NameGroup nameGroup = GetNameGroup (nameGroups, "");

							if(field.IsRuntimeSpecialName && field.Name == "value__") {
								map.UpdateField (fieldKey, ObfuscationStatus.Skipped, "filtered");
								nameGroup.Add (fieldKey.Name);
							}
							else

								// skip filtered fields
								if(info.ShouldSkip (fieldKey) || !ShouldObfuscate(field, type)) {
									map.UpdateField (fieldKey, ObfuscationStatus.Skipped, "filtered");
									nameGroup.Add (fieldKey.Name);
								}
								else {
									string newName;
									if(project.Settings.ReuseNames)
										newName = nameGroup.GetNext ();
									else
										newName = NameMaker.UniqueName (uniqueMemberNameIndex++);

									RenameField (info, fieldKey, field, newName);

									nameGroup.Add (newName);
								}
						}
					}
				}
			}
		}

		void RenameField (AssemblyInfo info, FieldKey fieldKey, FieldDefinition field, string newName)
		{
			// find references, rename them, then rename the field itself

			foreach(AssemblyInfo reference in info.ReferencedBy) {
				for(int i = 0; i < reference.UnrenamedReferences.Count; ) {
					FieldReference member = reference.UnrenamedReferences [i] as FieldReference;
					if(member != null) {
						if(fieldKey.Matches (member)) {
							member.Name = newName;
							reference.UnrenamedReferences.RemoveAt (i);

							// since we removed one, continue without the increment
							continue;
						}
					}

					i++;
				}
			}

			field.Name = newName;

			map.UpdateField (fieldKey, ObfuscationStatus.Renamed, newName);
		}

		/// <summary>
		/// Renames constructor, method, and generic parameters.
		/// </summary>
		public void RenameParams ()
		{
			int index;

			foreach(AssemblyInfo info in project) {
				AssemblyDefinition library = info.Definition;

				// loop through the types
				foreach(TypeDefinition type in library.MainModule.Types) {
					if(type.FullName == "<Module>")
						continue;

					if(ShouldRename (type)) {
						if(info.ShouldSkip (new TypeKey (type)))
							continue;
						System.Reflection.ObfuscationAttribute at = GetObfuscationAttribute (type);
						if(at != null && at.Exclude) continue;

						// rename the constructor parameters
						foreach(MethodDefinition method in type.Constructors)
							RenameParams (method);

						// rename the method parameters
						foreach(MethodDefinition method in type.Methods)
							RenameParams (method);

						// rename the class parameters
						index = 0;
						foreach(GenericParameter param in type.GenericParameters)
							param.Name = NameMaker.UniqueName (index++);
					}
				}
			}
		}

		void RenameParams (MethodDefinition method)
		{
			int index = 0;
			if(!ShouldObfuscate (method, method.DeclaringType)) return;
			foreach(ParameterReference param in method.Parameters)
				param.Name = NameMaker.UniqueName (index++);

			index = 0;
			foreach(GenericParameter param in method.GenericParameters)
				param.Name = NameMaker.UniqueName (index++);
		}

		bool ShouldRename (TypeDefinition type)
		{
			const string ctor = "System.Void Obfuscar.ObfuscateAttribute::.ctor()";

			bool should = !project.Settings.MarkedOnly;

			foreach(CustomAttribute attr in type.CustomAttributes) {
				if(attr.Constructor.ToString () == ctor) {
					// determine the result from the property, default to true if missing
					object obj = attr.Properties ["ShouldObfuscate"];
					if(obj != null)
						should = (bool)obj;
					else
						should = true;

					break;
				}
			}

			return should;
		}

		/// <summary>
		/// Renames types and resources in the project.
		/// </summary>
		public void RenameTypes ()
		{
			foreach(AssemblyInfo info in project) {
				AssemblyDefinition library = info.Definition;

				// make a list of the resources that can be renamed
				List<Resource> resources = new List<Resource> (library.MainModule.Resources.Count);
				foreach(Resource res in library.MainModule.Resources)
					resources.Add (res);

				// Save the original names of all types because parent (declaring) types of nested types may be already renamed.
				// The names are used for the mappings file.
				Dictionary<TypeDefinition, TypeKey> unrenamedTypeKeys = new Dictionary<TypeDefinition, TypeKey> ();
				foreach(TypeDefinition type in library.MainModule.Types)
					unrenamedTypeKeys.Add (type, new TypeKey (type));

				// loop through the types
				int typeIndex = 0;
				foreach(TypeDefinition type in library.MainModule.Types) {
					if(type.FullName == "<Module>")
						continue;
					TypeKey oldTypeKey = new TypeKey (type);
					TypeKey unrenamedTypeKey = unrenamedTypeKeys [type];
					string fullName = type.FullName;

					System.Reflection.ObfuscationAttribute atr = GetObfuscationAttribute (type);
					if(ShouldRename (type) && (atr == null || !atr.Exclude)) {
						if(!info.ShouldSkip (unrenamedTypeKey)) {			
							string name;
							string ns;
							if(project.Settings.ReuseNames) {
								name = NameMaker.UniqueTypeName (typeIndex);
								ns = NameMaker.UniqueNamespace (typeIndex);
							}
							else {
								name = NameMaker.UniqueName (uniqueTypeNameIndex);
								ns = NameMaker.UniqueNamespace (uniqueTypeNameIndex);
								uniqueTypeNameIndex++;
							}

							if(type.GenericParameters.Count > 0)
								name += '`' + type.GenericParameters.Count.ToString ();
							if(type.DeclaringType != null) // Nested types do not have namespaces
								ns = "";

							TypeKey newTypeKey = new TypeKey (info.Name, ns, name);
							typeIndex++;

							// go through the list of renamed types and try to rename resources
							for(int i = 0; i < resources.Count; ) {
								Resource res = resources [i];
								string resName = res.Name;

								if(resName.StartsWith (fullName + ".")) {
									string suffix = resName.Substring (fullName.Length);
									string newName = newTypeKey.Fullname + suffix;

									res.Name = newName;
									resources.RemoveAt (i);

									map.AddResource (resName, ObfuscationStatus.Renamed, newName);
								}
								else
									i++;
							}

							RenameType (info, type, oldTypeKey, newTypeKey, unrenamedTypeKey);
						}
						else {
							map.UpdateType (oldTypeKey, ObfuscationStatus.Skipped, "filtered");

							// go through the list of resources, remove ones that would be renamed
							for(int i = 0; i < resources.Count; ) {
								Resource res = resources [i];
								string resName = res.Name;

								if(resName.StartsWith (fullName + ".")) {
									resources.RemoveAt (i);
									map.AddResource (resName, ObfuscationStatus.Skipped, "filtered");
								}
								else
									i++;
							}
						}
					}
					else {
						map.UpdateType (oldTypeKey, ObfuscationStatus.Skipped, "marked");

						// go through the list of resources, remove ones that would be renamed
						for(int i = 0; i < resources.Count; ) {
							Resource res = resources [i];
							string resName = res.Name;

							if(resName.StartsWith (fullName + ".")) {
								resources.RemoveAt (i);
								map.AddResource (resName, ObfuscationStatus.Skipped, "marked");
							}
							else
								i++;
						}
					}
				}

				foreach(Resource res in resources)
					map.AddResource (res.Name, ObfuscationStatus.Skipped, "no clear new name");
			}
		}

		void RenameType (AssemblyInfo info, TypeDefinition type, TypeKey oldTypeKey, TypeKey newTypeKey, TypeKey unrenamedTypeKey)
		{
			// find references, rename them, then rename the type itself

			foreach(AssemblyInfo reference in info.ReferencedBy) {
				for(int i = 0; i < reference.UnrenamedTypeReferences.Count; ) {
					TypeReference refType = reference.UnrenamedTypeReferences [i];

					// check whether the referencing module references this type...if so,
					// rename the reference
					if(oldTypeKey.Matches (refType)) {
						refType.Namespace = newTypeKey.Namespace;
						refType.Name = newTypeKey.Name;

						reference.UnrenamedTypeReferences.RemoveAt (i);

						// since we removed one, continue without the increment
						continue;
					}

					i++;
				}
			}

			type.Namespace = newTypeKey.Namespace;
			type.Name = newTypeKey.Name;

			map.UpdateType (unrenamedTypeKey, ObfuscationStatus.Renamed, string.Format ("[{0}]{1}", newTypeKey.Scope, type.ToString ()));
		}

		Dictionary<ParamSig, NameGroup> GetSigNames (Dictionary<TypeKey, Dictionary<ParamSig, NameGroup>> baseSigNames,
			TypeKey typeKey)
		{
			Dictionary<ParamSig, NameGroup> sigNames;
			if(!baseSigNames.TryGetValue (typeKey, out sigNames)) {
				sigNames = new Dictionary<ParamSig, NameGroup> ();
				baseSigNames [typeKey] = sigNames;
			}
			return sigNames;
		}

		NameGroup GetNameGroup (Dictionary<TypeKey, Dictionary<ParamSig, NameGroup>> baseSigNames,
			TypeKey typeKey, ParamSig sig)
		{
			return GetNameGroup (GetSigNames (baseSigNames, typeKey), sig);
		}


		NameGroup GetNameGroup<KeyType> (Dictionary<KeyType, NameGroup> sigNames, KeyType sig)
		{
			NameGroup nameGroup;
			if(!sigNames.TryGetValue (sig, out nameGroup)) {
				nameGroup = new NameGroup ();
				sigNames [sig] = nameGroup;
			}
			return nameGroup;
		}

		public void RenameProperties ()
		{
			// do nothing if it was requested not to rename
			if(!project.Settings.RenameProperties)
				return;

			foreach(AssemblyInfo info in project) {
				AssemblyDefinition library = info.Definition;

				foreach(TypeDefinition type in library.MainModule.Types) {
					if(type.FullName == "<Module>")
						continue;

					TypeKey typeKey = new TypeKey (type);

					if(ShouldRename (type)) {
						int index = 0;
						List<PropertyDefinition> propsToDrop = new List<PropertyDefinition> ();
						foreach(PropertyDefinition prop in type.Properties) {
							PropertyKey propKey = new PropertyKey (typeKey, prop);
							ObfuscatedThing m = map.GetProperty (propKey);

							// skip runtime special properties
							if(prop.IsRuntimeSpecialName) {
								m.Update (ObfuscationStatus.Skipped, "runtime special");
								continue;
							}

							// skip filtered props
							if(info.ShouldSkip (propKey) || !ShouldObfuscate(prop, type) ) {
								m.Update (ObfuscationStatus.Skipped, "filtered");

								// make sure get/set get skipped too
								if(prop.GetMethod != null)
									info.ForceSkip (new MethodKey (prop.GetMethod));
								if(prop.SetMethod != null)
									info.ForceSkip (new MethodKey (prop.SetMethod));

								continue;
							}
							// do not rename properties of custom attribute types which have a public setter method
							else if(type.BaseType != null && type.BaseType.Name.EndsWith ("Attribute") && prop.SetMethod != null && (prop.SetMethod.Attributes & MethodAttributes.Public) != 0) {
								m.Update (ObfuscationStatus.Skipped, "public setter of a custom attribute");
								// no problem when the getter or setter methods are renamed by RenameMethods()
							}
							// If a property has custom attributes we don't remove the property but rename it instead.
							else if(prop.CustomAttributes.Count > 0) {
								string newName;
								if(project.Settings.ReuseNames)
									newName = NameMaker.UniqueName (index++);
								else
									newName = NameMaker.UniqueName (uniqueMemberNameIndex++);
								RenameProperty (info, propKey, prop, newName);
							}
							else {
								// add to to collection for removal
								propsToDrop.Add (prop);
							}
						}

						foreach(PropertyDefinition prop in propsToDrop) {
							PropertyKey propKey = new PropertyKey (typeKey, prop);
							ObfuscatedThing m = map.GetProperty (propKey);

							m.Update (ObfuscationStatus.Renamed, "dropped");
							type.Properties.Remove (prop);
						}
					}
				}
			}
		}

		void RenameProperty (AssemblyInfo info, PropertyKey propertyKey, PropertyDefinition property, string newName)
		{
			// find references, rename them, then rename the property itself

			foreach(AssemblyInfo reference in info.ReferencedBy) {
				for(int i = 0; i < reference.UnrenamedReferences.Count; ) {
					PropertyReference member = reference.UnrenamedReferences [i] as PropertyReference;
					if(member != null) {
						if(propertyKey.Matches (member)) {
							member.Name = newName;
							reference.UnrenamedReferences.RemoveAt (i);

							// since we removed one, continue without the increment
							continue;
						}
					}

					i++;
				}
			}

			property.Name = newName;

			map.UpdateProperty (propertyKey, ObfuscationStatus.Renamed, newName);
		}

		public void RenameEvents ()
		{
			// do nothing if it was requested not to rename
			if(!project.Settings.RenameEvents)
				return;

			foreach(AssemblyInfo info in project) {
				AssemblyDefinition library = info.Definition;

				foreach(TypeDefinition type in library.MainModule.Types) {
					if(type.FullName == "<Module>")
						continue;

					TypeKey typeKey = new TypeKey (type);

					if(ShouldRename (type)) {
						List<EventDefinition> evtsToDrop = new List<EventDefinition> ();
						foreach(EventDefinition evt in type.Events) {
							EventKey evtKey = new EventKey (typeKey, evt);
							ObfuscatedThing m = map.GetEvent (evtKey);

							// skip runtime special events
							if(evt.IsRuntimeSpecialName) {
								m.Update (ObfuscationStatus.Skipped, "runtime special");
								continue;
							}

							// skip filtered events
							if(info.ShouldSkip (evtKey) || !ShouldObfuscate(evt, type)) {
								m.Update (ObfuscationStatus.Skipped, "filtered");

								// make sure add/remove get skipped too
								info.ForceSkip (new MethodKey (evt.AddMethod));
								info.ForceSkip (new MethodKey (evt.RemoveMethod));

								continue;
							}

							// add to to collection for removal
							evtsToDrop.Add (evt);
						}

						foreach(EventDefinition evt in evtsToDrop) {
							EventKey evtKey = new EventKey (typeKey, evt);
							ObfuscatedThing m = map.GetEvent (evtKey);

							m.Update (ObfuscationStatus.Renamed, "dropped");
							type.Events.Remove (evt);
						}
					}
				}
			}
		}

		public void RenameMethods ()
		{
			Dictionary<TypeKey, Dictionary<ParamSig, NameGroup>> baseSigNames =
				new Dictionary<TypeKey, Dictionary<ParamSig, NameGroup>> ();

			foreach(AssemblyInfo info in project) {
				AssemblyDefinition library = info.Definition;

				foreach(TypeDefinition type in library.MainModule.Types) {
					if(type.FullName == "<Module>")
						continue;

					TypeKey typeKey = new TypeKey (type);

					Dictionary<ParamSig, NameGroup> sigNames = GetSigNames (baseSigNames, typeKey);

					// first pass.  mark grouped virtual methods to be renamed, and mark some things
					// to be skipped as neccessary
					foreach(MethodDefinition method in type.Methods) {
						string skiprename = null;
						if(!ShouldRename (type))
							skiprename = "Obfuscar.ObfuscateAttribute found on type.";

						MethodKey methodKey = new MethodKey (typeKey, method);
						ObfuscatedThing m = map.GetMethod (methodKey);

						// skip runtime methods
						if(method.IsRuntime)
							skiprename = "runtime method";

						// skip filtered methods
						if(info.ShouldSkip (methodKey) || !ShouldObfuscate(method, type))
							skiprename = "filtered";

						// update status for skipped non-virtual methods immediately...status for
						// skipped virtual methods gets updated in RenameVirtualMethod
						if(!method.IsVirtual) {
							if(skiprename != null)
								m.Update (ObfuscationStatus.Skipped, skiprename);
							continue;
						}

						if(method.IsSpecialName) {
							switch(method.SemanticsAttributes) {
								case MethodSemanticsAttributes.Getter:
								case MethodSemanticsAttributes.Setter:
									if(!project.Settings.RenameProperties)
										skiprename = "skipping properties";
									break;
								case MethodSemanticsAttributes.AddOn:
								case MethodSemanticsAttributes.RemoveOn:
									if(!project.Settings.RenameEvents)
										skiprename = "skipping events";
									break;
								default:
									skiprename = "virtual and special name";
									break;
							}
						}

						// if we need to skip the method or we don't yet have a name planned for a method, rename it
						if((skiprename != null && m.Status != ObfuscationStatus.Skipped) ||
							m.Status == ObfuscationStatus.Unknown)
							RenameVirtualMethod (info, baseSigNames, sigNames, methodKey, method, skiprename);
					}

					// update name groups, so new names don't step on inherited ones
					foreach(TypeKey baseType in project.InheritMap.GetBaseTypes (typeKey)) {
						Dictionary<ParamSig, NameGroup> baseNames = GetSigNames (baseSigNames, baseType);
						foreach(KeyValuePair<ParamSig, NameGroup> pair in baseNames) {
							NameGroup nameGroup = GetNameGroup (sigNames, pair.Key);
							nameGroup.AddAll (pair.Value);
						}
					}
				}


				foreach(TypeDefinition type in library.MainModule.Types) {
					if(type.FullName == "<Module>")
						continue;

					TypeKey typeKey = new TypeKey (type);

					Dictionary<ParamSig, NameGroup> sigNames = GetSigNames (baseSigNames, typeKey);
					// second pass...marked virtuals and anything not skipped get renamed
					foreach(MethodDefinition method in type.Methods) {
						MethodKey methodKey = new MethodKey (typeKey, method);
						ObfuscatedThing m = map.GetMethod (methodKey);

						// if we already decided to skip it, leave it alone
						if(m.Status == ObfuscationStatus.Skipped)
							continue;

						if(method.IsSpecialName) {
							switch(method.SemanticsAttributes) {
								case MethodSemanticsAttributes.Getter:
								case MethodSemanticsAttributes.Setter:
									if(project.Settings.RenameProperties) {
										RenameMethod (info, sigNames, methodKey, method);
										method.SemanticsAttributes = 0;
									}
									else
										m.Update (ObfuscationStatus.Skipped, "skipping properties");
									break;
								case MethodSemanticsAttributes.AddOn:
								case MethodSemanticsAttributes.RemoveOn:
									if(project.Settings.RenameEvents) {
										RenameMethod (info, sigNames, methodKey, method);
										method.SemanticsAttributes = 0;
									}
									else
										m.Update (ObfuscationStatus.Skipped, "skipping events");
									break;
								default:
									m.Update (ObfuscationStatus.Skipped, "special name");
									break;
							}
						}
						else
							RenameMethod (info, sigNames, methodKey, method);
					}
				}
			}
		}

		void RenameVirtualMethod (AssemblyInfo info, Dictionary<TypeKey, Dictionary<ParamSig, NameGroup>> baseSigNames,
			Dictionary<ParamSig, NameGroup> sigNames, MethodKey methodKey, MethodDefinition method, string skipRename)
		{
			// if method is in a group, look for group key
			MethodGroup group = project.InheritMap.GetMethodGroup (methodKey);
			if(group != null) {
				string groupName = group.Name;
				if(groupName == null) {
					// group is not yet named

					// counts are grouping according to signature
					ParamSig sig = new ParamSig (method);

					// get name groups for classes in the group
					NameGroup [] nameGroups = GetNameGroups (baseSigNames, group.Methods, sig);

					if(group.External)
						skipRename = "external base class or interface";
					if(skipRename != null) {
						// for an external group, we can't rename.  just use the method 
						// name as group name
						groupName = method.Name;
					}
					else {
						// for an internal group, get next unused name
						groupName = NameGroup.GetNext (nameGroups);
					}

					group.Name = groupName;

					// set up methods to be renamed
					foreach(MethodKey m in group.Methods)
						if(skipRename == null)
							map.UpdateMethod (m, ObfuscationStatus.WillRename, groupName);
						else
							map.UpdateMethod (m, ObfuscationStatus.Skipped, skipRename);

					// make sure the classes' name groups are updated
					for(int i = 0; i < nameGroups.Length; i++)
						nameGroups [i].Add (groupName);
				}
				else if(skipRename != null) {
					// group is named, so we need to un-name it

					Debug.Assert (!group.External,
						"Group's external flag should have been handled when the group was created, " +
						"and all methods in the group should already be marked skipped.");

					// counts are grouping according to signature
					ParamSig sig = new ParamSig (method);

					// get name groups for classes in the group
					NameGroup [] nameGroups = GetNameGroups (baseSigNames, group.Methods, sig);

					// make sure to remove the old group name from the classes' name groups
					for(int i = 0; i < nameGroups.Length; i++)
						nameGroups [i].Remove (groupName);

					// since this method has to be skipped, we need to use the method 
					// name as new group name
					groupName = method.Name;
					group.Name = groupName;

					// set up methods to be renamed
					foreach(MethodKey m in group.Methods)
						map.UpdateMethod (m, ObfuscationStatus.Skipped, skipRename);

					// make sure the classes' name groups are updated
					for(int i = 0; i < nameGroups.Length; i++)
						nameGroups [i].Add (groupName);
				}
				else {
					ObfuscatedThing m = map.GetMethod (methodKey);
					Debug.Assert (m.Status == ObfuscationStatus.Skipped ||
						((m.Status == ObfuscationStatus.WillRename || m.Status == ObfuscationStatus.Renamed) &&
						m.StatusText == groupName),
						"If the method isn't skipped, and the group already has a name...method should have one too.");
				}
			}
			else if(skipRename != null)
				map.UpdateMethod (methodKey, ObfuscationStatus.Skipped, skipRename);
		}

		NameGroup [] GetNameGroups (Dictionary<TypeKey, Dictionary<ParamSig, NameGroup>> baseSigNames,
			IEnumerable<MethodKey> methodKeys, ParamSig sig)
		{
			// build unique set of classes in group
			HashSet<TypeKey> typeKeys = new HashSet<TypeKey> ();
			foreach(MethodKey methodKey in methodKeys)
				typeKeys.Add (methodKey.TypeKey);

			// build list of namegroups
			NameGroup [] nameGroups = new NameGroup [typeKeys.Count];

			int i = 0;
			foreach(TypeKey typeKey in typeKeys) {
				NameGroup nameGroup = GetNameGroup (baseSigNames, typeKey, sig);

				nameGroups [i++] = nameGroup;
			}

			return nameGroups;
		}

		string GetNewMethodName (Dictionary<ParamSig, NameGroup> sigNames, MethodKey methodKey, MethodDefinition method)
		{
			ObfuscatedThing t = map.GetMethod (methodKey);

			// if it already has a name, return it
			if(t.Status == ObfuscationStatus.Renamed ||
				t.Status == ObfuscationStatus.WillRename)
				return t.StatusText;

			// don't mess with methods we decided to skip
			if(t.Status == ObfuscationStatus.Skipped)
				return null;

			// counts are grouping according to signature
			ParamSig sig = new ParamSig (method);

			NameGroup nameGroup = GetNameGroup (sigNames, sig);

			string newName = nameGroup.GetNext ();

			// got a new name for the method
			t.Status = ObfuscationStatus.WillRename;
			t.StatusText = newName;

			// make sure the name groups is updated
			nameGroup.Add (newName);

			return newName;
		}

		void RenameMethod (AssemblyInfo info, Dictionary<ParamSig, NameGroup> sigNames, MethodKey methodKey, MethodDefinition method)
		{
			string newName = GetNewMethodName (sigNames, methodKey, method);

			RenameMethod (info, methodKey, method, newName);
		}

		void RenameMethod (AssemblyInfo info, MethodKey methodKey, MethodDefinition method, string newName)
		{
			// find references, rename them, then rename the method itself
			foreach(AssemblyInfo reference in info.ReferencedBy) {
				for(int i = 0; i < reference.UnrenamedReferences.Count; ) {
					MethodReference member = reference.UnrenamedReferences [i] as MethodReference;
					if(member != null) {
						if(methodKey.Matches (member)) {
							member.Name = newName;
							reference.UnrenamedReferences.RemoveAt (i);

							// since we removed one, continue without the increment
							continue;
						}
					}

					i++;
				}
			}

			method.Name = newName;

			map.UpdateMethod (methodKey, ObfuscationStatus.Renamed, newName);
		}

		private bool ShouldObfuscate (ICustomAttributeProvider member, TypeDefinition def)
		{
			System.Reflection.ObfuscationAttribute at = GetObfuscationAttribute (member);
			if(at != null) {
				if(at.Exclude) return false;
			}
			at = GetObfuscationAttribute (def);
			if(at != null) {
				if(at.Exclude && at.ApplyToMembers)
					return false;
			}
			return true;
		}

		private System.Reflection.ObfuscationAttribute GetObfuscationAttribute (ICustomAttributeProvider attributes)
		{
			IAnnotationProvider ap = attributes as IAnnotationProvider;
			if(ap != null && ap.Annotations ["Obfuscation"] != null)
				return (System.Reflection.ObfuscationAttribute)ap.Annotations ["Obfuscation"];
			if (attributes == null || !attributes.HasCustomAttributes) return null;
			for (int i = 0; i < attributes.CustomAttributes.Count; i++)
			{
				CustomAttribute at = attributes.CustomAttributes [i];
				if(at.Constructor.DeclaringType.FullName == "System.Reflection.ObfuscationAttribute") {
					at.Resolve ();
					System.Reflection.ObfuscationAttribute res = new System.Reflection.ObfuscationAttribute ();
					if(at.Properties ["ApplyToMembers"] is bool)
						res.ApplyToMembers = (bool)at.Properties ["ApplyToMembers"];
					if(at.Properties ["Exclude"] is bool)
						res.Exclude = (bool)at.Properties ["Exclude"];
					if(at.Properties ["StripAfterObfuscation"] is bool)
						res.StripAfterObfuscation = (bool)at.Properties ["StripAfterObfuscation"];
					if(at.Properties ["Feature"] is string)
						res.Feature = (string)at.Properties ["Feature"];

					if(res.StripAfterObfuscation)
						attributes.CustomAttributes.RemoveAt (i);
					if(ap != null)
						ap.Annotations ["Obfuscation"] = res;
					return res;
				}
			}
			return null;
		}

		static void ResolveCustomAttributes (ICustomAttributeProvider ap)
		{
			for(int i = 0; i < ap.CustomAttributes.Count; i++)
				if (!ap.CustomAttributes [i].Resolved) ap.CustomAttributes [i].Resolve ();
		}

		class ResolveCustomAttributeVisitor : BaseCustomAttributeVisitor
		{
			public override void VisitCustomAttribute (CustomAttribute customAttr)
			{
				customAttr.Resolve ();
			}
		}
		/*
		class FixCustomAttributeVisitor : BaseCustomAttributeVisitor
		{
			Obfuscator parent;
			AssemblyInfo thisAssembly;
			public FixCustomAttributeVisitor(Obfuscator parent) {
				this.parent = parent;
			}

			public AssemblyInfo ThisAssembly { get { return thisAssembly; } set { thisAssembly = value; } }
			private List<DictionaryEntry> fixList = new List<DictionaryEntry>();

			public override void VisitCustomAttribute (CustomAttribute customAttr)
			{
				for(int i = 0; customAttr.ConstructorParameters.Count; i++) {
					customAttr.ConstructorParameters [i] = FixType (customAttr.ConstructorParameters [i], customAttr.Constructor.Parameters[i].ParameterType);
				}
				fixList.Clear ();
				foreach(System.Collections.DictionaryEntry et in customAttr.Fields) {
					object o = FixType (et.Value, customAttr.GetFieldType (et.Key));
					if(et.Value != o) {
						fixList.Add (new DictionaryEntry (et.Key, o));
					}
				}
				foreach(DictionaryEntry et in fixList)
					customAttr.Fields [et.Key] = et.Value;

				fixList.Clear ();
				foreach(System.Collections.DictionaryEntry et in customAttr.Properties) {
					object o = FixType (et.Value, customAttr.GetPropertyType(et.Key));
					if(et.Value != o) {
						fixList.Add (new DictionaryEntry (et.Key, o));
					}
				}
				foreach(DictionaryEntry et in fixList)
					customAttr.Properties [et.Key] = et.Value;
			}

			private object FixType (object type, TypeReference valuetype)
			{
				if(valuetype.FullName == "System.Type") {
				}
				return type;
			}
			
		}
			*/
		class BaseCustomAttributeVisitor : BaseReflectionVisitor
		{

			public override void VisitConstructorCollection (ConstructorCollection ctors)
			{
				if(ctors == null) return;
				for(int i = 0; i < ctors.Count; i++)
					ctors [i].Accept (this);
			}

			
			public override void VisitCustomAttributeCollection (CustomAttributeCollection customAttrs)
			{
				if(customAttrs == null) return;
				for(int i = 0; i < customAttrs.Count; i++)
					customAttrs [i].Accept (this);
			}

			public override void VisitEventDefinitionCollection (EventDefinitionCollection events)
			{
				for(int i = 0; i < events.Count; i++)
					events [i].Accept (this);
			}


			public override void VisitExternTypeCollection (ExternTypeCollection externs)
			{
				for(int i = 0; i < externs.Count; i++)
					externs [i].Accept (this);
			}

			public override void VisitFieldDefinitionCollection (FieldDefinitionCollection fields)
			{
				for(int i = 0; i < fields.Count; i++)
					fields [i].Accept (this);
			}

			public override void VisitGenericParameterCollection (GenericParameterCollection genparams)
			{
				if(genparams == null) return;
				for(int i = 0; i < genparams.Count; i++)
					genparams [i].Accept (this);
			}

			public override void VisitInterfaceCollection (InterfaceCollection interfaces)
			{
				for(int i = 0; i < interfaces.Count; i++)
					interfaces [i].Accept (this);
			}

			public override void VisitMemberReferenceCollection (MemberReferenceCollection members)
			{
				for(int i = 0; i < members.Count; i++)
					members [i].Accept (this);
			}

			public override void VisitMethodDefinitionCollection (MethodDefinitionCollection methods)
			{
				for(int i = 0; i < methods.Count; i++)
					methods [i].Accept (this);
			}

			public override void VisitNestedTypeCollection (NestedTypeCollection nestedTypes)
			{
				for(int i = 0; i < nestedTypes.Count; i++)
					nestedTypes [i].Accept (this);
			}

			public override void VisitOverrideCollection (OverrideCollection meth)
			{
				if(meth == null) return;
				for(int i = 0; i < meth.Count; i++)
					meth [i].Accept (this);
			}

			public override void VisitParameterDefinitionCollection (ParameterDefinitionCollection parameters)
			{
				for(int i = 0; i < parameters.Count; i++)
					parameters [i].Accept (this);
			}

			public override void VisitPropertyDefinitionCollection (PropertyDefinitionCollection properties)
			{
				for(int i = 0; i < properties.Count; i++)
					properties [i].Accept (this);
			}

			public override void VisitSecurityDeclarationCollection (SecurityDeclarationCollection secDecls)
			{
				if(secDecls == null) return;
				for(int i = 0; i < secDecls.Count; i++) {
					if (secDecls [i] != null)
						secDecls [i].Accept (this);
				}
			}

			public override void VisitTypeDefinitionCollection (TypeDefinitionCollection types)
			{
				for(int i = 0; i < types.Count; i++)
					types [i].Accept (this);
			}

			public override void VisitTypeReferenceCollection (TypeReferenceCollection refs)
			{
				for(int i = 0; i < refs.Count; i++)
					refs [i].Accept (this);
			}
		}

		internal void ResolveCustomAttributes ()
		{
			/*ResolveCustomAttributeVisitor visitor = new ResolveCustomAttributeVisitor ();
			foreach(AssemblyInfo info in project) {
				ResolveCustomAttributes (info.Definition);
				foreach(ModuleDefinition def in info.Definition.Modules) {
					ResolveCustomAttributes (def);
					def.Accept (visitor);
				}
			}*/
		}
		/*
		internal void FixCustomAttributeTypeParameters ()
		{
			FixCustomAttributeVisitor visitor = new FixCustomAttributeVisitor ();
			foreach(AssemblyInfo info in project) {
				ResolveCustomAttributes (info.Definition);
				foreach(ModuleDefinition def in info.Definition.Modules) {
					ResolveCustomAttributes (def);
					def.Accept (visitor);
				}
			}
		}*/
	}
}
