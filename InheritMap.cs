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
using System.Diagnostics;
using System.Collections.Generic;
using System.Text;

using Mono.Cecil;
using Mono.Cecil.Cil;

namespace Obfuscar
{
	class MethodGroup
	{
		private readonly HashSet<MethodKey> methods = new HashSet<MethodKey>( );

		private string name = null;
		private bool external = false;

		public HashSet<MethodKey> Methods
		{
			get { return methods; }
		}

		public string Name
		{
			get { return name; }
			set { name = value; }
		}

		public bool External
		{
			get { return external; }
			set { external = value; }
		}

        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append(Name);
            if (external)
                sb.Append("(ext)");
            else
                sb.Append("(int)");
            sb.Append(": ");
            foreach (MethodKey k in methods)
            {
                sb.Append(k.ToString());
                sb.Append(" ");
            }
            return sb.ToString();
        }
	}

	class InheritMap
	{
		private readonly Project project;

		// method to group map
		private readonly Dictionary<MethodKey, MethodGroup> methodGroups = new Dictionary<MethodKey, MethodGroup>( );

		private readonly Dictionary<TypeKey, TypeKey[]> baseTypes = new Dictionary<TypeKey, TypeKey[]>( );

		public InheritMap( Project project )
		{
			this.project = project;

			// cache for assemblies not in the project
			AssemblyCache cache = new AssemblyCache( project );
			//string[] lPaths = project.
			cache.ExtraFolders.AddRange(project.ExtraPaths);

			foreach ( AssemblyInfo info in project )
			{
				foreach ( TypeDefinition type in info.Definition.MainModule.Types )
				{
					if ( type.FullName == "<Module>" )
						continue;

					TypeKey typeKey = new TypeKey( type );

					baseTypes[typeKey] = GetBaseTypes( type );

					int i = 0;
					int j;

					MethodKey[] methods = GetVirtualMethods( cache, type );
					while ( i < methods.Length )
					{
						MethodGroup group;
						if ( !methodGroups.TryGetValue( methods[i], out group ) )
							group = null;

						for ( j = i + 1; j < methods.Length && MethodsMatch( methods, i, j ); j++ )
						{
							// found an override

							// see if either method is already in a group
							if ( group != null )
								group = AddToGroup( group, methods[j] );
							else if ( methodGroups.TryGetValue( methods[j], out group ) )
								group = AddToGroup (group, methods [i]);
							else
							{
								group = new MethodGroup( );
                                
								group = AddToGroup (group, methods [i]);
								group = AddToGroup (group, methods [j]);
							}

							// if the group isn't already external, see if it should be
							Debug.Assert( group != null, "should have a group by now" );
							if ( !group.External && !project.Contains( methods[j].TypeKey ) )
								group.External = true;
						}

						// if the group isn't already external, see if it should be
						if ( group != null && !group.External && !project.Contains( methods[i].TypeKey ) )
							group.External = true;

						// move on to the next thing that doesn't match
						i = j;
					}
				}
			}
		}

		static bool MethodsMatch( MethodKey[] methods, int i, int j )
		{
			return methods[i].Equals( (NameParamSig) methods[j] );
		}

		void GetBaseTypes( HashSet<TypeKey> baseTypes, TypeDefinition type )
		{
			// check the interfaces
			foreach ( TypeReference ifaceRef in type.Interfaces )
			{
				TypeDefinition iface = project.GetTypeDefinition( ifaceRef );
				if ( iface != null )
				{
					GetBaseTypes( baseTypes, iface );
					baseTypes.Add( new TypeKey( iface ) );
				}
			}

			// check the base type unless it isn't in the project, or we don't have one
			TypeDefinition baseType = project.GetTypeDefinition( type.BaseType );
			if ( baseType != null && baseType.FullName != "System.Object" )
			{
				GetBaseTypes( baseTypes, baseType );
				baseTypes.Add( new TypeKey( baseType ) );
			}
		}

		TypeKey[] GetBaseTypes( TypeDefinition type )
		{
			HashSet<TypeKey> baseTypes = new HashSet<TypeKey>( );
			GetBaseTypes( baseTypes, type );
            TypeKey[] res = new TypeKey[baseTypes.Count];
            baseTypes.CopyTo(res);
            return res;
		}

		void GetVirtualMethods( AssemblyCache cache, C5.TreeSet<MethodKey> methods, TypeDefinition type )
		{
			// check the interfaces
			foreach ( TypeReference ifaceRef in type.Interfaces )
			{
				TypeDefinition iface = project.GetTypeDefinition( ifaceRef );

				// if it's not in the project, try to get it via the cache
				if ( iface == null )
					iface = cache.GetTypeDefinition( ifaceRef );

				// search interface
				if ( iface != null )
					GetVirtualMethods( cache, methods, iface );
			}

			// check the base type unless it isn't in the project, or we don't have one
			TypeDefinition baseType = project.GetTypeDefinition( type.BaseType );

			// if it's not in the project, try to get it via the cache
			if ( baseType == null )
				baseType = cache.GetTypeDefinition( type.BaseType );

			// search base
			if ( baseType != null )
				GetVirtualMethods( cache, methods, baseType );

			foreach ( MethodDefinition method in type.Methods )
			{
				if ( method.IsVirtual )
					methods.Add( new MethodKey( method ) );
			}
		}

		MethodKey[] GetVirtualMethods( AssemblyCache cache, TypeDefinition type )
		{
			C5.TreeSet<MethodKey> methods = new C5.TreeSet<MethodKey>( );
			GetVirtualMethods( cache, methods, type );
			return methods.ToArray( );
		}

		MethodGroup AddToGroup( MethodGroup group, MethodKey methodKey )
		{
			// add the method to the group
			group.Methods.Add( methodKey );

			// point the method at the group
			MethodGroup group2;
			if(methodGroups.TryGetValue (methodKey, out group2) && group2 != group) {
				// we have a problem; two unrelated groups come together; merge them
                if (group.Methods.Count > group2.Methods.Count)
                {
                    group.Name = group.Name ?? group2.Name;
                    group.External = group.External | group2.External;
                    foreach (MethodKey mk in group2.Methods)
                    {
                        methodGroups[mk] = group;
                        group.Methods.Add(mk);

                    }
                    return group;
                }
                else
                {
                    group2.Name = group2.Name ?? group.Name;
                    group2.External = group2.External | group.External;
                    foreach (MethodKey mk in group.Methods)
                    {
                        methodGroups[mk] = group2;
                        group2.Methods.Add(mk);

                    }
                    return group2;
                }
			}
			methodGroups[methodKey] = group;

			return group;
		}

		public MethodGroup GetMethodGroup( MethodKey methodKey )
		{
			MethodGroup group;
			if ( methodGroups.TryGetValue( methodKey, out group ) )
				return group;
			else
				return null;
		}

		public TypeKey[] GetBaseTypes( TypeKey typeKey )
		{
			return baseTypes[typeKey];
		}
	}
}
