using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Manage
{
    public class ResixLoader
    {
        static string path = @"~\..\..\..\..\Manage\RolesFile.resx";

        public static bool GetPermissions(string roleName, out string[] permissions)
        {
            permissions = new string[5];
            string permission = (string)RolesFile.ResourceManager.GetObject(roleName);

            if (permission != null)
            {
                permissions = permission.Split(',');
                return true;
            }

            return false;
        }
        
    }
}
