using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;

namespace Manage
{
    public class CustomPrincipal : IPrincipal
    {
        //CustomPrincipal klasa kreira kada trenutni tred poziva pa ga autorizujemo tako
        //popunjavamo polja winIdentity-a koje nam treba da proveravamo da li on stvarno moze da ima neku permisiju
        WindowsIdentity windowsIdentity;

        public CustomPrincipal(WindowsIdentity identity)
        {
            this.windowsIdentity = identity;
        }

        public IIdentity Identity
        {
            get { return windowsIdentity; }
        }
        public bool IsInRole(string permission)
        {
            foreach (IdentityReference item in windowsIdentity.Groups)
            {
                //Trazimo SID koji je u jednom zapisu, konvertujemo ga u citljivi sid
                // group Name i trazimo permisije za njega 
                SecurityIdentifier sid = (SecurityIdentifier)item.Translate(typeof(SecurityIdentifier));
                var name = sid.Translate(typeof(NTAccount));
                //Ovaj deo izbrisati jer sam kopirao njihov formatter lakse je i nije tesko razumeti 
                string groupName = Formatter.ParseName(name.ToString());
                if (ResixLoader.GetPermissions(groupName, out string[] permissions))
                {
                    return permissions.Contains(permission);
                }

            }
            return false;
        }
    }
}
