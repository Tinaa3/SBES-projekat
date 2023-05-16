using CertHelper;
using System;
using System.Collections.Generic;
using System.IdentityModel.Claims;
using System.IdentityModel.Policy;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.ServiceModel;
using System.Text;
using System.Threading.Tasks;

namespace Manage
{
    public class CustomAuthorizationPolicy : IAuthorizationPolicy
    {
        public CustomAuthorizationPolicy()
        {
            Id = Guid.NewGuid().ToString();
        }


        public ClaimSet Issuer
        {
            get { return ClaimSet.System; }
        }

        public string Id { get; set; }

        public bool Evaluate(EvaluationContext evaluationContext, ref object state)
        {
            
            if (!evaluationContext.Properties.TryGetValue("Identities", out object lista))
            {
                return false;
            }

            IList<IIdentity> identities = lista as IList<IIdentity>;
           
            if (lista == null || identities.Count <= 0)
            {
                return false;
            }

            WindowsIdentity windowsIdentity = identities[0] as WindowsIdentity;

            try
            {
                AuditClient.Instance().LogAuthenticationSuccess(Formatter.ParseName(windowsIdentity.Name));
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }

            evaluationContext.Properties["Principal"] = new CustomPrincipal(windowsIdentity);
            return true;
        }
    }
}
