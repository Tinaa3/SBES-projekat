using CertHelper;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using System.Text;
using System.Threading.Tasks;

namespace Manage
{
    public class CustomAuthorizationManager : ServiceAuthorizationManager
    {
        protected override bool CheckAccessCore(OperationContext operationContext)
        {
            //TO DO : Obezbediti proveru permisije iz principala koji smo podesili na kontekst
            CustomPrincipal principal = operationContext.ServiceSecurityContext.AuthorizationContext.Properties["Principal"] as CustomPrincipal;

            bool retVal = principal.IsInRole("ExchangeSessionKey");

            if (!retVal)
            {
                try
                {
                    AuditClient.Instance().LogAuthorizationFailed(Formatter.ParseName(principal.Identity.Name),
                                                                  OperationContext.Current.IncomingMessageHeaders.Action, "User does't have session key.");
                }
                catch (Exception e)
                {
                    Console.WriteLine(e.Message);
                }
            }

            return retVal;
        }
    }
}
