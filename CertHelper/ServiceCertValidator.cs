using System;
using System.Collections.Generic;
using System.IdentityModel.Selectors;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;

namespace CertHelper
{
    public class ServiceCertValidator : X509CertificateValidator
    {
        public override void Validate(X509Certificate2 certificate)
        {
            if (certificate == null)
            {
                throw new ArgumentNullException("certificate");
            }

            string srvCertCN = Formatter.ParseName(WindowsIdentity.GetCurrent().Name);
           

            X509Certificate2 servCet = CertManager.GetCertificateFromStorage(StoreName.My, StoreLocation.LocalMachine, srvCertCN);
            if (!certificate.Issuer.Equals(servCet.Issuer))
            {
                throw new Exception("Certificate was not issued by a trusted issuer");
            }
        }
    }
}
