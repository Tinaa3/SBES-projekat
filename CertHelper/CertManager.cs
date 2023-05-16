using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace CertHelper
{
    public class CertManager
    {
        public static X509Certificate2 GetCertificateFromStorage(StoreName storeName, StoreLocation storeLocation, string subjectName)
        {
            X509Certificate2 certificate = null;

            try
            {
                X509Store store = new X509Store(storeName, storeLocation);
                store.Open(OpenFlags.ReadOnly);

                X509Certificate2Collection cers = store.Certificates.Find(X509FindType.FindBySubjectName, subjectName, true);
                for (int i = 0; i < cers.Count; i++)
                {
                    if (cers[i].SubjectName.Name.Equals(string.Format("CN={0}", subjectName)))
                    {
                        certificate = cers[i];
                    }
                }

                store.Close();

            }
            catch (Exception)
            {
                return null;
            }

            return certificate;
        }
    }
}
