using CertHelper;
using Contract;
using Manage;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.ServiceModel;
using System.Text;
using System.Threading.Tasks;

namespace Manage
{
    public class AuditClient : ChannelFactory<IAuditContract>, IAuditContract, IDisposable
    {
        IAuditContract factory;

        private static AuditClient _instance;
        private static readonly object _lock = new object();

        public static AuditClient Instance()
        {
            if (_instance == null)
            {
                lock (_lock)
                {
                    if (_instance == null)
                    {
                        NetTcpBinding binding = new NetTcpBinding();
                        binding.Security.Transport.ClientCredentialType = TcpClientCredentialType.Certificate;

                        /// Use CertManager class to obtain the certificate based on the "srvCertCN" representing the expected service identity.
                        X509Certificate2 srvCert = CertManager.GetCertificateFromStorage(StoreName.TrustedPeople, StoreLocation.LocalMachine, "Auditer");
                        EndpointAddress addressAudit = new EndpointAddress(new Uri("net.tcp://localhost:9999/Audit"),
                                                  new X509CertificateEndpointIdentity(srvCert));
                        _instance = new AuditClient(binding, addressAudit);
                    }
                }
            }

            return _instance;
        }

        public AuditClient(NetTcpBinding binding, EndpointAddress address) : base(binding, address)
        {
            string managerCertCN = Formatter.ParseName(WindowsIdentity.GetCurrent().Name);
            //string managerCertCN = "Manager";

            this.Credentials.ServiceCertificate.Authentication.CertificateValidationMode = System.ServiceModel.Security.X509CertificateValidationMode.Custom;
            this.Credentials.ServiceCertificate.Authentication.CustomCertificateValidator = new ClientCertValidator();

            /// Set appropriate client's certificate on the channel. Use CertManager class to obtain the certificate based on the "cltCertCN"
            this.Credentials.ClientCertificate.Certificate = CertManager.GetCertificateFromStorage(StoreName.My, StoreLocation.LocalMachine, managerCertCN);

            factory = this.CreateChannel();
        }

        public void TestCommunication()
        {
            try
            {
                factory.TestCommunication();
            }
            catch (Exception e)
            {
                Console.WriteLine("[TestCommunicationWithAuditer] ERROR = {0} \nTry to start Auditer", e.Message);
            }
        }

        public void Dispose()
        {
            if (factory != null)
            {
                factory = null;
            }

            this.Close();
        }

        public void LogAuthorizationFailed(string username, string serviceName, string reason)
        {
            try
            {
                factory.LogAuthorizationFailed(username, serviceName, reason);
            }
            catch (Exception e)
            {
                Console.WriteLine("[LogAuthorizationFailed] ERROR = {0}", e.Message);
            }
        }

        public void LogServiceStarted(string username)
        {
            try
            {
                factory.LogServiceStarted(username);
            }
            catch (Exception e)
            {
                Console.WriteLine("[LogServiceStarted] ERROR = {0}", e.Message);
            }
        }

        public void LogServiceStartDenied(string username, string protocol, string port, string reason)
        {
            try
            {
                factory.LogServiceStartDenied(username, protocol, port, reason);
            }
            catch (Exception e)
            {
                Console.WriteLine("[LogServiceStartDenied] ERROR = {0}", e.Message);
            }
        }

        public void LogAuthorizationSuccess(string username, string serviceName)
        {
            try
            {
                factory.LogAuthorizationSuccess(username, serviceName);
            }
            catch (Exception e)
            {
                Console.WriteLine("[LogAuthorizationSuccess] ERROR = {0}", e.Message);
            }
        }

        public void LogAuthenticationSuccess(string username)
        {
            try
            {
                factory.LogAuthenticationSuccess(username);
            }
            catch (Exception e)
            {
                Console.WriteLine("[LogAuthenticationSuccess] ERROR = {0}", e.Message);
            }
        }

        public void BlacklistFaultedState()
        {
            try
            {
                factory.BlacklistFaultedState();
            }
            catch (Exception e)
            {
                Console.WriteLine("[BlacklistFaultedState] ERROR = {0}", e.Message);
            }
        }

        public void BlacklistRuleAdded(string username, string group, string protocol, string port)
        {
            try
            {
                factory.BlacklistRuleAdded(username, group, protocol, port);
            }
            catch (Exception e)
            {
                Console.WriteLine("[BlacklistRuleAdded] ERROR = {0}", e.Message);
            }
        }

        public void BlacklistRuleRemoved(string username, string group, string protocol, string port)
        {
            try
            {
                factory.BlacklistRuleRemoved(username, group, protocol, port);
            }
            catch (Exception e)
            {
                Console.WriteLine("[BlacklistRuleRemoved] ERROR = {0}", e.Message);
            }
        }
    }
}
