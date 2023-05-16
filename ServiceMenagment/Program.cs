using CertHelper;
using Contract;
using Manage;
using System;
using System.Collections.Generic;
using System.IdentityModel.Policy;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.ServiceModel;
using System.ServiceModel.Description;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace ServiceMenagment
{
    class Program
    {
        static void Main(string[] args)
        {

            NetTcpBinding binding = new NetTcpBinding();
            string address = "net.tcp://localhost:8888/WCFService";
            //Windows autetifikacija vezbe 1 /2 
            binding.Security.Mode = SecurityMode.Transport;
            binding.Security.Transport.ClientCredentialType = TcpClientCredentialType.Windows;
            binding.Security.Transport.ProtectionLevel = System.Net.Security.ProtectionLevel.EncryptAndSign;

            ServiceHost host = new ServiceHost(typeof(ServiceManagerImplementation));
            host.AddServiceEndpoint(typeof(IServiceManagment), binding, address);


            host.Authorization.ServiceAuthorizationManager = new CustomAuthorizationManager();

            host.Authorization.PrincipalPermissionMode = PrincipalPermissionMode.Custom;

            List<IAuthorizationPolicy> polices = new List<IAuthorizationPolicy>();
            polices.Add(new CustomAuthorizationPolicy());

            host.Authorization.ExternalAuthorizationPolicies = polices.AsReadOnly();


            host.Open();
            Console.WriteLine(WindowsIdentity.GetCurrent().Name);
            Console.WriteLine("Server is successfully opened");

            Thread th = new Thread(() => ServiceManagerImplementation.CheckSumFunction());
            th.Start();

            AuditClient.Instance().TestCommunication();

            Console.ReadLine();
        }
    }
}
