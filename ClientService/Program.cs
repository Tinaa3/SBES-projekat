using Contract;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Principal;
using System.ServiceModel;
using System.Text;
using System.Threading.Tasks;

namespace ClientService
{
    class Program
    {
        static void Main(string[] args)
        {
            string protocol;
            int port;

            if (args[0] != null && args[1] != null)
            {
                protocol = args[0];
                port = Int32.Parse(args[1]);
            }
            else
            {
                Console.WriteLine("No argumets.");
                return;
            }

            NetTcpBinding binding = new NetTcpBinding();
            string address =($"net.tcp://localhost:{port}/IClientService");
            ServiceHost host = new ServiceHost(typeof(ClientServiceImplementation));
            host.AddServiceEndpoint(typeof(IClientsServices), binding, address);

            try
            {
                host.Open();
                Console.WriteLine($"Service started by: {WindowsIdentity.GetCurrent().Name}");
                Console.WriteLine($"Service is running with protocol: {protocol}, on port: {port}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Start failed: {ex.Message}");
            }

            Console.ReadKey();
        }
    }
}
