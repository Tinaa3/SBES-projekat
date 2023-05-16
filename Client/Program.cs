using CertHelper;
using Common;
using Manage;
using System;
using System.Reflection.Emit;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.ServiceModel;
using System.Text.RegularExpressions;

namespace Client
{
    class Program
    {
        static void Main(string[] args)
        {
            NetTcpBinding binding = new NetTcpBinding();
            string address = "net.tcp://localhost:8888/WCFService";

            binding.Security.Mode = SecurityMode.Transport;
            binding.Security.Transport.ClientCredentialType = TcpClientCredentialType.Windows;
            binding.Security.Transport.ProtectionLevel = System.Net.Security.ProtectionLevel.EncryptAndSign;

            using (WCFClient proxy = new WCFClient(binding, new EndpointAddress(new Uri(address))))
            {
                bool isConnected = false;
                bool isClosed = false;
                byte[] sessionKey = null;

                while (true)
                {
                    if (!isConnected)
                        Console.WriteLine("1. Connect to ServiceManagment (SM)");
                    else
                    {
                        Console.WriteLine("2. Run Client Service");
                        Console.WriteLine("3. Add BlackList Rule");
                        Console.WriteLine("4. Remove BlackList Rule");
                    }
                    Console.WriteLine("5. Exit");

                    int input = Int32.Parse(Console.ReadLine());

                    if (!isConnected)
                    {
                        switch (input)
                        {
                            case 1:
                                isConnected = ClientConnect(proxy, out sessionKey);
                               // Console.WriteLine(isConnected);
                                break;
                            case 5:
                                isClosed = true;
                                break;
                            default:
                                Console.WriteLine("Wrong input!");
                                break;
                        }
                    }
                    else if (isConnected)
                    {
                        switch (input)
                        {
                            case 2:
                                ClientStartService(proxy, sessionKey);
                                break;
                            case 3:
                                ClientAddRule(proxy);
                                break;
                            case 4:
                                ClientRemoveRule(proxy);
                                break;
                            case 5:
                                isClosed = true;
                                break;
                            default:
                                Console.WriteLine("Wrong input");
                                break;
                        }
                    }

                    if (isClosed)
                        break;

                    Console.WriteLine();
                }
            }

            Console.WriteLine("Press any key to exit...");
            Console.ReadKey();
        }

        private static void ClientRemoveRule(WCFClient proxy)
        {
            string userGroup = "";
            string protocol = "";
            string port = "";
            int portNum = -1;
            bool ruleRemoved = false;

            do
            {
                Console.WriteLine("Input name of a group: ");
                userGroup = Console.ReadLine().Trim();
            } 
            while (userGroup == "" || userGroup == null);

            while (true)
            {
                Console.WriteLine("Input protocol: ");
                protocol = Console.ReadLine();
                if (protocol == "")
                    break;
                ProtocolEnum.Protocols protocols;
                bool isConverted = Enum.TryParse<ProtocolEnum.Protocols>(protocol.ToUpper(), out protocols);
                if (!isConverted)
                    continue;
                if (Enum.IsDefined(typeof(ProtocolEnum.Protocols), protocols))
                    break;
            }

            do
            {
                Console.WriteLine("Input port: ");
                port = Console.ReadLine();
                if (port == "" && protocol != "")
                    break;
                bool isConverted = Int32.TryParse(port, out portNum);
                if (!isConverted)
                    continue;
            } 
            while (port == "" || port == null || portNum > 65535 || portNum < 1023);

            ruleRemoved = proxy.RemoveRule(userGroup, protocol, portNum);

            if (ruleRemoved)
                Console.WriteLine("Rule has been successfully removed");
            else
                Console.WriteLine("Rule has not been removed");
        }

        private static void ClientAddRule(WCFClient proxy)
        {
            string userGroup = "";
            string protocol = "";
            string port = "";
            int portNum = -1;
            bool isConverted = false;
            bool ruleAdded = false;

            do
            {
                Console.WriteLine("Input name of group: ");
                userGroup = Console.ReadLine().Trim();
            }
            while (userGroup == "" || userGroup == null);

            do
            {
                do
                {
                    Console.WriteLine("Input protocol: ");
                    protocol = Console.ReadLine().Trim();
                    if (protocol == "")
                        break;
                    ProtocolEnum.Protocols protocols;
                    isConverted = Enum.TryParse<ProtocolEnum.Protocols>(protocol.ToUpper(), out protocols);
                }
                while (isConverted == false);

                do
                {
                    Console.WriteLine("Input port: ");
                    port = Console.ReadLine().Trim();
                    if (port == "")
                        break;
                    isConverted = Int32.TryParse(port, out portNum);
                    if (!isConverted)
                    {
                        Console.WriteLine("Port must be between 1023 and 65535");
                        continue;
                    }
                }
                while (portNum > 65535 || portNum < 1023);

                if (protocol == "" && port == "")
                {
                    Console.WriteLine("You must define protocol or port");
                }
            }
            while (protocol == "" && port == null);

            ruleAdded =proxy.AddRule(userGroup, protocol, portNum);

            if (ruleAdded)
                Console.WriteLine("Rule has been successfully added");
            else
                Console.WriteLine("Rule has not been added");
        }

        private static void ClientStartService(WCFClient proxy, byte[] sessionKey)
        {
            string machineName = "";
            string protocol = "";
            string port = "";
            int portNum = -1;

            do
            {
                Console.WriteLine("Input name of machine: ");
                machineName = Console.ReadLine().Trim();
            }
            while (machineName == "" || machineName == null);

            while(true)
            {
                Console.WriteLine("Input protocol: ");
                protocol = Console.ReadLine().Trim();
                ProtocolEnum.Protocols protocols;
                bool isConverted = Enum.TryParse<ProtocolEnum.Protocols>(protocol.ToUpper(), out protocols);
                if (!isConverted)
                    continue;
                if (Enum.IsDefined(typeof(ProtocolEnum.Protocols), protocols))
                    break;
            }

            do
            {
                Console.WriteLine("Input port: ");
                port = Console.ReadLine().Trim();
                bool isConverted = Int32.TryParse(port, out portNum);
                if (!isConverted)
                    continue;
            }
            while (port == "" || port == null || portNum > 65535 || portNum < 1023);

            //Console.WriteLine($"{machineName},{protocol},{port}");
            byte[] encryptedData = AES_CBC.EncryptData(($"{machineName},{protocol},{port}"), sessionKey);
            //Console.WriteLine(encryptedData);

            bool isStarted = proxy.StartNewService(encryptedData);

            if (isStarted)
                Console.WriteLine("Service is started...");
            else
                Console.WriteLine("Service has not been started because of black list configuration. ");
        }

        private static bool ClientConnect(WCFClient proxy, out byte[] sessionKey)
        {
            string serviceCert = "Manager";

            Console.WriteLine(WindowsIdentity.GetCurrent().Name);
            sessionKey = SessionKeyHelper.CreateSessionKey();

            X509Certificate2 certificate = CertManager.GetCertificateFromStorage(StoreName.TrustedPeople, StoreLocation.LocalMachine, serviceCert);

            byte[] encryptedSessionKey = SessionKeyHelper.EncryptSessionKey(certificate, sessionKey);

            return proxy.Connect(encryptedSessionKey);
        }

        

    }
}
