using Contract;
using System;

namespace ClientService
{
    public class ClientServiceImplementation : IClientsServices
    {
        public void PrintInfo()
        {
            Console.WriteLine("INFO: Service started.");
        }
    }
}
