using System.Collections;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Resources;
using System.IO;
using System.Linq;
using System.Data.SqlTypes;
using System.Threading;
using static Common.ProtocolEnum;

namespace ServiceMenagment
{
    public class BlacklistManager
    {
        private static string path = @"~\..\..\..\..\ServiceMenagment\Blacklist.resx";
        private byte[] fileHash;
        private SHA256 shaProvider;

        private static BlacklistManager managerInstance;
        private static SortedDictionary<string, string> fileDictionary = new SortedDictionary<string, string>();

        public byte[] FileHash { get { return fileHash; } }
        private BlacklistManager() 
        {
            UpdateDictionary();
            shaProvider = SHA256.Create();
            fileHash = ComputeHashValue();
        }

        public static BlacklistManager Instance()
        {
            if (managerInstance == null)
            {
                managerInstance = new BlacklistManager();
            }

            return managerInstance;
        }

        private void UpdateDictionary()
        {
            while (true)
            {
                try
                {
                    using (ResXResourceReader rsxr = new ResXResourceReader(path))
                    {
                        foreach (DictionaryEntry d in rsxr)
                        {
                            fileDictionary[d.Key.ToString()] = (string)d.Value;
                        }
                    }
                    break;
                }
                catch 
                {
                    Console.WriteLine("Failed to open and update Blacklist.resx");
                    System.Threading.Thread.Sleep(500);
                }
            }
        }
        public bool FileHashValid()
        {
            byte[] currentHashValue;
            using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.None))
            {
                currentHashValue = shaProvider.ComputeHash(fs);
                fs.Close();
            }

            int iterator = 0;
            if (currentHashValue.Length == fileHash.Length)
            {
                while (iterator < currentHashValue.Length && (currentHashValue[iterator] == fileHash[iterator]))
                {
                    iterator++;
                }
                if (iterator == fileHash.Length)
                {
                    return true;
                }
            }

            return false;
        }

        public byte[] ComputeHashValue()
        {
            byte[] retVal = null;
            while (true)
            {
                try
                {
                    using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.None))
                    {
                        retVal = shaProvider.ComputeHash(fs);
                        break;
                    }

                }
                catch 
                {
                    Console.WriteLine("Failed to open and compute hash for Blacklist.resx");
                    System.Threading.Thread.Sleep(500);
                }
            }

            return retVal;
        }
        private bool PortIsValid(int port)
        {
            if (port >= 1023 && port < UInt16.MaxValue)
                return true;
            else
                return false;
        }

        private bool ProtocolSupported(string protocol)
        {
            if (protocol == "TCP" || protocol == "UDP" || protocol == "HTTP" || protocol == "POP3" || protocol == "SMTP" || protocol == "FTP" || protocol == "RHCP")
                return true;
            else
                return false;
        }

        public bool PermissionGranted(string[] groups, string protocol, int port, out string reason)
        {
            if (!PortIsValid(port))
            {
                reason = "PORT";
                return false;
            }

            string p = protocol.ToUpper();
            if (!ProtocolSupported(p))
            {
                reason = "PROTOCOL";
                return false;
            }


            string[] pairs, concretePair;
            string pairsStr, pr, por;
            reason = "";

            
            foreach (string group in groups)
            {   
                if (fileDictionary.ContainsKey(group))
                {
                    pairsStr = fileDictionary[group];
                    pairs = pairsStr.Split(',');
                    foreach (string pair in pairs)
                    {   
                        if (!pair.Contains(':'))
                        {
                            int portNum;
                            bool isNumber = Int32.TryParse(pair, out portNum);  

                            if (isNumber)   
                            {
                                if (port == portNum)
                                {
                                    reason = "PORT";
                                    return false;
                                }
                            }
                            else           
                            {
                                if (pair.ToUpper() == protocol.ToUpper())
                                {
                                    reason = "PROTOCOL";
                                    return false;
                                }
                            }
                        }
                        else
                        {
                            concretePair = pair.Split(':');
                            pr = concretePair[0];
                            por = concretePair[1];
                            if (protocol.ToUpper() == pr.ToUpper() && port.ToString() == por)
                            {
                                reason = "PROTOCOL+PORT";
                                return false;
                            }
                        }
                    }
                }
                else
                {
                    Console.WriteLine($"Specified user group \"{group}\" doesn't exist");
                    reason = "GROUP";
                    return false;
                }
            }
            return true;
        
        }

        public bool AddRule(string group, string protocol, int port)
        {
            bool ruleAdded = false;
            string output = "";

            if (!PortIsValid(port))
            {
                return ruleAdded;
            }

            string p = protocol.ToUpper();
            if (!ProtocolSupported(p))
            {
                return ruleAdded;
            }

            SortedDictionary<string, string> retDic = new SortedDictionary<string, string>();

            string addedPair = protocol.ToUpper() + ":" + port;

            if (!fileDictionary.ContainsKey(group))
            {
                Console.WriteLine($"Specified user group \"{group}\" doesn't exist");
                return ruleAdded;
            }

            string pairsStr = fileDictionary[group]; 
            string[] pairs = pairsStr.Split(',');

            foreach (string pair in pairs)
            {
                if (pair == addedPair)
                {
                    Console.WriteLine("Specified rule already exists");
                    return ruleAdded;
                }
            }

            pairs = pairs.Concat(new string[] { addedPair }).ToArray();

            if (fileDictionary[group].Length == 0)
            {
                output = addedPair;
            }
            else
            {
                output = String.Join(",", pairs);
            }

            

            using (ResXResourceReader rsxr = new ResXResourceReader(path))
            {
                foreach (DictionaryEntry d in rsxr)
                {
                    if (d.Key.ToString() != group)
                        retDic.Add(d.Key.ToString(), d.Value.ToString());
                }
                rsxr.Close();
            }

            retDic.Add(group, output);

            using (ResXResourceWriter writer = new ResXResourceWriter(path))
            {
                foreach (KeyValuePair<string, string> kvp in retDic)
                {
                    writer.AddResource(kvp.Key, kvp.Value);
                    ruleAdded = true;
                }
            }

            
            UpdateDictionary();
            fileHash = ComputeHashValue();

            Console.WriteLine($"Rule has been successfully added by {Thread.CurrentPrincipal.Identity.Name}");
            return ruleAdded;
        }

        public bool AddRule(string group, string protocol)
        {
            bool ruleAdded = false;
            string p = protocol.ToUpper();
            string output = "";
            
            if (!ProtocolSupported(p))
            {
                return ruleAdded;
            }

            SortedDictionary<string, string> retDic = new SortedDictionary<string, string>();

            if (!fileDictionary.ContainsKey(group))
            {
                Console.WriteLine($"Specified user group \"{group}\" doesn't exist");
                return ruleAdded;
            }

            string pairsStr = fileDictionary[group];
            string[] pairs = pairsStr.Split(',');

            pairs = pairs.Where(x => !x.ToUpper().StartsWith(protocol.ToUpper())).ToArray();

            pairs = pairs.Concat(new string[] { protocol.ToUpper() }).ToArray();

            if (fileDictionary[group].Length == 0)
            {
                 output = protocol;
            }
            else
            {
                 output = String.Join(",", pairs);
            }

            using (ResXResourceReader rsxr = new ResXResourceReader(path))
            {
                foreach (DictionaryEntry d in rsxr)
                {
                    if (d.Key.ToString() != group)
                        retDic.Add(d.Key.ToString(), d.Value.ToString());
                }
                rsxr.Close();
            }
            
            retDic.Add(group, output);

            using (ResXResourceWriter writer = new ResXResourceWriter(path))
            {
                foreach (KeyValuePair<string, string> kvp in retDic)
                {
                    writer.AddResource(kvp.Key, kvp.Value);
                    
                }
                ruleAdded = true;
            }

            UpdateDictionary();
            fileHash = ComputeHashValue();

            Console.WriteLine($"Rule has been successfully added by {Thread.CurrentPrincipal.Identity.Name}");
            return ruleAdded;
        }

        public bool AddRule(string group, int port)
        {
            string output = "";
            bool ruleAdded = false;
            if (!PortIsValid(port))
            {
                return ruleAdded;
            }

            SortedDictionary<string, string> retDic = new SortedDictionary<string, string>();
            List<string> toDelete = new List<string>();

            if (!fileDictionary.ContainsKey(group))
            {
                Console.WriteLine($"Specified user group \"{group}\" doesn't exist");
                return ruleAdded;
            }

            string pairsStr = fileDictionary[group];
            string[] pairs = pairsStr.Split(',');

            foreach (string pair in pairs)
            {
                if (!pair.Contains(':'))
                {
                    if (pair == port.ToString())        
                        break;
                }
                else
                {
                    string[] concretePair = pair.Split(':');
                    if (concretePair[1] == port.ToString())
                        toDelete.Add(pair);
                }
            }
            List<string> tmpList = pairs.ToList();

            foreach (string itemToDelete in toDelete)
            {
                foreach (string item in tmpList.ToList())
                {
                    if (itemToDelete == item)
                    {
                        tmpList.Remove(item);
                    }
                }
            }
            pairs = tmpList.ToArray();

            pairs = pairs.Concat(new string[] { port.ToString() }).ToArray();

            if (fileDictionary[group].Length == 0)
            {
                output = port.ToString();
            }
            else
            {
                output = String.Join(",", pairs);
            }

            

            using (ResXResourceReader rsxr = new ResXResourceReader(path))
            {
                foreach (DictionaryEntry d in rsxr)
                {
                    if (d.Key.ToString() != group)
                        retDic.Add(d.Key.ToString(), d.Value.ToString());
                }
                rsxr.Close();
            }

            retDic.Add(group, output);


            using (ResXResourceWriter writer = new ResXResourceWriter(path))
            {
                foreach (KeyValuePair<string, string> kvp in retDic)
                {
                    writer.AddResource(kvp.Key, kvp.Value);
                    ruleAdded = true;
                }
            }
            UpdateDictionary();
            fileHash = ComputeHashValue();

            Console.WriteLine($"Rule has been successfully added by {Thread.CurrentPrincipal.Identity.Name}");
            return ruleAdded;
        }

        public bool RemoveRule(string group, string protocol, int port)
        {
            bool ruleRemoved = false;

            if (!PortIsValid(port))
            {
                return ruleRemoved;
            }

            string p = protocol.ToUpper();
            if (!ProtocolSupported(p))
            {
                return ruleRemoved;
            }

            Dictionary<string, string> retDic = new Dictionary<string, string>();

            string toDelete = protocol.ToUpper() + ":" + port;

            if (!fileDictionary.ContainsKey(group))
            {
                Console.WriteLine($"Specified user group \"{group}\" doesn't exist");

                return ruleRemoved;
            }

            string pairsStr = fileDictionary[group];
            string[] pairs = pairsStr.Split(',');

            List<string> outList = new List<string>();

            foreach (string pair in pairs)
            {
                if (pair != toDelete)
                {
                    outList.Add(pair);
                }
            }
            if (pairs.Count() == outList.Count)
            {                                          
                Console.WriteLine("Specified rule doesn't exist");
                return ruleRemoved;
            }


            string output = String.Join(",", outList);

            using (ResXResourceReader rsxr = new ResXResourceReader(path))
            {
                foreach (DictionaryEntry d in rsxr)
                {
                    if (d.Key.ToString() != group)
                        retDic.Add(d.Key.ToString(), d.Value.ToString());
                }
                rsxr.Close();
            }

            retDic.Add(group, output);

            using (ResXResourceWriter writer = new ResXResourceWriter(path))
            {
                foreach (KeyValuePair<string, string> kvp in retDic)
                {
                    writer.AddResource(kvp.Key, kvp.Value);
                }
                ruleRemoved = true;
            }

            UpdateDictionary();
            fileHash = ComputeHashValue();

            Console.WriteLine($"Rule has been successfully removed by {Thread.CurrentPrincipal.Identity.Name}");

            return ruleRemoved;
        }

        public bool RemoveRule(string group, string protocol)
        {
            string p = protocol.ToUpper();
            bool ruleRemoved = false;

            if (!ProtocolSupported(p))
            {
                return ruleRemoved;
            }


            Dictionary<string, string> retDic = new Dictionary<string, string>();

            if (!fileDictionary.ContainsKey(group))
            {
                Console.WriteLine($"Specified user group \"{group}\" doesn't exist");

                return ruleRemoved;
            }

            string pairsStr = fileDictionary[group];
            string[] pairs = pairsStr.Split(',');

            List<string> outList = new List<string>();

            foreach (string pair in pairs)
            {
                if (pair != protocol.ToUpper())
                {
                    outList.Add(pair);
                }
            }
            if (pairs.Count() == outList.Count)
            {
                Console.WriteLine("Specified rule doesn't exist");
                return ruleRemoved;
            }


            string output = String.Join(",", outList);

            using (ResXResourceReader rsxr = new ResXResourceReader(path))
            {
                foreach (DictionaryEntry d in rsxr)
                {
                    if (d.Key.ToString() != group)
                        retDic.Add(d.Key.ToString(), d.Value.ToString());
                }
                rsxr.Close();
            }

            retDic.Add(group, output);

            using (ResXResourceWriter writer = new ResXResourceWriter(path))
            {
                foreach (KeyValuePair<string, string> kvp in retDic)
                {
                    writer.AddResource(kvp.Key, kvp.Value);
                }
                ruleRemoved = true;
            }
            UpdateDictionary();
            fileHash = ComputeHashValue();

            Console.WriteLine($"Rule has been successfully removed by {Thread.CurrentPrincipal.Identity.Name}");
            return ruleRemoved;
        }

        public bool RemoveRule(string group, int port)
        {
            bool ruleRemoved = false;
            if (!PortIsValid(port))
            {
                return ruleRemoved;
            }

            Dictionary<string, string> retDic = new Dictionary<string, string>();

            if (!fileDictionary.ContainsKey(group))
            {
                return ruleRemoved;
            }

            string pairsStr = fileDictionary[group];
            string[] pairs = pairsStr.Split(',');

            List<string> outList = new List<string>();

            foreach (string pair in pairs)
            {
                if (pair != port.ToString())
                {
                    outList.Add(pair);
                }
            }
            if (pairs.Count() == outList.Count)
            {
                Console.WriteLine("Specified rule doesn't exist");
                return ruleRemoved;
            }

            string output = String.Join(",", outList);

            using (ResXResourceReader rsxr = new ResXResourceReader(path))
            {
                foreach (DictionaryEntry d in rsxr)
                {
                    if (d.Key.ToString() != group)
                    
                        retDic.Add(d.Key.ToString(), d.Value.ToString());
                }
                rsxr.Close();
            }

            retDic.Add(group, output);
            using (ResXResourceWriter writer = new ResXResourceWriter(path))
            {
                foreach (KeyValuePair<string, string> kvp in retDic)
                {
                    writer.AddResource(kvp.Key, kvp.Value);
                }
                ruleRemoved = true;
            }

            UpdateDictionary();
            fileHash = ComputeHashValue();

            Console.WriteLine($"Rule has been successfully removed by {Thread.CurrentPrincipal.Identity.Name}");
            return ruleRemoved;
        }
    }
}
